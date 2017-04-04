import socket
import glados
import asyncio
import discord
import traceback
import sys
import copy
import re
import socks
import ssl


class HybridSocket(object):

    MODE_SOCKET = 0
    MODE_PYSOCKS = 1

    def __init__(self, host, port, ssl_enable, ssl_verify, proxyhost, proxyport):
        assert not (ssl_enable and proxyhost), "Simultaneous usage of proxy and SSL is not supported"

        if proxyhost:
            self.mode = self.MODE_PYSOCKS
            self.socket = socks.socksocket()
            self.socket.setproxy(socks.PROXY_TYPE_SOCKS5, proxyhost, proxyport, True)
            self.socket.connect((host, port))
        else:
            self.mode = self.MODE_SOCKET
            if ssl_enable:
                sslctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                if not ssl_verify:
                    sslctx.check_hostname = False
                    sslctx.verify_mode = ssl.CERT_NONE
                self.socket = sslctx.wrap_socket(socket.create_connection((host, port)), server_hostname=host)
            else:
                self.socket = socket.create_connection((host, port))

    def send(self, msg):
        return self.socket.send(msg)

    def recv(self, num):
        return self.socket.recv(num)


class IRCBridge(glados.Module):

    STATE_DISCONNECTED = 0
    STATE_TRY_JOIN = 1
    STATE_CONNECTED = 2

    def __init__(self, settings):
        super(IRCBridge, self).__init__(settings)
        self.command_prefix = settings['commands']['prefix']
        self.settings = settings
        self.irc_settings = settings['irc']
        self.host = self.irc_settings['host']
        self.port = int(self.irc_settings['port'])
        self.proxyhost = self.irc_settings['proxy host']
        self.proxyport = int(self.irc_settings['proxy port'])
        self.secure = True if self.irc_settings['secure connection'] == 'true' else False
        self.verify = True if self.irc_settings['verify security'] == 'true' else False
        self.botnick = self.irc_settings['nick']
        self.irc_channels = self.irc_settings['irc channels']
        self.discord_channels = list()
        self.channels_to_join = list()
        self.socket = None
        self.bridge_enable = True if self.irc_settings['enable'] == 'true' else False
        self.state = self.STATE_DISCONNECTED
        asyncio.async(self.run())

    def connect_to_server(self):
        self.channels_to_join = copy.deepcopy(self.irc_channels)
        glados.log('Connecting to: {}:{}'.format(self.host, self.port))
        try:
            self.socket = HybridSocket(self.host, self.port, self.secure, self.verify, self.proxyhost, self.proxyport)
            self.send_raw_message('USER {0} {0} {0} :{0}\n'.format(self.botnick))
            if not self.irc_settings['password'] == '':
                # self.send_raw_message('PRIVMSG NickServ :IDENTIFY {} {}\n'.format(self.botnick, self.irc_settings['password']))
                self.send_raw_message('PASS {}\n'.format(self.irc_settings['password']))
            self.send_raw_message('NICK {}\n'.format(self.botnick))
            self.state = self.STATE_TRY_JOIN
        except Exception as e:
            glados.log('Exception caught: {}'.format(e))
            exc_info = sys.exc_info()
            traceback.print_exception(*exc_info)

    def join_remaining_channels(self):
        for channel in self.channels_to_join:
            glados.log('Joining channel {}'.format(channel))
            self.send_raw_message('JOIN {}\n'.format(channel))

    def send_raw_message(self, msg):
        if self.socket:
            glados.log('irc: {}'.format(msg.strip('\r\n')))
            self.socket.send(msg.encode())

    def send_to_all_channels(self, msg):
        for channel in self.irc_channels:
            self.send_raw_message('PRIVMSG {} :{}\n'.format(channel, msg))

    @asyncio.coroutine
    def run(self):
        while True:
            try:
                if self.state == self.STATE_DISCONNECTED:
                    self.connect_to_server()

                else:
                    loop = asyncio.get_event_loop()
                    msg = yield from loop.run_in_executor(None, self.socket.recv, 2048)
                    if not msg:
                        continue

                    msg = msg.decode().strip('\r\n')
                    glados.log('Received message: {}'.format(msg))

                    if msg[:4] == 'PING':
                        resp = 'PONG {}\n'.format(msg.split()[1])
                        self.send_raw_message(resp)

                    if self.state == self.STATE_TRY_JOIN:
                        glados.log('There are channels to be joined...')
                        self.channels_to_join = [x for x in self.channels_to_join if msg.find('JOIN {}'.format(x)) == -1]
                        self.join_remaining_channels()
                        if len(self.channels_to_join) == 0:
                            glados.log('All channels joined')
                            self.state = self.STATE_CONNECTED

                    if msg.find('PRIVMSG ') != -1:
                        if self.client:
                            self.discord_channels = self.get_discord_channels(self.irc_settings['discord channels'])
                        if self.bridge_enable:
                            match = re.match('^.*PRIVMSG #.*? :(.*)$', msg)
                            if match is not None:
                                resp = match.group(1)
                                for channel in self.discord_channels:
                                    try:
                                        yield from self.client.send_message(channel, resp)
                                    except:
                                        yield
                                        continue

            except Exception as e:
                glados.log('Exception caught: {}'.format(e))
                exc_info = sys.exc_info()
                traceback.print_exception(*exc_info)
            yield

    def get_discord_channels(self, channel_IDs):
        return self.client.get_all_channels()
        ret = list()
        for channel in self.client.get_all_channels():
            if channel.id in channel_IDs:
                ret.append(channel)
        return ret

    def get_help_list(self):
        return list()

    @glados.Module.rules('^.*$')
    def on_discord_message(self, message, match):
        if isinstance(message.channel, discord.Object):
            return()
        if message.channel.is_private:
            return ()
        if not self.bridge_enable:
            return ()
        if message.content[0] == self.command_prefix:
            return ()
        if message.channel.id not in self.irc_settings['discord channels']:
            return ()
        author = message.author.name
        content = self.substitute_mentions(message)
        self.send_to_all_channels('<{}> {}'.format(author, content))
        return ()

    @glados.Module.commands('irc')
    def on_irc_enable(self, message, args):
        if message.author.id not in self.settings['admins']['IDs']:
            return ()

        self.bridge_enable = not self.bridge_enable
        msg = 'IRC bridge enabled.' if self.bridge_enable else 'IRC bridge disabled.'
        yield from self.client.send_message(message.channel, msg)

    @staticmethod
    def substitute_mentions(message):
        content = message.content
        for mention in message.mentions:
            content = content.replace('<@{}>'.format(mention.id), mention.name)
            content = content.replace('<@!{}>'.format(mention.id), mention.name)
        return content
