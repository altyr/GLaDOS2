import glados
import os
from datetime import datetime


class Log(glados.Module):

    def __init__(self, settings):
        super(Log, self).__init__(settings)

        self.__log_path = os.path.join(settings['modules']['config path'], 'log')
        if not os.path.exists(self.__log_path):
            os.makedirs(self.__log_path)

        self.__date = datetime.now().strftime('%Y-%m-%d')
        self.__log = open(os.path.join(self.__log_path, 'chanlog-{}'.format(self.__date)), 'a')

    def get_help_list(self):
        return list()

    def __open_new_log_if_necessary(self):
        date = datetime.now().strftime('%Y-%m-%d')
        if not self.__date == date:
            self.__log.close()
            self.__date = date
            self.__log = open(os.path.join(self.__log_path, 'chanlog-{}'.format(self.__date)), 'a')

    @glados.Module.rules('^.*$')
    def on_message(self, message, match):
        # If user has opted out, don't log
        if message.author.id in self.settings['optout']:
            return ()

        server_name = message.server.name if message.server else ''
        self.__open_new_log_if_necessary()
        info = '[{0}] {1}: #{2}: {3}: {4}\n'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                                    server_name,
                                                    message.channel.name,
                                                    message.author.name,
                                                    message.clean_content)
        self.__log.write(info)
        self.__log.flush()
        return tuple()
