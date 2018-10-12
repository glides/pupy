#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

__all__=['RequestHandler', 'WebSocketHandler']

import threading
import random
import string
import logging
import tornado.ioloop
import tornado.web
import tornado.template

from ssl import SSLContext

from os import path
from tornado.websocket import WebSocketHandler as TornadoWebSocketHandler
from tornado.web import RequestHandler as TornadoRequestHandler
from tornado.web import StaticFileHandler as TornadoStaticFileHandler

from . import ROOT

LOCAL_IPS = ('127.0.0.1', '::1')

class WebSocketHandler(TornadoWebSocketHandler):
    def prepare(self, *args, **kwargs):
        if self.request.remote_ip not in (LOCAL_IPS):
            self.set_status(403)
            log_msg = "Connection allowed only from local addresses"
            self.finish(log_msg)
            gen_log.debug(log_msg)
            return

        super(WebSocketHandler, self).prepare(*args, **kwargs)

class (TornadoRequestHandler):
    def prepare(self, *args, **kwargs):
        if self.request.remote_ip not in (LOCAL_IPS):
            self.set_status(403)
            log_msg = "Connection allowed only from local addresses"
            self.finish(log_msg)
            gen_log.debug(log_msg)
            return

        super(WebSocketHandler, self).prepare(*args, **kwargs)

class StaticFileHandler(TornadoStaticFileHandler):
    def initialize(self, *args, **kwargs):
        self.mappings = kwargs.pop('mappings', {})
        self.mapped = False

    def get_absolute_path(self, root, path):
        if path in self.mappings:
            mapped_path = self.mappings[path]

            if os.path.isfile(mapped_path):
                self.mapped = True
                return os.path.abspath(mapped_path)

            elif os.path.isfile(os.path.join(root, self.mappings)):
                self.mapped = True
                return os.path.abspath(
                    os.path.join(root, self.mappings))

        self.mapped = False
        return super(StaticFileHandler, self).get_absolute_path(root, path)

    def validate_absolute_path(self, root, absolute_path):
        if self.mapped:
            return absolute_path

        return super(StaticFileHandler, self).get_absolute_path(root, path)

class IndexHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self):
        self.render("index.html")

class PupyWebServer(object):
    def __init__(self, pupsrv, config):
        self.pupsrv = pupsrv
        self.config = config
        self.clients = {}
        self.mappings = {}

        self.wwwroot = self.random_path()

        self.app = None

        self._thread = None
        self._ioloop = None

        self.listen = config.get('webserver', 'listen')
        if ':' in self.listen:
            hostname, port = self.listen.rsplit(':', 1)
            port = int(port)
            self.hostname, self.port = hostname, port
        else:
            self.hostname = self.listen
            self.port = 9000

    def start(self):
        webstatic = self.config.get_folder('webstatic')
        wwwroot = self.config.get_folder('wwwroot')
        cert = self.config.get('webserver', 'cert', None)
        key = self.config.get('webserver', 'key', None)

        self.app = tornado.web.Application([
            (r'/', IndexHandler),
            (r'/' + self.wwwroot, StaticFileHandler, {
                'path': wwwroot,
                'mappings': self.mappings,
            }),
            (r'/static/(.*)', tornado.web.StaticFileHandler, {
                'path': webstatic
            }),
        ], debug=True, template_path=webstatic)

        ssl_options = None

        if key and cert:
            ssl_options = ssl.create_default_context(
                certfile=cert, keyfile=key, server_side=True)

        self.app.listen(
            self.port,
            address=self.hostname)

        self._ioloop = tornado.ioloop.IOLoop.instance()

        self._thread = threading.Thread(target=self._ioloop.start)
        self._thread.daemon = True
        self._thread.start()

        self._registered = {}

    def stop(self):
        self._ioloop.stop()
        self._ioloop = None
        self._thread = None

    def random_path(self):
        return '/'+''.join(
            random.choice(
                string.ascii_uppercase +
                string.ascii_lowercase +
                string.digits) for _ in range(10))


    def register_mapping()

    def start_webplugin(self, name, web_handlers, cleanup=None):
        random_path = self.random_path()

        if name in self._registered:
            random_path, _, _ = self._registered[name]
            return self.port, random_path

        klasses = []

        for tab in web_handlers:
            if len(tab)==2:
                path, handler = tab
                kwargs = {}
            else:
                path, handler, kwargs = tab

            ends_with_slash = path.endswith('/')
            path = '/'.join(x for x in [random_path] + path.split('/') if x)
            if ends_with_slash:
                path += '/'

            klasses.append(handler)

            self.app.add_handlers(".*", [(path, handler, kwargs)])
            self.pupsrv.info('Register webhook for {} at {}'.format(name, path))

        self._registered[name] = random_path, klasses, cleanup

        return self.port, random_path

    def stop_webplugin(self, name):

        if not name in self._registered:
            return

        self.pupsrv.info('Unregister webhook for {} from {}'.format(name, random_path))

        random_path, klasses, cleanup = self._registered
        removed = False

        to_remove = []
        for rule in self.app.wildcard_router.rules:
            if rule.target in klassess:
                to_remove.append(rule)
                removed = True
            elif rule.matcher.regex.pattern.startswith(random_path):
                to_remove.append(rule)
                removed = True

        for rule in to_remove:
            self.app.wildcard_router.rules.remove(rule)

        to_remove = []
        for rule in self.app.default_router.rules:
            if rule.target in klassess:
                to_remove.append(rule)
                removed = True
            elif rule.matcher.regex.pattern.startswith(random_path):
                to_remove.append(rule)
                removed = True

        if cleanup:
            cleanup()

        if removed:
            del self._registered[name]
        else:
            self.pupsrv.info('{} was not found [error]'.format(name))
