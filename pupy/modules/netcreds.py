# -*- encoding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color

class NetCreds(PupyModule):
    ''' Manage saved authentication information '''
    
    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='netcreds', description=cls.__doc__
        )

        commands = cls.arg_parser.add_subparsers(title='actions')
        
        lst = commands.add_parser('list', help='List stored credentials')
        lst.set_defaults(action=cls.list)

        add = commands.add_parser('add', help='Add credential')
        add.set_defaults(action=cls.add)

        remove = commands.add_parser('del', help='Delete credential')
        remove.set_defaults(action=cls.remove)

        clear = commands.add_parser('clear', help='Delete all credentials')
        clear.set_defaults(action=cls.clear)

    def list(self, args):
        pass

    def add(self, args):
        pass

    def remove(self, args):
        pass

    def clear(self, args):
        pass

