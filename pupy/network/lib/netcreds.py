# -*- encoding: utf-8 -*-

__all__ = (
    'NetCreds',
    'add_cred', 'find_creds',
    'find_first_cred', 'find_all_creds', 'find_creds_for_uri',
    'export'
)

from socket import getaddrinfo, gaierror
from urlparse import urlparse
from netaddr import IPAddress, AddrFormatError

_TARGET_WEIGHTS = {
    'domain': 0b1, 'schema': 0b10,
    'realm': 0b100, 'port': 0b1000, 'path': 0b10000,
    'hostname': 0b100000, 'username': 0b1000000,
    'password': 0b10000000
}


def resolve_ip(hostname, port=0):
    ips = set()
    try:
        ip = set()
        for _, _, _, _, (ip, _) in getaddrinfo(hostname, port):
            ips.add(ip)

    except gaierror:
        return None

    return ips


def are_different(first, second):
    if not first or not second:
        return False

    if type(first) is not set and type(second) is set:
        if first not in second:
            return True

    if type(first) is set and type(second) is not set:
        if second not in first:
            return True

    return first != second


class AuthInfo(object):
    __slots__ = (
        'username', 'password', 'domain', 'schema',
        'hostname', 'ip', 'port', 'realm', 'path',
        'custom'
    )

    def __init__(
        self, username, password=None, domain=None, schema=None,
            address=None, ip=None, port=None, realm=None,
            path=False, custom=None):

        self.password = password
        self.schema = schema
        self.port = port
        self.realm = realm
        self.path = path
        self.custom = custom

        self.hostname = None
        self.ip = None

        if domain is True:
            if '\\' in username:
                self.domain, self.username = username.split('\\')
            else:
                self.domain = None
                self.username = username
        else:
            self.domain = domain
            self.username = username

        try:
            self.ip = {IPAddress(address)}
            self.hostname = None
        except AddrFormatError:
            self.ip = None
            self.hostname = address

        if self.ip is None and self.hostname:
            self.ip = resolve_ip(self.hostname, self.port)

    def _weight(self):
        value = 0b0

        for field, weight in _TARGET_WEIGHTS.iteritems():
            if getattr(self, field):
                value |= weight

        return value

    def __lt__(self, other):
        return self._weight() < other._weight()

    def __eq__(self, other):
        if type(other) != type(self):
            return False

        return all(
            getattr(self, key) == getattr(other, key)
            for key in self.__slots__
        )

    def __hash__(self):
        rethash = 0
        for key in self.__slots__:
            if key == 'custom':
                continue

            value = getattr(self, key)

            if type(value) == set:
                for item in value:
                    rethash <<= 1
                    rethash ^= hash(item)
            else:
                rethash <<= 1
                rethash ^= hash(value)

        for key in self.custom:
            rethash <<= 1
            rethash ^= hash(self.custom[key])

        return rethash

    @property
    def user(self):
        if self.domain:
            return self.domain + '\\' + self.username

        return self.username

    def __getattr__(self, key):
        if self.custom and key in self.custom:
            return self.custom[key]

    def as_dict(self):
        result = {
            key: getattr(self, key) for key in self.__slots__
            if key != 'custom' and getattr(self, key)
        }

        result['user'] = self.user

        result.update(self.custom)
        return result


class NetCreds(object):
    __slots__ = ('creds',)

    default_creds_manager = None

    def __init__(self):
        self.creds = set()

    @staticmethod
    def get_default_creds_manager():
        if NetCreds.default_creds_manager is None:
            NetCreds.default_creds_manager = NetCreds()

        return NetCreds.default_creds_manager

    def add_cred(
        self, username, password=None, domain=None, schema=None,
            hostname=None, ip=None, port=None, realm=None, path=None, **kwargs):

        self.creds.add(
            AuthInfo(
                username, password, domain, schema,
                hostname, ip, port, realm, path, kwargs))

    def add_uri(self, uri, password=None, username=None, realm=None):
        parsed = urlparse(uri)
        self.creds.add(
            AuthInfo(
                username or parsed.username,
                password or parsed.password,
                True, parsed.schema, parsed.hostname,
                parsed.port, realm
            )
        )

    def find_creds_for_uri(authuri, username=None, realm=None, domain=None):
        parsed = urlparse(authuri)
        for cred in self.find_creds(
            parsed.schema, parsed.hostname, username or parsed.username,
                realm, domain, parsed.path):

            yield cred

    def find_creds(
        self, schema=None, address=None, port=None, username=None, realm=None,
            domain=None, path=None):

        if address is not None:
            try:
                ip = {IPAddress(address)}
                hostname = None
            except AddrFormatError:
                ip = resolve_ip(address, port)
                hostname = address
        else:
            ip = None
            hostname = None

        if username is not None:
            if '\\' in username and domain is None:
                domain, username = username.split('\\', 1)

        found_cred = None

        for cred in sorted(self.creds, key=lambda x: x._weight(), reverse=True):
            pairs = (
                (realm, cred.realm),
                (domain, cred.domain),
                (schema, cred.schema),
                (ip, cred.ip),
                (hostname, cred.hostname),
                (port, cred.port),
                (username, cred.username),
            )

            different = False

            for (first, second) in pairs:
                if are_different(first, second):
                    different = True
                    break

            if path is not None and cred.path is not None:
                these_parts = '/'.join(
                    x for x in path.split('/') if x
                )

                those_parts = '/'.join(
                    x for x in cred.path.split('/') if x
                )

                if len(these_parts) < len(those_parts):
                    different = True
                else:
                    for x, y in zip(these_parts, those_parts):
                        if x != y:
                            different = True
                            break

            if different:
                continue

                (parsed.path, cred.path)

            yield cred

    # Urllib2 HTTPPasswordMgr
    def find_user_password(self, realm, authuri):
        for cred in self.find_creds(authuri, realm=realm):
            return cred.password


def add_cred(
    username, password=None, domain=None, schema=None,
       hostname=None, ip=None, port=None, realm=None, path=None, **kwargs):

    manager = NetCreds.get_default_creds_manager()
    manager.add_cred(
        username, password, domain, schema, hostname,
        ip, port, realm, path, **kwargs
    )


def find_creds(
    schema=None, address=None, port=None, username=None, realm=None,
        domain=None, path=None):

    manager = NetCreds.get_default_creds_manager()
    for cred in manager.find_creds(
            schema, address, port, username, realm, domain, path):
        yield cred


def find_first_cred(
    schema=None, address=None, port=None, username=None, realm=None,
        domain=None, path=None):

    manager = NetCreds.get_default_creds_manager()
    for cred in manager.find_creds(
            schema, address, port, username, realm, domain, path):
        return cred


def find_all_creds(
    schema=None, address=None, port=None, username=None, realm=None,
        domain=None, path=None):

    return tuple(find_creds(
        schema=None, address=None, port=None, username=None,
        realm=None, domain=None, path=None))


def find_creds_for_uri(authuri, username=None, realm=None, domain=None):
    manager = NetCreds.get_default_creds_manager()
    for cred in manager.find_creds_for_uri(authuri, username, realm, domain):
        yield cred


def export():
    manager = NetCreds.get_default_creds_manager()
    return tuple(
        tuple((k,v) for k,v in x.as_dict().iteritems())
        for x in manager.creds
    )
