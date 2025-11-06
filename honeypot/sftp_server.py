import os
import stat
import paramiko
from . import config
from . import logger
from . import db
HONEYPOT_LOGGER = logger.get_logger()


class HoneypotSFTPServer(paramiko.SFTPServerInterface):

    def __init__(self, server, *args, **kwargs):
        self.server = server
        self.root = config.SFTP_ROOT
        os.makedirs(self.root, exist_ok=True)
        super().__init__(*args, **kwargs)

    def _realpath(self, path):
        path = os.path.normpath(path).lstrip('/')
        return os.path.join(self.root, path)

    def list_folder(self, path):
        real = self._realpath(path)
        if not os.path.exists(real):
            return paramiko.SFTP_NO_SUCH_FILE
        try:
            entries = []
            for f in os.listdir(real):
                fpath = os.path.join(real, f)
                s = os.stat(fpath)
                attr = paramiko.SFTPAttributes.from_stat(s, f)
                entries.append(attr)
            return entries
        except Exception:
            return paramiko.SFTP_FAILURE

    def stat(self, path):
        real = self._realpath(path)
        if not os.path.exists(real):
            return paramiko.SFTP_NO_SUCH_FILE
        return paramiko.SFTPAttributes.from_stat(os.stat(real), os.path.basename(real))

    def lstat(self, path):
        return self.stat(path)
    def open(self, path, flags, attr):
        real = self._realpath(path)
        try:
            return paramiko.SFTPServerFile(self, real, 'r' if flags & os.O_RDONLY else 'w')
        except Exception:
            return paramiko.SFTP_FAILURE
    def remove(self, path):
        real = self._realpath(path)
        try:
            os.remove(real)
            return paramiko.SFTP_OK
        except Exception:
            return paramiko.SFTP_FAILURE

    def rename(self, oldpath, newpath):
        old = self._realpath(oldpath)
        new = self._realpath(newpath)
        try:
            os.rename(old, new)
            return paramiko.SFTP_OK
        except Exception:
            return paramiko.SFTP_FAILURE

    def mkdir(self, path, attr):
        real = self._realpath(path)
        try:
            os.makedirs(real, exist_ok=True)
            return paramiko.SFTP_OK
        except Exception:
            return paramiko.SFTP_FAILURE

    def rmdir(self, path):
        real = self._realpath(path)
        try:
            os.rmdir(real)
            return paramiko.SFTP_OK
        except Exception:
            return paramiko.SFTP_FAILURE

    def chattr(self, path, attr):
        return paramiko.SFTP_OK

    def readlink(self, path):
        return paramiko.SFTP_OP_UNSUPPORTED

    def symlink(self, path, target):
        return paramiko.SFTP_OP_UNSUPPORTED

    def canonicalize(self, path):
        return os.path.normpath(path)
