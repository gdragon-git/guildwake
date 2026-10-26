import profile_fixture
"""Credential metadata compatibility and refusal using dummy values only."""
from types import SimpleNamespace
import stat
import unittest
from unittest.mock import MagicMock,patch
from discord_amp import runtime
from discord_amp.model import Fault

class RuntimeCredentialTests(unittest.TestCase):
    def load(self,mode,uid=0,gid=0,symlink=False,value=b' dummy password '):
        path=MagicMock()
        path.stat.return_value=SimpleNamespace(st_mode=stat.S_IFREG|mode,st_uid=uid,st_gid=gid)
        path.is_symlink.return_value=symlink
        path.read_bytes.return_value=value
        directory=MagicMock(); directory.__truediv__.return_value=path
        with patch.object(runtime,'Path',return_value=directory),patch.object(runtime.os,'geteuid',return_value=999,create=True),\
             patch.dict(runtime.os.environ,{'CREDENTIALS_DIRECTORY':'/dummy-private-credentials'}):
            result=runtime.credential('amp-password')
        return result
    def test_systemd_root_read_mask_and_private_modes_preserve_password(self):
        for mode,uid,gid in [(0o440,0,0),(0o400,0,0),(0o400,999,988)]:
            with self.subTest(mode=mode,uid=uid): self.assertEqual(self.load(mode,uid,gid),' dummy password ')
    def test_other_readers_writers_owners_and_symlinks_rejected(self):
        for mode,uid,gid,link in [(0o444,0,0,False),(0o440,0,988,False),(0o440,999,0,False),
                (0o460,0,0,False),(0o600,0,0,False),(0o400,998,0,False),(0o400,0,0,True)]:
            with self.subTest(mode=mode,uid=uid,gid=gid,link=link),self.assertRaises(Fault) as error:
                self.load(mode,uid,gid,link)
            self.assertEqual(error.exception.code,'credential_unavailable')
