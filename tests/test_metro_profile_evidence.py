import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_profile_evidence import is_focus
class ProfileEvidence(unittest.TestCase):
    def test_local_roots_only(self):
        for name in ("XamProfileEnumerate","XamUserGetSigninState","XamContentCreateDeviceEnumerator"):
            self.assertTrue(is_focus(name))
        for name in ("XamProfileLoadWindowsLiveCredentials","XamProfileSaveWindowsLiveCredentials","XamUserGetXUIDForTFA","XeKeysGetKey"):
            self.assertFalse(is_focus(name))
