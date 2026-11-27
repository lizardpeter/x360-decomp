import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from collections import defaultdict
from metro_profile_evidence import is_focus,grouped_paths
class ProfileEvidence(unittest.TestCase):
    def test_local_roots_only(self):
        for name in ("XamProfileEnumerate","XamUserGetSigninState","XamContentCreateDeviceEnumerator"):
            self.assertTrue(is_focus(name))
        for name in ("XamProfileLoadWindowsLiveCredentials","XamProfileSaveWindowsLiveCredentials","XamUserGetXUIDForTFA","XeKeysGetKey"):
            self.assertFalse(is_focus(name))

    def test_internal_ui_and_storage_roots(self):
        for name in ("XamShowSigninUIp","XamContentCreateEnumeratorInternal","XamNotifyCreateListenerInternal"):
            self.assertTrue(is_focus(name))
    def test_independent_bounded_api_paths(self):
        edges=defaultdict(set,{1:{(2,4,True),(3,8,True)},4:{(5,16,True)}})
        calls=defaultdict(list,{5:[{"import":{"library":"xboxkrnl","ordinal":"0001","name":"NtOpenFile","sdk_stub":False}}]})
        report=grouped_paths({"identity":{1},"storage":{4}},edges,calls,limit=2)
        self.assertTrue(report["identity"]["truncated"])
        self.assertFalse(report["storage"]["truncated"])
        self.assertEqual(report["storage"]["imports"][0]["name"],"NtOpenFile")
        self.assertEqual(report["storage"]["nodes"][-1]["entry"],"00000005")
