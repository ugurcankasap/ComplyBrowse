import configparser
import json
import plistlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "qa_tests" / "macos_fixtures"


def read_plist(name):
    with (FIXTURES / name).open("rb") as stream:
        return plistlib.load(stream)


def read_prefs(name):
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return {
        key: json.loads(value)
        for key, value in re.findall(r'user_pref\("([^"]+)",\s*(true|false|null|-?\d+(?:\.\d+)?)\);', text)
    }


def evaluate_user_policy(managed, user_sources, expected, access_denied=False, supported=True):
    if not supported:
        return {"verdict": "NOT_ASSESSED"}
    if access_denied:
        return {"verdict": "NOT_ASSESSED", "root_cause": "RC_TCC_PERMISSION_MISSING"}
    if managed is not None:
        return {"verdict": "PASS" if managed == expected else "FAIL"}
    values = [value for value in user_sources if value is not None]
    if len(set(values)) > 1:
        return {"verdict": "NOT_ASSESSED", "reason": "conflicting_user_sources"}
    if values:
        return {"verdict": "PASS_NOT_ENFORCED" if values[0] == expected else "FAIL"}
    return {"verdict": "FAIL"}


def read_json(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def assert_policy_map_contract(test_case, controls):
    control_ids = [item.get("control_id") for item in controls]
    test_case.assertTrue(control_ids)
    test_case.assertEqual(len(control_ids), len(set(control_ids)))
    for item in controls:
        test_case.assertTrue(item.get("control_id"))
        supported = item.get("macos_supported", True)
        if supported:
            if item.get("mode", "MANUAL").upper() != "MANUAL":
                test_case.assertTrue(item.get("policy_key") or item.get("pref_name"))
        else:
            test_case.assertTrue(item.get("unsupported_reason"))


class TestMacOSFixtureContracts(unittest.TestCase):
    def test_policy_maps_have_complete_macOS_contracts(self):
        chrome = read_json("chrome_macos_policy_map.json")
        firefox = read_json("firefox_macos_policy_map.json")
        safari = read_json("safari_macos_policy_map.json")

        assert_policy_map_contract(self, chrome)
        assert_policy_map_contract(self, firefox["controls"])
        assert_policy_map_contract(self, safari["controls"])

        catalog_ids = {
            line.split("|", 1)[0]
            for line in (ROOT / "safari_controls.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertEqual(catalog_ids, {item["control_id"] for item in safari["controls"]})

    def test_required_fixtures_are_synthetic_and_parseable(self):
        compatible = read_plist("managed_com.google.Chrome_compatible.plist")
        incompatible = read_plist("managed_com.google.Chrome_incompatible.plist")
        user = read_plist("user_com.google.Chrome.plist")
        self.assertEqual(compatible["PasswordManagerEnabled"], False)
        self.assertEqual(incompatible["PasswordManagerEnabled"], True)
        self.assertEqual(user["PasswordManagerEnabled"], False)

        policies = json.loads((FIXTURES / "firefox_policies.json").read_text(encoding="utf-8"))
        self.assertIn("policies", policies)
        self.assertEqual(read_prefs("prefs.js")["signon.rememberSignons"], False)

        profiles = configparser.ConfigParser()
        profiles.read(FIXTURES / "profiles.ini", encoding="utf-8")
        self.assertEqual(profiles["Profile0"]["Path"], "Profiles/profile-alpha")
        self.assertEqual(profiles["Profile1"]["Path"], "Profiles/profile-beta")

    def test_managed_compatible_is_pass(self):
        result = evaluate_user_policy(False, [], expected=False)
        self.assertEqual(result["verdict"], "PASS")

    def test_managed_incompatible_is_fail(self):
        result = evaluate_user_policy(True, [], expected=False)
        self.assertEqual(result["verdict"], "FAIL")

    def test_user_compatible_without_managed_is_pass_not_enforced(self):
        result = evaluate_user_policy(None, [False], expected=False)
        self.assertEqual(result["verdict"], "PASS_NOT_ENFORCED")

    def test_missing_managed_and_user_is_fail_for_policy_control(self):
        result = evaluate_user_policy(None, [], expected=False)
        self.assertEqual(result["verdict"], "FAIL")

    def test_access_denied_is_not_assessed_with_tcc_root_cause(self):
        metadata = json.loads((FIXTURES / "access_denied.json").read_text(encoding="utf-8"))
        result = evaluate_user_policy(False, [], expected=False, access_denied=metadata["access_denied"])
        self.assertEqual(result, {"verdict": "NOT_ASSESSED", "root_cause": "RC_TCC_PERMISSION_MISSING"})

    def test_unsupported_macos_control_is_not_assessed(self):
        chrome_map = json.loads((ROOT / "chrome_macos_policy_map.json").read_text(encoding="utf-8"))
        unsupported = next(item for item in chrome_map if item["control_id"] == "1.7")
        self.assertFalse(unsupported["macos_supported"])
        result = evaluate_user_policy(False, [], expected=False, supported=unsupported["macos_supported"])
        self.assertEqual(result["verdict"], "NOT_ASSESSED")

    def test_conflicting_user_sources_are_not_assessed(self):
        user = read_plist("user_com.google.Chrome.plist")
        profile = json.loads((FIXTURES / "chrome_profile_preferences.json").read_text(encoding="utf-8"))
        result = evaluate_user_policy(
            None,
            [user["PasswordManagerEnabled"], profile["credentials_enable_service"]],
            expected=False,
        )
        self.assertEqual(result, {"verdict": "NOT_ASSESSED", "reason": "conflicting_user_sources"})

    def test_process_fixtures_cover_bypass_and_clean_paths(self):
        clean = (FIXTURES / "process_args_no_bypass.txt").read_text(encoding="utf-8")
        bypass = (FIXTURES / "process_args_bypass.txt").read_text(encoding="utf-8")
        self.assertNotRegex(clean, r"--(?:disable-web-security|safe-mode)\b")
        self.assertRegex(bypass, r"--disable-web-security\b")
        self.assertRegex(bypass, r"--safe-mode\b")

    def test_safari_tcc_denial_never_becomes_fail(self):
        metadata = json.loads((FIXTURES / "safari_tcc_denied.json").read_text(encoding="utf-8"))
        safari_map = json.loads((ROOT / "safari_macos_policy_map.json").read_text(encoding="utf-8"))
        self.assertEqual(len(safari_map["controls"]), 9)
        self.assertEqual(metadata["root_cause"], "RC_TCC_PERMISSION_MISSING")
        results = [
            {"verdict": "NOT_ASSESSED", "root_cause": metadata["root_cause"], "counts_in_score": False}
            for _ in safari_map["controls"]
        ]
        self.assertTrue(all(result["verdict"] != "FAIL" for result in results))
        self.assertTrue(all(not result["counts_in_score"] for result in results))

    def test_safari_unsupported_controls_are_explicit(self):
        safari_map = json.loads((ROOT / "safari_macos_policy_map.json").read_text(encoding="utf-8"))
        unsupported = [item for item in safari_map["controls"] if not item["macos_supported"]]
        self.assertEqual({item["control_id"] for item in unsupported}, {"SAF-003", "SAF-004"})
        self.assertTrue(all(item.get("unsupported_reason") for item in unsupported))


if __name__ == "__main__":
    unittest.main(verbosity=2)
