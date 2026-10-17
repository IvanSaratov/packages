"""Behavioral tests use real RPM signatures and RPM-MD, with only HTTP replaced."""
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).resolve().parents[1]
BUILDER = SOURCE / "scripts" / "build_repository.py"
PRIMARY = "{http://linux.duke.edu/metadata/common}"
REPO = "{http://linux.duke.edu/metadata/repo}"
XMLBASE = "{http://www.w3.org/XML/1998/namespace}base"


def command(*args, env=None):
    result = subprocess.run(args, check=False, capture_output=True, text=True, env=env)
    if result.returncode:
        raise AssertionError(f"{args[0]} failed: {result.stdout}{result.stderr}")
    return result.stdout


class RepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BUILDER.is_file():
            raise AssertionError("Repository builder has not been implemented")
        spec = importlib.util.spec_from_file_location("repository_builder", BUILDER)
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)
        cls.fixtures = tempfile.TemporaryDirectory()
        cls.root = Path(cls.fixtures.name)
        cls.gpg = cls.root / "gnupg"
        cls.gpg.mkdir(mode=0o700)
        cls.env = dict(os.environ, GNUPGHOME=str(cls.gpg))
        cls.keys = []
        for name in ("Approved", "Unapproved"):
            command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                    "--quick-generate-key", f"{name} fixture <fixture@example.invalid>",
                    "rsa2048", "sign", "0", env=cls.env)
            listing = command("gpg", "--batch", "--with-colons", "--list-keys",
                              f"{name} fixture", env=cls.env)
            fingerprint = next(line.split(":")[9] for line in listing.splitlines()
                               if line.startswith("fpr:"))
            key = command("gpg", "--batch", "--armor", "--export", fingerprint, env=cls.env)
            cls.keys.append((fingerprint, key.encode()))
        cls.rpms = {}
        for name, version, release, epoch in (
            ("sample", "1.0.0", "1.fc44", 0),
            ("sample", "2.0.0", "1.fc44", 0),
            ("second", "1.0.0", "1.fc44", 0),
            ("sample-viewer", "1.0.0", "1.fc44", 0),
            ("sample", "1.0.0", "2.fc44", 0),
            ("sample", "1.0.0", "1.fc44", 1),
        ):
            build = cls.root / f"build-{name}-{version}-{release}-{epoch}"
            build.mkdir()
            recipe = build / "package.spec"
            recipe.write_text(f"""Name: {name}
Version: {version}
Release: {release}
Epoch: {epoch}
Summary: Synthetic repository test package
License: MIT
BuildArch: noarch
%description
Synthetic package with no private or application data.
%install
mkdir -p %{{buildroot}}/usr/share/{name}
printf 'repository fixture\\n' > %{{buildroot}}/usr/share/{name}/fixture
%files
/usr/share/{name}/fixture
""")
            command("rpmbuild", "--define", f"_topdir {build}", "-bb", str(recipe))
            rpm = next((build / "RPMS").rglob("*.rpm"))
            unsigned = rpm.read_bytes()
            command("rpmsign", "--define", "_openpgp_sign gpg",
                    "--define", f"_openpgp_sign_id {cls.keys[0][0]}",
                    "--addsign", str(rpm), env=cls.env)
            cls.rpms[(name, version, release, epoch)] = rpm.read_bytes()
            if name == "sample" and version == "1.0.0" and release == "1.fc44" and epoch == 0:
                cls.unsigned = unsigned
                wrong = build / "wrong.rpm"
                wrong.write_bytes(unsigned)
                command("rpmsign", "--define", "_openpgp_sign gpg",
                        "--define", f"_openpgp_sign_id {cls.keys[1][0]}",
                        "--addsign", str(wrong), env=cls.env)
                cls.wrong_key = wrong.read_bytes()
        # A key trusted by the runner globally must not be trusted for this feed.
        wrong_public = cls.root / "global-unapproved.asc"
        wrong_public.write_bytes(cls.keys[1][1])
        command("rpmkeys", "--import", str(wrong_public))

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "gpg"):
            subprocess.run(["gpgconf", "--homedir", str(cls.gpg), "--kill", "all"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if hasattr(cls, "fixtures"):
            cls.fixtures.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "keys").mkdir()
        (self.root / "keys" / "approved.asc").write_bytes(self.keys[0][1])
        (self.root / "site").mkdir()
        (self.root / "site" / "index.html").write_text("<!doctype html><title>Packages</title><!-- PACKAGES -->")
        (self.root / "site" / "private.asc").write_text("PRIVATE SENTINEL MUST NOT BE PUBLISHED")
        self.config = {
            "repository": "example/packages",
            "site_url": "https://packages.example.invalid",
            "targets": [{"releasever": "44", "arch": "x86_64"}],
            "packages": {"sample": {"key": "keys/approved.asc",
                                     "fingerprint": self.keys[0][0], "epoch": 0}},
            "history_hours": 48,
        }
        self.payloads = {}
        self.downloads = []
        self.release = self.make_release()
        self.path = self.root / "repository.json"
        self.output = self.root / "published"

    def make_release(self, name="sample", version="1.0.0", release="1.fc44",
                     epoch=0, payload=None, asset_arch="noarch"):
        tag = f"{name}-v{version}-{release}"
        filename = f"{name}-{version}-{release}.{asset_arch}.rpm"
        data = self.rpms[(name, version, release, epoch)] if payload is None else payload
        url = f"https://github.com/example/packages/releases/download/{tag}/{filename}"
        self.payloads[url] = data
        return {"tag_name": tag, "draft": False, "prerelease": False, "immutable": True,
                "assets": [{"name": filename, "state": "uploaded", "size": len(data),
                            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                            "browser_download_url": url}]}

    def download(self, url, destination, limit):
        self.downloads.append(url)
        data = self.payloads[url]
        if len(data) > limit:
            raise ValueError("Response exceeds limit")
        Path(destination).write_bytes(data)

    def build(self, releases=None, previous=None, now=1800000000):
        self.path.write_text(json.dumps(self.config))
        return self.builder.build_repository(self.path, releases or [self.release], self.output,
                                             download=self.download, previous_state=previous, now=now)

    def packages(self):
        folder = self.output / "fedora/44/x86_64"
        repomd = ET.parse(folder / "repodata/repomd.xml")
        primary = next(d for d in repomd.getroot().findall(REPO + "data")
                       if d.get("type") == "primary")
        location = primary.find(REPO + "location").get("href")
        return ET.fromstring(gzip.decompress((folder / location).read_bytes())).findall(PRIMARY + "package")

    def assert_rejected(self, releases=None, previous=None):
        with self.assertRaises((ValueError, RuntimeError, subprocess.CalledProcessError)):
            self.build(releases, previous)
        self.assertFalse(self.output.exists(), "Failed build exposed a partial site")

    def test_signed_package_and_release_url(self):
        self.build()
        packages = self.packages()
        self.assertEqual(len(packages), 1)
        location = packages[0].find(PRIMARY + "location")
        self.assertEqual(location.get(XMLBASE) + location.get("href"),
                         "https://github.com/example/packages/releases/download/"
                         "sample-v1.0.0-1.fc44/sample-1.0.0-1.fc44.noarch.rpm")

    def test_site_allowlist_and_repo_key_agree(self):
        self.build()
        files = {str(p.relative_to(self.output)) for p in self.output.rglob("*") if p.is_file()}
        self.assertIn("ivansaratov-fedora.repo", files)
        self.assertIn("keys/approved.asc", files)
        self.assertFalse(any(n.endswith((".rpm", ".py", ".asc.tmp")) or "private" in n for n in files))
        self.assertEqual((self.output / "keys/approved.asc").read_bytes(), self.keys[0][1])
        repo = (self.output / "ivansaratov-fedora.repo").read_text()
        self.assertIn("gpgcheck=1", repo)
        self.assertIn("repo_gpgcheck=0", repo)
        self.assertIn("metadata_expire=0", repo)
        self.assertIn("https://packages.example.invalid/keys/approved.asc", repo)
        self.assertIn("includepkgs=sample", repo)

    def test_unsigned_rpm_rejected(self):
        self.assert_rejected([self.make_release(payload=self.unsigned)])

    def test_wrong_signer_rejected_even_when_globally_trusted(self):
        self.assert_rejected([self.make_release(payload=self.wrong_key)])

    def test_changed_asset_digest_rejected(self):
        url = self.release["assets"][0]["browser_download_url"]
        self.payloads[url] = b"changed" + self.payloads[url]
        self.assert_rejected()

    def test_corrupt_rpm_rejected_even_with_matching_asset_digest(self):
        data = bytearray(self.rpms[("sample", "1.0.0", "1.fc44", 0)])
        # The middle of a small RPM can be unsigned signature-header padding.
        # Change the payload, which must be covered by the mandatory signature.
        data[-1] ^= 1
        self.assert_rejected([self.make_release(payload=bytes(data))])

    def test_wrong_rpm_identity_rejected(self):
        for key in (("second", "1.0.0", "1.fc44", 0),
                    ("sample", "2.0.0", "1.fc44", 0),
                    ("sample", "1.0.0", "2.fc44", 0),
                    ("sample", "1.0.0", "1.fc44", 1)):
            with self.subTest(key=key):
                self.assert_rejected([self.make_release(payload=self.rpms[key])])

    def test_wrong_claimed_architecture_rejected(self):
        self.assert_rejected([self.make_release(asset_arch="x86_64")])

    def test_nonstable_or_mutable_releases_excluded(self):
        for field in ("draft", "prerelease", "immutable"):
            with self.subTest(field=field):
                candidate = self.make_release(version="2.0.0")
                candidate[field] = field != "immutable"
                self.build([self.release, candidate])
                self.assertEqual(len(self.packages()), 1)
                shutil.rmtree(self.output)

    def test_no_usable_package_does_not_publish_empty_feed(self):
        self.release["immutable"] = False
        self.assert_rejected()

    def test_old_versions_remain_in_index(self):
        self.build([self.release, self.make_release(version="2.0.0")])
        self.assertEqual(sorted(p.find(PRIMARY + "version").get("ver") for p in self.packages()),
                         ["1.0.0", "2.0.0"])

    def test_multiple_registered_projects_are_indexed(self):
        self.config["packages"]["second"] = dict(self.config["packages"]["sample"])
        self.build([self.release, self.make_release(name="second")])
        self.assertEqual(sorted(p.find(PRIMARY + "name").text for p in self.packages()),
                         ["sample", "second"])

    def test_overlapping_package_names_are_indexed(self):
        self.config["packages"]["sample-viewer"] = dict(self.config["packages"]["sample"])
        self.build([self.release, self.make_release(name="sample-viewer")])
        self.assertEqual(sorted(p.find(PRIMARY + "name").text for p in self.packages()),
                         ["sample", "sample-viewer"])

    def test_unregistered_release_and_attached_key_are_not_trusted(self):
        unknown = self.make_release(name="second")
        self.release["assets"].append({"name": "approved.asc", "state": "uploaded",
                                       "digest": "sha256:" + "0" * 64, "size": 100})
        self.build([self.release, unknown])
        self.assertEqual(len(self.packages()), 1)
        self.assertFalse(any(url.endswith(".asc") for url in self.downloads))

    def test_trusted_key_fingerprint_mismatch_rejected(self):
        self.config["packages"]["sample"]["fingerprint"] = self.keys[1][0]
        self.assert_rejected()

    def test_registered_release_missing_rpm_rejected(self):
        self.release["assets"] = []
        self.assert_rejected()

    def test_unsafe_release_tag_rejected(self):
        self.release["tag_name"] = "sample-v1.0.0-1.fc44/../../escape"
        self.assert_rejected()

    def historical(self, data=b"old metadata", seen=1800000000, path=None):
        digest = hashlib.sha256(data).hexdigest()
        path = path or f"fedora/44/x86_64/repodata/{digest}-primary.xml.gz"
        self.payloads[self.config["site_url"] + "/" + path] = data
        return {"format": 1, "metadata": [{"path": path, "sha256": digest, "seen_at": seen}]}

    def test_recent_hashed_metadata_retained(self):
        previous = self.historical()
        self.build(previous=previous, now=1800000001)
        self.assertTrue((self.output / previous["metadata"][0]["path"]).is_file())

    def test_current_metadata_retention_timestamp_is_refreshed(self):
        self.build()
        previous = json.loads((self.output / "repository-state.json").read_text())
        for record in previous["metadata"]:
            self.payloads[self.config["site_url"] + "/" + record["path"]] = (self.output / record["path"]).read_bytes()
        shutil.rmtree(self.output)
        self.build(previous=previous, now=1800003600)
        state = json.loads((self.output / "repository-state.json").read_text())
        records = {r["path"]: r for r in state["metadata"]}
        repomd = ET.parse(self.output / "fedora/44/x86_64/repodata/repomd.xml")
        for node in repomd.getroot().findall(REPO + "data"):
            path = "fedora/44/x86_64/" + node.find(REPO + "location").get("href")
            self.assertEqual(records[path]["seen_at"], 1800003600)

    def test_expired_hashed_metadata_not_retained(self):
        previous = self.historical(seen=1800000000 - 49 * 3600)
        self.build(previous=previous)
        self.assertFalse((self.output / previous["metadata"][0]["path"]).exists())

    def test_current_metadata_survives_replacement_after_long_idle(self):
        self.build()
        previous = json.loads((self.output / "repository-state.json").read_text())
        paths = {record["path"] for record in previous["metadata"]}
        for path in paths:
            self.payloads[self.config["site_url"] + "/" + path] = (self.output / path).read_bytes()
        shutil.rmtree(self.output)
        retirement = 1800000000 + 7 * 24 * 3600
        self.build([self.release, self.make_release(version="2.0.0")], previous=previous, now=retirement)
        state = json.loads((self.output / "repository-state.json").read_text())
        records = {r["path"]: r for r in state["metadata"]}
        self.assertTrue(paths - set(state.get("current_metadata", [])), "Fixture must replace old metadata")
        for path in paths:
            self.assertTrue((self.output / path).is_file(), "Retired metadata disappeared immediately")
            self.assertEqual(records[path]["seen_at"], retirement)

    def test_invalid_current_metadata_history_rejected(self):
        for value in ("not a list", ["../escape"],
                      ["fedora/44/x86_64/repodata/" + "0" * 64 + "-primary.xml.gz"]):
            with self.subTest(value=value):
                previous = self.historical()
                previous["current_metadata"] = value
                self.assert_rejected(previous=previous)

    def test_history_traversal_rejected(self):
        self.assert_rejected(previous=self.historical(path="../escape"))

    def test_history_digest_mismatch_rejected(self):
        previous = self.historical()
        self.payloads[self.config["site_url"] + "/" + previous["metadata"][0]["path"]] = b"tampered"
        self.assert_rejected(previous=previous)

    def test_state_contains_only_public_package_metadata(self):
        self.build()
        state = json.loads((self.output / "repository-state.json").read_text())
        self.assertEqual(state["format"], 1)
        self.assertEqual(state["packages"][0]["name"], "sample")
        self.assertEqual(state["packages"][0]["version"], "1.0.0")
        self.assertNotIn(str(self.root), json.dumps(state))
        self.assertTrue(state["metadata"])


if __name__ == "__main__":
    unittest.main()
