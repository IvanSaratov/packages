#!/usr/bin/env python3
"""Build a small, verified RPM-MD repository without publishing RPM payloads."""
import argparse
import hashlib
import html
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

MAX_RPM = 512 * 1024 * 1024
MAX_METADATA = 20 * 1024 * 1024
MAX_SITE = 900 * 1024 * 1024
SAFE_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
HISTORY_PATH = re.compile(
    r"fedora/[0-9]+/[A-Za-z0-9_]+/repodata/"
    r"([0-9a-f]{64})-(?:primary|filelists|filelists-ext|other)\.xml\.gz"
)


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stdout}{result.stderr}")
    return result.stdout


def download_url(url, destination, limit):
    request = Request(url, headers={"User-Agent": "personal-rpm-repository"})
    total = 0
    with urlopen(request, timeout=60) as response, Path(destination).open("wb") as output:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise ValueError("Download exceeds configured size limit")
            output.write(chunk)


def load_config(path):
    root = Path(path).resolve().parent
    config = json.loads(Path(path).read_text())
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", config["repository"]):
        raise ValueError("Invalid release repository")
    site = urlparse(config["site_url"])
    if site.scheme != "https" or not site.netloc or site.username or site.password or site.query or site.fragment:
        raise ValueError("Site URL must be a plain HTTPS URL")
    config["site_url"] = config["site_url"].rstrip("/")
    if not config["packages"] or not config["targets"]:
        raise ValueError("At least one package and target are required")
    for target in config["targets"]:
        if not re.fullmatch(r"[0-9]+", target["releasever"]) or not re.fullmatch(r"[A-Za-z0-9_]+", target["arch"]):
            raise ValueError("Invalid Fedora target")
    for name, policy in config["packages"].items():
        if not SAFE_PART.fullmatch(name) or not re.fullmatch(r"keys/[A-Za-z0-9_.-]+", policy["key"]):
            raise ValueError("Invalid package policy")
        key = (root / policy["key"]).resolve()
        if not key.is_relative_to(root) or not key.is_file():
            raise ValueError("Signing key must be a file inside the repository")
        if not re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", policy["fingerprint"]):
            raise ValueError("Invalid expected key fingerprint")
        if type(policy.get("epoch", 0)) is not int or policy.get("epoch", 0) < 0:
            raise ValueError("Invalid expected RPM epoch")
    return root, config


def trusted_keyrings(root, config, work, site):
    rings = {}
    gpg_home = work / "gnupg"
    gpg_home.mkdir(mode=0o700)
    for name, policy in config["packages"].items():
        key = root / policy["key"]
        data = key.read_bytes()
        if (not data.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
                or not data.rstrip().endswith(b"-----END PGP PUBLIC KEY BLOCK-----")
                or b"PRIVATE KEY" in data):
            raise ValueError("Only armored public signing keys can be published")
        listing = run("gpg", "--batch", "--homedir", str(gpg_home),
                      "--with-colons", "--show-keys", str(key))
        primary, awaiting = [], False
        for line in listing.splitlines():
            kind = line.split(":", 1)[0]
            if kind == "pub":
                awaiting = True
            elif kind == "fpr" and awaiting:
                primary.append(line.split(":")[9])
                awaiting = False
        if primary != [policy["fingerprint"]]:
            raise ValueError(f"Signing key fingerprint mismatch for {name}")
        ring = work / ("rpmdb-" + name)
        ring.mkdir()
        run("rpmkeys", "--dbpath", str(ring), "--define", "_keyring rpmdb", "--import", str(key))
        rings[name] = ring
        destination = site / policy["key"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    return rings


def selected_rpms(config, releases):
    seen = set()
    for release in releases:
        if release.get("draft") is not False or release.get("prerelease") is not False or release.get("immutable") is not True:
            continue
        tag = release.get("tag_name", "")
        name = next((n for n in sorted(config["packages"], key=len, reverse=True)
                     if tag.startswith(n + "-v")), None)
        if name is None:
            continue
        if not SAFE_PART.fullmatch(tag):
            raise ValueError("Unsafe registered release tag")
        try:
            version, rpm_release = tag[len(name) + 2:].rsplit("-", 1)
        except ValueError as error:
            raise ValueError("Invalid registered release tag") from error
        if not SAFE_PART.fullmatch(version) or not re.fullmatch(r"[A-Za-z0-9._+]+\.fc[0-9]+", rpm_release):
            raise ValueError("Invalid RPM version or release")
        releasever = rpm_release.rsplit(".fc", 1)[1]
        arches = {t["arch"] for t in config["targets"] if t["releasever"] == releasever}
        if not arches:
            continue
        if tag in seen:
            raise ValueError("Duplicate release tag")
        seen.add(tag)
        found = False
        for asset in release.get("assets", []):
            for arch in sorted(arches | {"noarch"}):
                filename = f"{name}-{version}-{rpm_release}.{arch}.rpm"
                if asset.get("name") != filename:
                    continue
                found = True
                size = asset.get("size")
                if (asset.get("state") != "uploaded" or type(size) is not int
                        or not 0 < size <= MAX_RPM
                        or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest", ""))):
                    raise ValueError("Missing or invalid RPM asset integrity data")
                yield name, version, rpm_release, arch, releasever, tag, asset
        if not found:
            raise ValueError(f"Registered release {tag} has no supported RPM")


def restore_history(config, state, site, download, now):
    records = {}
    if state is None:
        return records
    if state.get("format") != 1 or not isinstance(state.get("metadata"), list) or len(state["metadata"]) > 10000:
        raise ValueError("Invalid repository history")
    current = state.get("current_metadata", [])
    if (not isinstance(current, list)
            or any(not isinstance(path, str) or not HISTORY_PATH.fullmatch(path) for path in current)):
        raise ValueError("Invalid current metadata history")
    paths = {record["path"] for record in state["metadata"]}
    if not set(current).issubset(paths):
        raise ValueError("Current metadata is missing from history")
    current = set(current)
    total = 0
    for record in state["metadata"]:
        match = HISTORY_PATH.fullmatch(record["path"])
        seen = record.get("seen_at")
        if (not match or match[1] != record.get("sha256")
                or type(seen) is not int or seen < 0 or seen > now + 300):
            raise ValueError("Unsafe or invalid metadata history record")
        # Previously current files remained live until this deployment, even
        # when the last build happened long ago. Start retention on retirement.
        if record["path"] in current:
            seen = now
        if now - seen > config.get("history_hours", 48) * 3600:
            continue
        destination = site / PurePosixPath(record["path"])
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            download(config["site_url"] + "/" + record["path"], destination, MAX_METADATA)
        data = destination.read_bytes()
        if len(data) > MAX_METADATA or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError("Historical metadata checksum mismatch")
        total += len(data)
        if total > MAX_SITE:
            raise ValueError("Metadata history exceeds site budget")
        records[record["path"]] = dict(record, seen_at=seen)
    return records


def build_repository(config_path, releases, output, *, download=download_url, previous_state=None, now=None):
    root, config = load_config(config_path)
    now = int(time.time()) if now is None else now
    output = Path(output)
    if output.exists():
        raise ValueError("Output directory must not already exist")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        work = Path(temporary)
        site = work / "site"
        site.mkdir()
        rings = trusted_keyrings(root, config, work, site)
        packages = []
        identities = set()
        inputs = {}
        for target in config["targets"]:
            key = (target["releasever"], target["arch"])
            inputs[key] = work / ("rpms-" + "-".join(key))
            inputs[key].mkdir()

        for name, version, rpm_release, arch, releasever, tag, asset in selected_rpms(config, releases):
            filename = asset["name"]
            url = f"https://github.com/{config['repository']}/releases/download/{quote(tag, safe='')}/{quote(filename, safe='')}"
            local = work / filename
            download(url, local, asset["size"])
            if local.stat().st_size != asset["size"] or hashlib.sha256(local.read_bytes()).hexdigest() != asset["digest"][7:]:
                raise ValueError(f"RPM asset checksum mismatch: {filename}")
            ring_args = ("--dbpath", str(rings[name]), "--define", "_keyring rpmdb")
            # The default rpmkeys policy accepts unsigned digest-only packages.
            run("rpmkeys", *ring_args, "--define", "_pkgverify_level signature", "--checksig", str(local))
            identity = run("rpm", *ring_args, "-qp", "--qf",
                           "%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}", str(local)).strip()
            expected = f"{name}|{config['packages'][name].get('epoch', 0)}|{version}|{rpm_release}|{arch}"
            if identity != expected or identity in identities:
                raise ValueError(f"RPM identity mismatch or duplicate: {filename}")
            identities.add(identity)
            for target, directory in inputs.items():
                if target[0] == releasever and arch in (target[1], "noarch"):
                    folder = directory / tag
                    folder.mkdir(exist_ok=True)
                    shutil.copyfile(local, folder / filename)
            packages.append({"name": name, "version": version, "release": rpm_release, "arch": arch,
                             "sha256": asset["digest"][7:], "url": url})
            print(f"Verified {filename}")
        if not packages:
            raise ValueError("No approved signed RPMs; refusing to publish an empty repository")

        for (releasever, arch), directory in inputs.items():
            if not any(directory.rglob("*.rpm")):
                raise ValueError(f"No approved RPMs for Fedora {releasever} {arch}")
            target = site / "fedora" / releasever / arch
            target.mkdir(parents=True)
            run("createrepo_c", "--quiet", "--no-database", "--checksum", "sha256",
                "--general-compress-type", "gz", "--baseurl",
                f"https://github.com/{config['repository']}/releases/download/",
                "--outputdir", str(target), str(directory))
            if not (target / "repodata/repomd.xml").is_file():
                raise RuntimeError("createrepo_c did not generate repomd.xml")

        current_metadata = {p.relative_to(site).as_posix()
                            for p in site.glob("fedora/*/*/repodata/*") if p.name != "repomd.xml"}
        records = restore_history(config, previous_state, site, download, now)
        for path in site.glob("fedora/*/*/repodata/*"):
            if path.name == "repomd.xml":
                continue
            relative = path.relative_to(site).as_posix()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            match = HISTORY_PATH.fullmatch(relative)
            if not match or match[1] != digest:
                raise ValueError("Unexpected generated metadata file")
            # Retained files keep their last-reference timestamp.
            if relative in current_metadata:
                records[relative] = {"path": relative, "sha256": digest, "seen_at": now}

        key_urls = sorted({config["site_url"] + "/" + p["key"] for p in config["packages"].values()})
        names = " ".join(sorted(config["packages"]))
        repo = ("[ivansaratov-fedora]\n"
                "name=IvanSaratov packages for Fedora $releasever - $basearch\n"
                f"baseurl={config['site_url']}/fedora/$releasever/$basearch/\n"
                "enabled=1\ngpgcheck=1\nrepo_gpgcheck=0\nmetadata_expire=0\n"
                "skip_if_unavailable=0\n"
                f"includepkgs={names}\n"
                "gpgkey=" + "\n       ".join(key_urls) + "\n")
        (site / "ivansaratov-fedora.repo").write_text(repo)
        listing = "<ul>" + "".join(
            f"<li>{html.escape(p['name'])} {html.escape(p['version'])}-{html.escape(p['release'])} "
            f"({html.escape(p['arch'])})</li>"
            for p in sorted(packages, key=lambda p: (p["name"], p["version"], p["release"], p["arch"]))
        ) + "</ul>"
        template = root / "site/index.html"
        if template.is_symlink():
            raise ValueError("Site template must not be a symlink")
        (site / "index.html").write_text(template.read_text().replace("<!-- PACKAGES -->", listing))
        state = {"format": 1, "packages": packages, "current_metadata": sorted(current_metadata),
                 "metadata": sorted(records.values(), key=lambda r: r["path"])}
        (site / "repository-state.json").write_text(json.dumps(state, indent=2) + "\n")
        if sum(p.stat().st_size for p in site.rglob("*") if p.is_file()) > MAX_SITE:
            raise ValueError("Generated site exceeds Pages budget")
        site.rename(output)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("repository.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    _, config = load_config(args.config)
    pages = json.loads(run("gh", "api", "--paginate", "--slurp",
                           f"repos/{config['repository']}/releases?per_page=100"))
    releases = [release for page in pages for release in page]
    previous = None
    url = config["site_url"] + "/repository-state.json?build=" + str(time.time_ns())
    with tempfile.TemporaryDirectory() as temporary:
        history = Path(temporary) / "state.json"
        try:
            download_url(url, history, MAX_METADATA)
        except HTTPError as error:
            if error.code != 404:
                raise
        else:
            previous = json.loads(history.read_text())
    build_repository(args.config, releases, args.output, previous_state=previous)


if __name__ == "__main__":
    main()
