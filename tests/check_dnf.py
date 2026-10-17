#!/usr/bin/env python3
"""Exercise the generated or live repository with Fedora's actual DNF client."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed:\n{result.stdout}{result.stderr}")
    return result.stdout


def check(base):
    config = json.loads((ROOT / "repository.json").read_text())
    with urlopen(base + "/repository-state.json", timeout=30) as response:
        state = json.load(response)
    with urlopen(base + "/ivansaratov-fedora.repo", timeout=30) as response:
        repo = response.read().decode()
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        repos = work / "repos"
        repos.mkdir()
        (repos / "personal.repo").write_text(repo.replace(config["site_url"], base))
        for target in config["targets"]:
            prefix = work / (target["releasever"] + "-" + target["arch"])
            prefix.mkdir()
            dnf = ("dnf", "--releasever=" + target["releasever"],
                   "--forcearch=" + target["arch"], "--repo=ivansaratov-fedora",
                   "--setopt=reposdir=" + str(repos), "--setopt=cachedir=" + str(prefix / "cache"),
                   "--setopt=system_cachedir=" + str(prefix / "cache"),
                   "--setopt=logdir=" + str(prefix / "logs"))
            expected = {
                f"{p['name']}-{p['version']}-{p['release']}.{p['arch']}"
                for p in state["packages"]
                if p["release"].endswith(".fc" + target["releasever"])
                and p["arch"] in (target["arch"], "noarch")
            }
            query = run(*dnf, "repoquery", "--available",
                        "--queryformat", "%{name}-%{version}-%{release}.%{arch}")
            actual = set(query.splitlines())
            if actual != expected:
                raise RuntimeError(f"DNF package set differs: {actual} != {expected}")
            print("DNF repoquery: " + ", ".join(sorted(actual)), flush=True)
            names = sorted({p["name"] for p in state["packages"]
                            if p["release"].endswith(".fc" + target["releasever"])
                            and p["arch"] in (target["arch"], "noarch")})
            destination = prefix / "downloads"
            destination.mkdir()
            run(*dnf, "download", "--destdir=" + str(destination), *names)
            files = list(destination.glob("*.rpm"))
            if len(files) != len(names):
                raise RuntimeError("DNF did not download every expected package")
            for rpm in files:
                name = run("rpm", "-qp", "--qf", "%{NAME}", str(rpm)).strip()
                policy = config["packages"][name]
                key = prefix / (name + ".asc")
                with urlopen(base + "/" + policy["key"], timeout=30) as response:
                    key.write_bytes(response.read())
                keyring = prefix / ("rpmdb-" + name)
                keyring.mkdir()
                run("rpmkeys", "--dbpath", str(keyring), "--define", "_keyring rpmdb",
                    "--import", str(key))
                run("rpmkeys", "--dbpath", str(keyring), "--define", "_keyring rpmdb",
                    "--define", "_pkgverify_level signature", "--checksig", str(rpm))
                print("DNF download and mandatory signature: " + rpm.name, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--site", type=Path)
    group.add_argument("--url")
    args = parser.parse_args()
    if args.url:
        check(args.url.rstrip("/"))
        return
    handler = partial(SimpleHTTPRequestHandler, directory=str(args.site))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        check(f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
