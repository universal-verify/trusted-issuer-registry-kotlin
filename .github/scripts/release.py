"""Verify GitHub releases and publish signed bundles through Central Portal."""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

GROUP = "com.universalverify"
ARTIFACT = "trusted-issuer-registry"
CENTRAL = "https://central.sonatype.com/api/v1/publisher"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
POM_NAMESPACE = {"m": "http://maven.apache.org/POM/4.0.0"}


class ReleaseError(Exception):
    def __init__(self, message, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def required_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ReleaseError(f"Missing required environment variable: {name}")
    return value


def request(method, url, headers, data=None):
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        raise ReleaseError(
            f"{urllib.parse.urlparse(url).hostname} returned HTTP {error.code}",
            retryable=error.code == 429 or error.code >= 500,
        ) from None
    except (urllib.error.URLError, TimeoutError) as error:
        raise ReleaseError("Network request failed", retryable=True) from error


def request_json(method, url, headers, data=None):
    try:
        return json.loads(request(method, url, headers, data))
    except (ValueError, UnicodeDecodeError) as error:
        raise ReleaseError("Server returned an invalid JSON response") from error


def release_version(event, pom):
    release = event.get("release") or {}
    if event.get("action") != "published" or release.get("draft", True):
        raise ReleaseError("Publication requires a published GitHub release")
    version = release.get("tag_name", "").removeprefix("v")
    if not VERSION.fullmatch(version) or version.upper().endswith("-SNAPSHOT"):
        raise ReleaseError("The release tag must be an SDK version, such as 0.1.0")
    document = ET.parse(pom).getroot()
    actual = {
        field: document.findtext(f"m:{field}", namespaces=POM_NAMESPACE)
        for field in ("groupId", "artifactId", "version")
    }
    if actual != {"groupId": GROUP, "artifactId": ARTIFACT, "version": version}:
        raise ReleaseError("The release tag does not match the generated SDK publication coordinates/version")
    return version


def wait_for_ci(repository, commit, token, timeout=1200, interval=15):
    query = urllib.parse.urlencode({"head_sha": commit, "per_page": 100})
    url = f"https://api.github.com/repos/{repository}/actions/workflows/ci.yml/runs?{query}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": ARTIFACT,
    }
    deadline = time.monotonic() + timeout
    while True:
        runs = request_json("GET", url, headers).get("workflow_runs", [])
        eligible = [
            run for run in runs
            if run.get("head_sha") == commit
            and run.get("event") in ("push", "workflow_dispatch")
        ]
        passed = next((run for run in eligible if run.get("conclusion") == "success"), None)
        if passed:
            print(f"SDK checks passed for {commit}: {passed['html_url']}", flush=True)
            return
        if eligible and all(run.get("status") == "completed" for run in eligible):
            raise ReleaseError("SDK checks did not pass for the released commit; fix or rerun CI before retrying publication")
        if time.monotonic() >= deadline:
            raise ReleaseError("Timed out waiting for successful SDK checks for the released commit")
        print("Waiting for SDK checks on the released commit...", flush=True)
        time.sleep(interval)


def verify_bundle(bundle, version):
    prefix = f"{GROUP.replace('.', '/')}/{ARTIFACT}/{version}/{ARTIFACT}-{version}"
    try:
        with zipfile.ZipFile(bundle) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ReleaseError("Publication bundle contains duplicate file paths")
            for suffix in (".jar", "-sources.jar", "-javadoc.jar", ".pom", ".module"):
                name = prefix + suffix
                for required in (name, name + ".asc", name + ".md5", name + ".sha1"):
                    if required not in names or not archive.read(required):
                        raise ReleaseError(f"Publication bundle is missing a required file: {required}")
                content = archive.read(name)
                for algorithm in ("md5", "sha1"):
                    actual = archive.read(name + "." + algorithm).decode().strip()
                    if hashlib.new(algorithm, content).hexdigest() != actual:
                        raise ReleaseError(f"Publication checksum does not match: {name}")
    except (zipfile.BadZipFile, OSError, UnicodeDecodeError) as error:
        raise ReleaseError("Cannot read a valid signed publication bundle") from error


def record_deployment(deployment, version):
    print(f"Central deployment ID: {deployment}", flush=True)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as target:
            target.write(f"deployment_id={deployment}\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as target:
            target.write(f"\nMaven Central deployment for {GROUP}:{ARTIFACT}:{version}: {deployment}\n")


def publish(bundle, version, username, password, timeout=1800, interval=15):
    verify_bundle(bundle, version)
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization": f"Bearer {token}", "User-Agent": ARTIFACT}
    boundary = "central-" + uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="bundle"; filename="{bundle.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + bundle.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    query = urllib.parse.urlencode({
        "publishingType": "AUTOMATIC",
        "name": f"{GROUP}:{ARTIFACT}:{version}",
    })
    try:
        uploaded = request(
            "POST", f"{CENTRAL}/upload?{query}",
            {**headers, "Content-Type": f"multipart/form-data; boundary={boundary}"},
            body,
        ).decode().strip()
    except (ReleaseError, UnicodeDecodeError) as error:
        # Do not repeat an upload whose response may have been lost.
        reason = str(error) if isinstance(error, ReleaseError) else "unreadable response"
        raise ReleaseError(f"Central upload failed ({reason}). Check Central Portal before retrying this release.") from error
    try:
        deployment = str(uuid.UUID(uploaded))
    except ValueError as error:
        raise ReleaseError("Central returned an invalid deployment ID. Check Central Portal before retrying.") from error
    record_deployment(deployment, version)
    deadline = time.monotonic() + timeout
    status_url = f"{CENTRAL}/status?" + urllib.parse.urlencode({"id": deployment})
    while True:
        try:
            status = request_json("POST", status_url, headers)
        except ReleaseError as error:
            if not error.retryable:
                raise
            status = {}
            print("Central status is temporarily unavailable; retrying the status check.", flush=True)
        state = status.get("deploymentState")
        if state:
            print(f"Central deployment state: {state}", flush=True)
        if state == "PUBLISHED":
            print(f"Published {GROUP}:{ARTIFACT}:{version}", flush=True)
            return
        if state == "FAILED":
            details = json.dumps(status.get("errors", {}), ensure_ascii=True)
            for secret in (username, password, token):
                if secret:
                    details = details.replace(secret, "[redacted]")
            raise ReleaseError(f"Central validation failed: {details}")
        if state and state not in ("PENDING", "VALIDATING", "VALIDATED", "PUBLISHING"):
            raise ReleaseError(f"Unexpected Central deployment state: {state}")
        if time.monotonic() >= deadline:
            raise ReleaseError(f"Timed out waiting for Central deployment {deployment}. Check its status in Central Portal before retrying.")
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "publish"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    event = json.loads(Path(required_env("GITHUB_EVENT_PATH")).read_text())
    version = release_version(event, root / "build/publications/maven/pom-default.xml")
    if args.operation == "verify":
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        if commit != required_env("GITHUB_SHA"):
            raise ReleaseError("The checked-out commit does not match the GitHub release commit")
        wait_for_ci(required_env("GITHUB_REPOSITORY"), commit, required_env("GITHUB_TOKEN"))
    else:
        publish(
            root / f"build/central/{ARTIFACT}-{version}-central.zip", version,
            required_env("CENTRAL_USERNAME"), required_env("CENTRAL_PASSWORD"),
        )


if __name__ == "__main__":
    try:
        main()
    except (ReleaseError, OSError, ET.ParseError, ValueError) as error:
        print(f"Release failed: {error}", file=sys.stderr)
        raise SystemExit(1)
