"""Measure the minified consumer APK with and without the published SDK."""
from pathlib import Path
import json
import os
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
APK = ROOT / "verification/android/build/outputs/apk/release/android-consumer-release.apk"


def build(baseline=False):
    command = [str(ROOT / "gradlew"), "-p", "verification/android", "assembleRelease", "--rerun-tasks"]
    if baseline:
        command.append("-PwithoutSdk")
    subprocess.run(command, cwd=ROOT, check=True, env=os.environ.copy())
    with zipfile.ZipFile(APK) as archive:
        dex = sum(info.file_size for info in archive.infolist() if info.filename.endswith(".dex"))
    return {"apk_bytes": APK.stat().st_size, "dex_bytes": dex}


with_sdk = build()
baseline = build(True)
result = {
    "configuration": "minified release, API 26 minimum, API 37.2 compilation",
    "with_sdk": with_sdk,
    "baseline": baseline,
    "delta": {key: with_sdk[key] - baseline[key] for key in baseline},
}
destination = ROOT / "verification/android/build/dependency-size.json"
destination.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
# Leave the runnable SDK consumer APK as the final build output.
build()
