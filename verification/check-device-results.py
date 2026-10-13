"""Fail if instrumentation silently discovers no tests on any connected device."""
from pathlib import Path
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parent / "android/build/outputs/androidTest-results"
reports = list(root.rglob("TEST-*.xml"))
if not reports:
    raise SystemExit("No Android device test reports found")
for report in reports:
    tree = ET.parse(report).getroot()
    tests = int(tree.attrib.get("tests", "0"))
    failures = int(tree.attrib.get("failures", "0")) + int(tree.attrib.get("errors", "0"))
    if tests < 3 or failures:
        raise SystemExit(f"{report.name}: expected at least 3 passing tests, found {tests} tests and {failures} failures")
    print(f"{report.name}: {tests} tests passed")
