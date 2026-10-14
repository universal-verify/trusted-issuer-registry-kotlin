"""Offline regression checks for release gates and Central publication."""

import base64
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import patch

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bundle = self.root / "trusted-issuer-registry-0.1.0-central.zip"
        self.deployment = "19c5b87e-5570-4d2d-9448-662b8b2df442"
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        env = patch.dict("os.environ", {"GITHUB_OUTPUT": "", "GITHUB_STEP_SUMMARY": ""})
        env.start()
        self.addCleanup(env.stop)

    def make_pom(self, version="0.1.0", group=release.GROUP):
        path = self.root / "pom.xml"
        path.write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            f"<groupId>{group}</groupId><artifactId>{release.ARTIFACT}</artifactId>"
            f"<version>{version}</version></project>"
        )
        return path

    def event(self, tag="0.1.0", action="published", draft=False):
        return {"action": action, "release": {"tag_name": tag, "draft": draft}}

    def make_bundle(self, missing=None, corrupt=None):
        prefix = "com/universalverify/trusted-issuer-registry/0.1.0/trusted-issuer-registry-0.1.0"
        with zipfile.ZipFile(self.bundle, "w") as archive:
            for suffix in (".jar", "-sources.jar", "-javadoc.jar", ".pom", ".module"):
                content = ("fixture publication " + suffix).encode()
                files = {suffix: content, suffix + ".asc": b"fixture signature"}
                for algorithm in ("md5", "sha1"):
                    files[suffix + "." + algorithm] = hashlib.new(algorithm, content).hexdigest().encode()
                for name, data in files.items():
                    if name != missing:
                        archive.writestr(prefix + name, b"corrupt" if name == corrupt else data)

    def response(self, state, **fields):
        return json.dumps({"deploymentState": state, **fields}).encode()

    def publish(self, timeout=10):
        release.publish(self.bundle, "0.1.0", "fixture-user", "fixture-password", timeout=timeout, interval=0)

    def test_matching_tag_and_coordinates(self):
        for tag in ("0.1.0", "v0.1.0"):
            with self.subTest(tag=tag):
                self.assertEqual(release.release_version(self.event(tag), self.make_pom()), "0.1.0")

    def test_prerelease_version_matches_publication(self):
        self.assertEqual(
            release.release_version(self.event("0.2.0-rc.1"), self.make_pom("0.2.0-rc.1")),
            "0.2.0-rc.1",
        )

    def test_invalid_release_cannot_pass_version_gate(self):
        for event in (
            self.event("0.2.0"), self.event("../0.1.0"), self.event("0.1.0-SNAPSHOT"),
            self.event(action="created"), self.event(draft=True), {},
        ):
            with self.subTest(event=event), self.assertRaises(release.ReleaseError):
                release.release_version(event, self.make_pom())

    def test_wrong_namespace_is_rejected(self):
        with self.assertRaises(release.ReleaseError):
            release.release_version(self.event(), self.make_pom(group="other.namespace"))

    def test_matching_successful_ci_is_required(self):
        run = {"head_sha": "commit", "event": "push", "status": "completed",
               "conclusion": "success", "html_url": "https://github.com/example/run"}
        with patch.object(release, "request_json", return_value={"workflow_runs": [run]}) as request:
            release.wait_for_ci("owner/repo", "commit", "fixture-token", timeout=0)
        self.assertIn("/actions/workflows/ci.yml/runs?head_sha=commit", request.call_args.args[1])

    def test_other_commit_or_pull_request_success_does_not_satisfy_ci(self):
        for commit, event in (("other", "push"), ("commit", "pull_request")):
            run = {"head_sha": commit, "event": event, "conclusion": "success"}
            with self.subTest(commit=commit, event=event):
                with patch.object(release, "request_json", return_value={"workflow_runs": [run]}):
                    with self.assertRaisesRegex(release.ReleaseError, "Timed out"):
                        release.wait_for_ci("owner/repo", "commit", "token", timeout=0)

    def test_failed_ci_stops_release(self):
        run = {"head_sha": "commit", "event": "push", "status": "completed", "conclusion": "failure"}
        with patch.object(release, "request_json", return_value={"workflow_runs": [run]}):
            with self.assertRaisesRegex(release.ReleaseError, "did not pass"):
                release.wait_for_ci("owner/repo", "commit", "token", timeout=0)

    def test_in_progress_ci_waits_for_success(self):
        pending = {"head_sha": "commit", "event": "push", "status": "in_progress"}
        passed = {**pending, "status": "completed", "conclusion": "success", "html_url": "run-url"}
        with patch.object(release, "request_json", side_effect=[
            {"workflow_runs": [pending]}, {"workflow_runs": [passed]},
        ]), patch.object(release.time, "sleep") as sleep:
            release.wait_for_ci("owner/repo", "commit", "token")
        sleep.assert_called_once()

    def test_invalid_bundle_is_rejected_before_upload(self):
        for options in ({"missing": ".jar.asc"}, {"corrupt": ".pom.sha1"}):
            with self.subTest(options=options):
                self.make_bundle(**options)
                with patch.object(release, "request") as request:
                    with self.assertRaises(release.ReleaseError):
                        self.publish()
                    request.assert_not_called()

    def test_upload_is_multipart_and_waits_until_published(self):
        self.make_bundle()
        with patch.object(release, "request", side_effect=[
            self.deployment.encode(), self.response("VALIDATING"),
            self.response("PUBLISHING"), self.response("PUBLISHED"),
        ]) as request:
            self.publish()
        self.assertEqual(request.call_count, 4)
        method, url, headers, body = request.call_args_list[0].args
        self.assertEqual(method, "POST")
        self.assertIn("publishingType=AUTOMATIC", url)
        self.assertIn('name="bundle"', body.decode("latin1"))
        self.assertIn(self.bundle.read_bytes(), body)
        self.assertTrue(headers["Content-Type"].startswith("multipart/form-data; boundary="))
        self.assertEqual(headers["Authorization"], "Bearer " + base64.b64encode(b"fixture-user:fixture-password").decode())
        self.assertTrue(all(call.args[0] == "POST" for call in request.call_args_list[1:]))

    def test_validation_failure_is_reported_without_credentials(self):
        self.make_bundle()
        token = base64.b64encode(b"fixture-user:fixture-password").decode()
        with patch.object(release, "request", side_effect=[
            self.deployment.encode(),
            self.response("FAILED", errors={"signature": f"invalid fixture-password {token}"}),
        ]):
            with self.assertRaisesRegex(release.ReleaseError, "Central validation failed") as result:
                self.publish()
        self.assertIn("signature", str(result.exception))
        self.assertNotIn("fixture-password", str(result.exception))
        self.assertNotIn(token, str(result.exception))

    def test_lost_upload_response_is_not_retried(self):
        self.make_bundle()
        with patch.object(release, "request", side_effect=release.ReleaseError("interrupted", retryable=True)) as request:
            with self.assertRaisesRegex(release.ReleaseError, "Check Central Portal"):
                self.publish()
        self.assertEqual(request.call_count, 1)

    def test_upload_http_failure_reports_status_without_retry(self):
        self.make_bundle()
        with patch.object(release, "request", side_effect=release.ReleaseError("Central returned HTTP 401")) as request:
            with self.assertRaisesRegex(release.ReleaseError, "HTTP 401"):
                self.publish()
        self.assertEqual(request.call_count, 1)

    def test_transient_status_failure_does_not_repeat_upload(self):
        self.make_bundle()
        with patch.object(release, "request", side_effect=[
            self.deployment.encode(), release.ReleaseError("503", retryable=True),
            self.response("PUBLISHED"),
        ]) as request:
            self.publish()
        self.assertEqual(sum("/upload?" in call.args[1] for call in request.call_args_list), 1)

    def test_publication_timeout_preserves_deployment_id(self):
        self.make_bundle()
        with patch.object(release, "request", side_effect=[
            self.deployment.encode(), self.response("PUBLISHING"),
        ]):
            with self.assertRaisesRegex(release.ReleaseError, self.deployment):
                self.publish(timeout=0)

    def test_bad_deployment_id_is_rejected_before_polling(self):
        self.make_bundle()
        with patch.object(release, "request", return_value=b"invalid-id") as request:
            with self.assertRaisesRegex(release.ReleaseError, "invalid deployment ID"):
                self.publish()
        self.assertEqual(request.call_count, 1)

    def test_http_errors_do_not_expose_response_body(self):
        error = urllib.error.HTTPError(
            "https://central.sonatype.com/api/v1/publisher/upload", 401, "Unauthorized", {},
            io.BytesIO(b"private response information"),
        )
        with patch.object(release.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(release.ReleaseError, "HTTP 401") as result:
                release.request("POST", error.url, {"Authorization": "Bearer secret"})
        self.assertNotIn("secret", str(result.exception))
        self.assertNotIn("private response", str(result.exception))


if __name__ == "__main__":
    unittest.main()
