from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
README = ROOT / "README.md"
GIT_VALIDATOR = ROOT / "scripts" / "retrospective_history_git_v2.py"
REQUIREMENTS = ROOT / "requirements-v2.txt"
MAINTAINER_FINGERPRINT = "EFBBC913F49A5F6E0AF0D248F70246143DC28F32"
GITHUB_FINGERPRINT = "968479A1AFF927E37D1A566BB5690EEEBB952194"
PUBLISHER_FINGERPRINT = "40FA5D05AC7A3D5C180B037FF6DCF7A06FFC9C52"
COMMIT_TIMESTAMP = 1_800_100_020

SPEC = importlib.util.spec_from_file_location(
    "retrospective_history_git_v2_ci_contract",
    GIT_VALIDATOR,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ADMIN_PATHS = tuple(path.decode("ascii") for path in sorted(MODULE.V2_ADMIN_PATHS))
TRUSTED_PATHS = (
    ".github/workflows/ci.yml",
    "requirements-v2.in",
    "requirements-v2.txt",
    "retrospective-history-v2-admin.asc",
    "retrospective-history-v2-publisher.asc",
    "schemas/retained-manifest-v2.schema.json",
    "schemas/session-retrospective-v2.schema.json",
    "scripts/retrospective_history_attestation_v2.py",
    "scripts/retrospective_history_credentials_v2.py",
    "scripts/retrospective_history_git_v2.py",
    "scripts/retrospective_history_merge_v2.py",
    "scripts/retrospective_history_privacy_v2.py",
    "scripts/retrospective_history_templates_v2.py",
    "scripts/retrospective_history_v2.py",
    "scripts/validate_retained_history.py",
)


def git(
    root: Path,
    *arguments: str,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    if check and result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def workflow_step(name: str) -> str:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    marker = f"      - name: {name}"
    start = lines.index(marker)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith(
            ("      - name: ", "      - uses: ", "  post-validation-tests:")
        ):
            end = index
            break
    return "\n".join(lines[start:end])


def workflow_run_script(name: str) -> str:
    lines = workflow_step(name).splitlines()
    run_index = lines.index("        run: |")
    return textwrap.dedent("\n".join(lines[run_index + 1 :]))


def run_script(
    script: str,
    root: Path,
    environment: dict[str, str],
    *,
    timeout: float = 120,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.pop("GH_TOKEN", None)
    merged.pop("GITHUB_TOKEN", None)
    merged.update(environment)
    return subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-c", script],
        cwd=root,
        check=False,
        capture_output=True,
        env=merged,
        text=True,
        timeout=timeout,
    )


def gpg(home: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            shutil.which("gpg") or "gpg",
            "--batch",
            "--no-options",
            "--homedir",
            str(home),
            *arguments,
        ],
        check=False,
        capture_output=True,
        timeout=60,
    )


def generate_signing_key(home: Path, uid: str) -> tuple[str, bytes]:
    home.mkdir(mode=0o700)
    generated = gpg(
        home,
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--quick-generate-key",
        uid,
        "rsa2048",
        "sign",
        "0",
    )
    if generated.returncode != 0:
        raise RuntimeError(generated.stderr.decode("utf-8", errors="replace"))
    listing = gpg(home, "--with-colons", "--list-secret-keys")
    if listing.returncode != 0:
        raise RuntimeError(listing.stderr.decode("utf-8", errors="replace"))
    fingerprint = next(
        (
            line.split(b":")[9].decode("ascii")
            for line in listing.stdout.splitlines()
            if line.startswith(b"fpr:")
        ),
        None,
    )
    if fingerprint is None:
        raise RuntimeError("ephemeral signing key has no fingerprint")
    exported = gpg(home, "--armor", "--export", fingerprint)
    if exported.returncode != 0:
        raise RuntimeError(exported.stderr.decode("utf-8", errors="replace"))
    return fingerprint, exported.stdout


def parse_github_environment(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    )


class RetrospectiveHistoryV2CITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._key_root = tempfile.TemporaryDirectory()
        cls.key_root = Path(cls._key_root.name)
        cls.gpg_error: str | None = None
        try:
            cls.maintainer_home = cls.key_root / "maintainer"
            cls.maintainer_fingerprint, cls.maintainer_public_key = (
                generate_signing_key(
                    cls.maintainer_home,
                    "History Maintainer Test <history-maintainer@example.invalid>",
                )
            )
            cls.github_home = cls.key_root / "github"
            cls.github_fingerprint, cls.github_public_key = generate_signing_key(
                cls.github_home,
                "History GitHub Test <history-github@example.invalid>",
            )
            cls.publisher_home = cls.key_root / "publisher"
            cls.publisher_fingerprint, cls.publisher_public_key = generate_signing_key(
                cls.publisher_home,
                "History Publisher Test <history-publisher@example.invalid>",
            )
        except RuntimeError as exc:
            cls.gpg_error = str(exc)

    @classmethod
    def tearDownClass(cls) -> None:
        if shutil.which("gpgconf"):
            for name in ("maintainer_home", "github_home", "publisher_home"):
                home = getattr(cls, name, None)
                if home is not None:
                    subprocess.run(
                        ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                        check=False,
                        capture_output=True,
                        timeout=30,
                    )
        cls._key_root.cleanup()

    def require_gpg(self) -> None:
        if self.gpg_error is not None:
            self.skipTest(f"real GPG is unavailable: {self.gpg_error}")

    def write_trusted_admin_tree(self, root: Path) -> None:
        for relative in ADMIN_PATHS:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == "retrospective-history-v2-admin.asc":
                target.write_bytes(self.maintainer_public_key + self.github_public_key)
            elif relative == "retrospective-history-v2-publisher.asc":
                target.write_bytes(self.publisher_public_key)
            elif relative == "scripts/retrospective_history_git_v2.py":
                source = GIT_VALIDATOR.read_text(encoding="utf-8")
                source = (
                    source.replace(
                        MAINTAINER_FINGERPRINT,
                        self.maintainer_fingerprint,
                    )
                    .replace(
                        GITHUB_FINGERPRINT,
                        self.github_fingerprint,
                    )
                    .replace(
                        PUBLISHER_FINGERPRINT,
                        self.publisher_fingerprint,
                    )
                )
                target.write_text(source, encoding="utf-8")
            else:
                shutil.copy2(ROOT / relative, target)

    def make_signed_admin_range(
        self,
        temporary: Path,
        *,
        tamper_validator: bool = False,
        payload: bytes = b"Reviewed policy update.\n",
        trust_root_upgrade: bool = False,
        unauthorized_path: bool = False,
    ) -> tuple[Path, Path, str, str]:
        self.require_gpg()
        source = temporary / "source"
        source.mkdir()
        git(source, "init", "--quiet")
        git(source, "config", "user.name", "Fixture")
        git(source, "config", "user.email", "fixture@example.invalid")
        self.write_trusted_admin_tree(source)
        git(source, "add", "--all")
        git(source, "commit", "--quiet", "--no-gpg-sign", "-m", "Trusted base")
        base = git(source, "rev-parse", "HEAD^{commit}")

        if tamper_validator:
            (source / "scripts" / "retrospective_history_git_v2.py").write_text(
                "def validate_append_only_range(*_args):\n    return []\n",
                encoding="utf-8",
            )
        target = source / ("notes.txt" if unauthorized_path else "README.md")
        target.write_bytes(payload)
        git(source, "add", "--all")
        git(source, "config", "gpg.program", shutil.which("gpg") or "gpg")
        environment = os.environ.copy()
        environment.update(
            {
                "GNUPGHOME": str(self.maintainer_home),
                "GIT_AUTHOR_NAME": "Joey Teng",
                "GIT_AUTHOR_EMAIL": "joey.teng.dev@gmail.com",
                "GIT_AUTHOR_DATE": f"@{COMMIT_TIMESTAMP} +0000",
                "GIT_COMMITTER_NAME": "Joey Teng",
                "GIT_COMMITTER_EMAIL": "joey.teng.dev@gmail.com",
                "GIT_COMMITTER_DATE": f"@{COMMIT_TIMESTAMP} +0000",
            }
        )
        git(
            source,
            "commit",
            "--quiet",
            f"-S{self.maintainer_fingerprint}",
            "-m",
            (
                "Upgrade session retrospective history v2 trust root"
                if trust_root_upgrade
                else "Administer session retrospective history v2: update policy"
            ),
            env=environment,
        )
        head = git(source, "rev-parse", "HEAD^{commit}")

        trusted = temporary / "trusted-base"
        untrusted = temporary / "untrusted-head"
        git(temporary, "clone", "--quiet", "--no-hardlinks", str(source), str(trusted))
        git(trusted, "checkout", "--quiet", "--detach", base)
        git(
            temporary, "clone", "--quiet", "--no-hardlinks", str(source), str(untrusted)
        )
        git(untrusted, "checkout", "--quiet", "--detach", head)
        return trusted, untrusted, base, head

    def imported_fingerprint_script(self) -> str:
        script = workflow_run_script("Import trusted signing keys")
        for production, fixture in (
            (MAINTAINER_FINGERPRINT, self.maintainer_fingerprint),
            (GITHUB_FINGERPRINT, self.github_fingerprint),
            (PUBLISHER_FINGERPRINT, self.publisher_fingerprint),
        ):
            if production not in script:
                raise AssertionError("production fingerprint fixture is unavailable")
            script = script.replace(production, fixture, 1)
        return script.replace(">/dev/null 2>&1", "")

    def run_production_trust_chain(
        self,
        temporary: Path,
        trusted: Path,
        untrusted: Path,
        base: str,
        head: str,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        environment_file = temporary / "github-environment"
        common = {
            "BASE_OID": base,
            "BASE_REF": "master",
            "BASE_REPOSITORY": "Joey-Tools/history-fixture",
            "DEFAULT_BRANCH": "master",
            "EVENT_NAME": "pull_request_target",
            "EVENT_REF": "refs/pull/1/merge",
            "EVENT_REPOSITORY": "Joey-Tools/history-fixture",
            "GITHUB_ENV": str(environment_file),
            "HEAD_OID": head,
            "MERGE_PLAN_PATH": str(temporary / "merge-plan.json"),
            "PUSH_FORCED": "false",
            "RUNNER_TEMP": str(temporary),
            "TRUSTED_ROOT": str(trusted),
            "UNTRUSTED_ROOT": str(untrusted),
            "WORKFLOW_SOURCE_OID": base,
        }
        preflight = run_script(
            workflow_run_script("Verify exact trusted and untrusted checkouts"),
            temporary,
            common,
        )
        self.assertEqual(preflight.returncode, 0, preflight.stdout + preflight.stderr)
        imported = run_script(
            self.imported_fingerprint_script(),
            temporary,
            common,
        )
        self.assertEqual(imported.returncode, 0, imported.stdout + imported.stderr)
        propagated = parse_github_environment(environment_file)
        validation = run_script(
            workflow_run_script("Build immutable candidate merge plan"),
            temporary,
            {**common, **propagated, "TRUSTED_PYTHON": sys.executable},
        )
        return validation, Path(propagated["TRUSTED_GNUPGHOME"])

    def run_default_branch_trust_chain(
        self,
        temporary: Path,
        trusted: Path,
        untrusted: Path,
        base: str,
        head: str,
        *,
        forced: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment_file = temporary / "push-github-environment"
        common = {
            "BASE_OID": base,
            "BASE_REF": "",
            "BASE_REPOSITORY": "",
            "DEFAULT_BRANCH": "master",
            "EVENT_FORCED": "true" if forced else "false",
            "EVENT_NAME": "push",
            "EVENT_REF": "refs/heads/master",
            "EVENT_REPOSITORY": "Joey-Tools/history-fixture",
            "GITHUB_ENV": str(environment_file),
            "HEAD_OID": head,
            "PUSH_FORCED": "true" if forced else "false",
            "RUNNER_TEMP": str(temporary),
            "TRUSTED_ROOT": str(trusted),
            "UNTRUSTED_ROOT": str(untrusted),
            "WORKFLOW_SOURCE_OID": head,
        }
        preflight = run_script(
            workflow_run_script("Verify exact trusted and untrusted checkouts"),
            temporary,
            common,
        )
        self.assertEqual(preflight.returncode, 0, preflight.stdout + preflight.stderr)
        imported = run_script(
            self.imported_fingerprint_script(),
            temporary,
            common,
        )
        self.assertEqual(imported.returncode, 0, imported.stdout + imported.stderr)
        propagated = parse_github_environment(environment_file)
        return run_script(
            workflow_run_script("Monitor default branch squash"),
            temporary,
            {**common, **propagated, "TRUSTED_PYTHON": sys.executable},
        )

    def test_workflow_distinguishes_pr_trust_from_after_controlled_push(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^  pull_request_target:$")
        self.assertIn("branches: [master]", workflow)
        self.assertIn("BASE_REF", workflow)
        self.assertIn("DEFAULT_BRANCH", workflow)
        self.assertNotRegex(workflow, r"(?m)^  pull_request:$")
        self.assertRegex(workflow, r"(?m)^  push:$")
        self.assertIn("trusted-validation:", workflow)
        self.assertNotIn("post-validation-tests:", workflow)
        self.assertNotIn("pull_request.head.repo.full_name", workflow)
        self.assertIn("steps.resolve-candidate.outputs.head_oid", workflow)
        self.assertIn("github.event.before", workflow)
        self.assertIn("github.event.after", workflow)
        self.assertIn("Monitor default branch squash", workflow)
        self.assertIn("github.workflow_sha", workflow)
        self.assertIn(
            "candidate-controlled post-merge workflow cannot authorize a trust-root upgrade",
            GIT_VALIDATOR.read_text(encoding="utf-8"),
        )
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-checks: write", workflow)
        self.assertIn("permission-administration: read", workflow)
        self.assertNotIn("id-token: write", workflow)

    def test_documentation_preserves_external_deployment_contract(self) -> None:
        readme = README.read_text(encoding="utf-8")
        normalized_readme = re.sub(r"\s+", " ", readme)
        for requirement in (
            "publisher_attestation",
            "do not prove publisher identity",
            "pull_request_target",
            "persist-credentials: false",
            "never imported, sourced, or executed",
            "dedicated GitHub App",
            "secret-key packets",
            "full base-plus-head history",
            "immutable merge plan",
            "push workflow definition is loaded from event `after`",
            "trust-root upgrade",
            "strict required status checks",
            "App-only",
            "squash subject",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, normalized_readme)

    def test_actions_are_commit_pinned(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"(?m)^\s+uses: ([^\s#]+)", workflow)
        self.assertGreaterEqual(len(uses), 4)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_embedded_bash_steps_parse(self) -> None:
        for name in (
            "Verify exact trusted and untrusted checkouts",
            "Install trusted validation dependencies",
            "Import trusted signing keys",
            "Build immutable candidate merge plan",
            "Monitor default branch squash",
            "Resolve immutable candidate",
            "Execute trusted App squash transaction",
        ):
            with self.subTest(name=name):
                result = subprocess.run(
                    ["bash", "-n"],
                    input=workflow_run_script(name),
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    result.stdout + result.stderr,
                )

    def test_every_checkout_disables_persisted_credentials(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        checkout_steps = re.findall(
            r"(?ms)^      - name: Checkout .*?(?=^      - name: |^  [a-z])",
            workflow,
        )
        self.assertEqual(len(checkout_steps), 2)
        for step in checkout_steps:
            with self.subTest(step=step.splitlines()[0]):
                self.assertIn("persist-credentials: false", step)

    def test_trusted_job_treats_head_as_data_until_role_validation(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Checkout candidate head as data", workflow)
        self.assertIn("Build immutable candidate merge plan", workflow)
        self.assertIn("build_pull_request_candidate_plan", workflow)
        self.assertIn("sys.path.insert(0, str(trusted_root))", workflow)
        self.assertNotIn("untrusted-head/scripts/", workflow)
        self.assertNotIn("Run tests", workflow)
        self.assertNotIn("working-directory:", workflow)
        self.assertNotIn("authenticated-head", workflow)

        ordered_steps = (
            "Checkout trusted base",
            "Set up trusted Python",
            "Create trusted merge token",
            "Resolve immutable candidate",
            "Checkout candidate head as data",
            "Verify exact trusted and untrusted checkouts",
            "Install trusted validation dependencies",
            "Import trusted signing keys",
            "Build immutable candidate merge plan",
            "Monitor default branch squash",
            "Execute trusted App squash transaction",
        )
        offsets = [workflow.index(f"- name: {name}") for name in ordered_steps]
        self.assertEqual(offsets, sorted(offsets))

    def test_oid_and_trust_root_preflight_is_case_exact(self) -> None:
        script = workflow_run_script("Verify exact trusted and untrusted checkouts")
        self.assertIn('case "$1" in', script)
        self.assertIn("*[!0-9a-f]*", script)
        self.assertIn('":(literal)$relative"', script)
        self.assertIn('[ "$tree_path" != "$relative" ]', script)
        for relative in TRUSTED_PATHS:
            self.assertIn(relative, script)

    def test_safe_python_and_hash_enforcement_are_structural(self) -> None:
        validation = workflow_run_script("Build immutable candidate merge plan")
        installation = workflow_run_script("Install trusted validation dependencies")
        self.assertIn(
            "env -u GH_TOKEN -u GITHUB_TOKEN -u PYTHONHOME -u PYTHONPATH", validation
        )
        self.assertIn('"$TRUSTED_PYTHON" -I -', validation)
        self.assertIn('cd "$TRUSTED_ROOT"', installation)
        self.assertIn("python -I -m venv", installation)
        self.assertIn('"$TRUSTED_VENV/bin/python" -I -m pip install', installation)
        self.assertIn("--require-hashes", installation)
        self.assertIn("--only-binary=:all:", installation)
        self.assertNotRegex(
            WORKFLOW.read_text(encoding="utf-8"), r"(?<!-I )python -m pip"
        )

    def test_malicious_local_pip_module_is_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            trusted = temporary / "trusted"
            untrusted = temporary / "untrusted"
            trusted.mkdir()
            (untrusted / "pip").mkdir(parents=True)
            marker = temporary / "malicious-pip-executed"
            (untrusted / "pip" / "__main__.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            (trusted / "requirements-v2.txt").write_text("", encoding="utf-8")
            result = run_script(
                workflow_run_script("Install trusted validation dependencies"),
                untrusted,
                {
                    "GITHUB_ENV": str(temporary / "environment"),
                    "RUNNER_TEMP": str(temporary),
                    "TRUSTED_ROOT": str(trusted),
                    "UNTRUSTED_ROOT": str(untrusted),
                },
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists())

    def test_requirement_lock_is_complete_and_hashed(self) -> None:
        lock = REQUIREMENTS.read_text(encoding="utf-8")
        self.assertIn("--universal --generate-hashes --no-sources", lock)
        headers = list(re.finditer(r"(?m)^([a-z0-9-]+)==([^ \\;]+).*$", lock))
        self.assertEqual(
            {match.group(1) for match in headers},
            {
                "attrs",
                "jsonschema",
                "jsonschema-specifications",
                "referencing",
                "rpds-py",
                "typing-extensions",
            },
        )
        for index, header in enumerate(headers):
            end = headers[index + 1].start() if index + 1 < len(headers) else len(lock)
            block = lock[header.start() : end]
            self.assertRegex(block, r"--hash=sha256:[0-9a-f]{64}")
        rpds_start = next(
            match.start() for match in headers if match.group(1) == "rpds-py"
        )
        typing_start = next(
            match.start() for match in headers if match.group(1) == "typing-extensions"
        )
        self.assertGreaterEqual(
            lock[rpds_start:typing_start].count("--hash=sha256:"),
            100,
        )

    def test_pip_hash_enforcement_rejects_unhashed_local_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            wheel = temporary / "fixture_pkg-1.0-py3-none-any.whl"
            dist_info = "fixture_pkg-1.0.dist-info"
            with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("fixture_pkg/__init__.py", "VALUE = 1\n")
                archive.writestr(
                    f"{dist_info}/METADATA",
                    "Metadata-Version: 2.1\nName: fixture-pkg\nVersion: 1.0\n\n",
                )
                archive.writestr(
                    f"{dist_info}/WHEEL",
                    "Wheel-Version: 1.0\n"
                    "Generator: retained-history-test\n"
                    "Root-Is-Purelib: true\n"
                    "Tag: py3-none-any\n\n",
                )
                archive.writestr(
                    f"{dist_info}/RECORD",
                    "fixture_pkg/__init__.py,,\n"
                    f"{dist_info}/METADATA,,\n"
                    f"{dist_info}/WHEEL,,\n"
                    f"{dist_info}/RECORD,,\n",
                )

            requirements = temporary / "requirements.txt"
            requirements.write_text(
                f"fixture-pkg @ {wheel.as_uri()}\n",
                encoding="utf-8",
            )

            def install(target: Path) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-m",
                        "pip",
                        "install",
                        "--disable-pip-version-check",
                        "--no-input",
                        "--no-index",
                        "--no-deps",
                        "--require-hashes",
                        "--target",
                        str(target),
                        "--requirement",
                        str(requirements),
                    ],
                    cwd=temporary,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

            rejected = install(temporary / "rejected")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "Hashes are required",
                rejected.stdout + rejected.stderr,
            )

            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            requirements.write_text(
                f"fixture-pkg @ {wheel.as_uri()} --hash=sha256:{digest}\n",
                encoding="utf-8",
            )
            accepted = install(temporary / "accepted")

        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_app_transaction_replaces_mutable_metadata_check_lifecycle(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        resolved = workflow_run_script("Resolve immutable candidate")
        transaction = workflow_run_script("Execute trusted App squash transaction")
        self.assertIn("actions/create-github-app-token@", workflow)
        self.assertIn("RETROSPECTIVE_HISTORY_MERGE_APP_ID", workflow)
        self.assertIn("RETROSPECTIVE_HISTORY_MERGE_APP_PRIVATE_KEY", workflow)
        self.assertIn("permission-checks: write", workflow)
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-administration: read", workflow)
        self.assertIn("permission-pull-requests: read", workflow)
        self.assertIn("retrospective_history_merge_v2", resolved)
        self.assertIn("transact", transaction)
        self.assertIn("--app-id", transaction)
        self.assertIn("--app-slug", transaction)
        self.assertNotIn("title", workflow)
        self.assertNotIn("draft", workflow)
        self.assertNotIn("status=in_progress", workflow)
        self.assertNotIn("post-completion-pull-request", workflow)
        self.assertNotIn("github.token", workflow)

    def test_key_import_proves_public_only_material_before_and_after_import(
        self,
    ) -> None:
        script = workflow_run_script("Import trusted signing keys")
        self.assertIn("--import-options show-only --dry-run --import", script)
        self.assertIn('$1 == "sec" || $1 == "ssb"', script)
        self.assertIn("--list-secret-keys", script)
        self.assertIn('[ -n "$SECRET_RECORDS" ]', script)

    def test_empty_gnupg_import_and_production_validation_chain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            trusted, untrusted, base, head = self.make_signed_admin_range(temporary)
            validation, imported_home = self.run_production_trust_chain(
                temporary,
                trusted,
                untrusted,
                base,
                head,
            )
            listing = gpg(imported_home, "--with-colons", "--list-keys")
            secret_listing = gpg(
                imported_home,
                "--with-colons",
                "--list-secret-keys",
            )

        self.assertEqual(
            validation.returncode, 0, validation.stdout + validation.stderr
        )
        self.assertEqual(listing.returncode, 0, listing.stderr.decode(errors="replace"))
        self.assertEqual(
            secret_listing.returncode,
            0,
            secret_listing.stderr.decode(errors="replace"),
        )
        self.assertEqual(secret_listing.stdout, b"")
        self.assertEqual(imported_home.name, "rh2-gpg")

    def test_default_branch_monitor_validates_unchanged_trust_root_update(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            trusted, untrusted, base, head = self.make_signed_admin_range(temporary)
            accepted = self.run_default_branch_trust_chain(
                temporary,
                trusted,
                untrusted,
                base,
                head,
            )
            rejected = self.run_default_branch_trust_chain(
                temporary,
                trusted,
                untrusted,
                base,
                head,
                forced=True,
            )

        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("force-push event is not append-only", rejected.stdout)

    def test_real_signed_trust_root_upgrade_uses_pr_protocol_not_push_monitor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            trusted, untrusted, base, head = self.make_signed_admin_range(
                temporary,
                tamper_validator=True,
                trust_root_upgrade=True,
            )
            validation, _imported_home = self.run_production_trust_chain(
                temporary,
                trusted,
                untrusted,
                base,
                head,
            )
            monitor = self.run_default_branch_trust_chain(
                temporary,
                trusted,
                untrusted,
                base,
                head,
            )

        self.assertEqual(
            validation.returncode, 0, validation.stdout + validation.stderr
        )
        self.assertNotEqual(monitor.returncode, 0)
        self.assertIn(
            "candidate-controlled post-merge workflow cannot authorize a trust-root upgrade",
            monitor.stdout,
        )

    def test_binary_secret_key_packet_is_rejected_before_import(self) -> None:
        self.require_gpg()
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            trusted, _untrusted, _base, _head = self.make_signed_admin_range(temporary)
            public_binary = gpg(
                self.publisher_home,
                "--export",
                self.publisher_fingerprint,
            )
            self.assertEqual(
                public_binary.returncode,
                0,
                public_binary.stderr.decode(errors="replace"),
            )
            synthetic_secret_packet = b"\xc5\x01\x04"
            (trusted / "retrospective-history-v2-publisher.asc").write_bytes(
                public_binary.stdout + synthetic_secret_packet
            )
            result = run_script(
                self.imported_fingerprint_script(),
                temporary,
                {
                    "GITHUB_ENV": str(temporary / "github-environment"),
                    "RUNNER_TEMP": str(temporary),
                    "TRUSTED_ROOT": str(trusted),
                },
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "not a valid public-key export",
            result.stdout + result.stderr,
        )

    def test_binary_secret_key_packet_is_rejected_in_candidate_admin_change(
        self,
    ) -> None:
        self.require_gpg()
        exported = gpg(
            self.maintainer_home,
            "--export-secret-keys",
            self.maintainer_fingerprint,
        )
        self.assertEqual(
            exported.returncode,
            0,
            exported.stderr.decode("utf-8", errors="replace"),
        )
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            trusted, untrusted, base, head = self.make_signed_admin_range(
                temporary,
                payload=exported.stdout,
            )
            validation, _imported_home = self.run_production_trust_chain(
                temporary,
                trusted,
                untrusted,
                base,
                head,
            )

        self.assertNotEqual(validation.returncode, 0)
        self.assertIn(
            "admin infrastructure contains a high-confidence secret",
            validation.stdout,
        )

    def test_tampered_head_validator_cannot_bypass_paths_or_secrets(self) -> None:
        self.require_gpg()
        cases = (
            (
                True,
                b"Reviewed policy update.\n",
                "unexpected retained artifact location",
            ),
            (
                False,
                b"Authorization: " + b"Bearer " + b"0123456789abcdef\n",
                "admin infrastructure contains a high-confidence secret",
            ),
        )
        for unauthorized_path, payload, expected in cases:
            with (
                self.subTest(unauthorized_path=unauthorized_path),
                tempfile.TemporaryDirectory() as raw,
            ):
                temporary = Path(raw)
                trusted, untrusted, base, head = self.make_signed_admin_range(
                    temporary,
                    tamper_validator=True,
                    payload=payload,
                    unauthorized_path=unauthorized_path,
                )
                validation, _imported_home = self.run_production_trust_chain(
                    temporary,
                    trusted,
                    untrusted,
                    base,
                    head,
                )

                self.assertNotEqual(validation.returncode, 0)
                self.assertIn(expected, validation.stdout)


if __name__ == "__main__":
    unittest.main()
