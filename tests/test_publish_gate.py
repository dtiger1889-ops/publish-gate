"""End-to-end tests: each one builds a throwaway repo and a bare 'remote' in a temp folder."""
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import publish_gate as pg  # noqa: E402

GOOD_EMAIL = "1+tester@users.noreply.github.com"


def sh(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout.strip()


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.remote = base / "remote.git"
        subprocess.run(["git", "init", "--bare", "--quiet", "-b", "main", str(self.remote)], check=True)
        self.repo = base / "work"
        self.repo.mkdir()
        sh(self.repo, "init", "--quiet", "-b", "main")
        sh(self.repo, "config", "user.email", GOOD_EMAIL)
        sh(self.repo, "config", "user.name", "tester")
        sh(self.repo, "remote", "add", "origin", str(self.remote))
        self.deny = base / "denylist.txt"
        self.deny.write_text("# personal tokens\nJane Q Realname\n", encoding="utf-8")
        self.write("README.md", "A tool.\n")
        self.write("LICENSE", "MIT\n")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, body):
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def run_gate(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = pg.main([*args, "--repo", str(self.repo)] +
                           (["--denylist", str(self.deny)] if args[0] in ("check", "publish", "monitor", "certify") else []))
        return code, out.getvalue()

    def first_publish(self):
        args = ("publish", "--paths", ".", "-m", "first", "--first-publish")
        self.assertEqual(self.run_gate(*args)[0], pg.EXIT_REVIEW)
        code, out = self.run_gate(*args, "--reviewed")
        self.assertEqual(code, pg.EXIT_CLEAN, out)
        return out

    def test_first_publish_stops_for_review_then_pins(self):
        code, out = self.run_gate("publish", "--paths", ".", "-m", "first", "--first-publish")
        self.assertEqual(code, pg.EXIT_REVIEW)
        self.assertIn("read EVERY file", out)
        self.assertEqual(sh(self.repo, "diff", "--cached", "--name-only"), "")  # index restored
        out = self.first_publish()
        head = sh(self.repo, "rev-parse", "HEAD")
        self.assertIn(f"PINNED {head}", out)
        self.assertEqual(pg.load_state(self.repo)["certified"], head)

    def test_second_publish_reviews_only_the_change(self):
        self.first_publish()
        self.write("README.md", "A tool. Now better.\n")
        code, out = self.run_gate("publish", "--paths", "README.md", "-m", "docs")
        self.assertEqual(code, pg.EXIT_REVIEW)
        self.assertIn("+A tool. Now better.", out)
        self.assertNotIn("LICENSE", out)

    def test_scope_lock_refuses_paths_outside(self):
        self.first_publish()
        self.write("README.md", "changed\n")
        self.write("secret-notes.md", "mine\n")
        code, out = self.run_gate("publish", "--paths", "README.md", "-m", "x")
        self.assertEqual(code, pg.EXIT_REFUSED)
        self.assertIn("secret-notes.md", out)

    def test_denylist_hit_in_content_blocks_and_restores_index(self):
        self.write("about.md", "Made by jane q realname.\n")
        code, out = self.run_gate("publish", "--paths", ".", "-m", "x", "--first-publish", "--reviewed")
        self.assertEqual(code, pg.EXIT_FINDINGS)
        self.assertIn("denylist", out)
        self.assertEqual(sh(self.repo, "ls-files"), "")
        self.assertEqual(sh(self.repo, "ls-remote", "origin"), "")

    def test_denylist_hit_only_in_history_blocks(self):
        self.write("about.md", "Made by Jane Q Realname.\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "oops")
        self.write("about.md", "Made by the author.\n")
        code, out = self.run_gate("publish", "--paths", ".", "-m", "scrub", "--first-publish", "--reviewed")
        self.assertEqual(code, pg.EXIT_FINDINGS)
        self.assertIn("history", out)

    def test_key_deleted_but_still_in_history_blocks(self):
        token = "ghp_" + "Zq8vR2mN5tL0xW7cJ4bH1kP9sD3fG6yA2eU8"
        self.write("config.py", f'TOKEN = "{token}"\n')
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "add config")
        (self.repo / "config.py").unlink()
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "remove config")
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_FINDINGS, out)
        self.assertIn("secret", out)
        self.assertIn("history", out)

    def test_personal_commit_email_blocks(self):
        sh(self.repo, "add", "-A")
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.email=me@realmail.test", "commit", "-qm", "x"],
                       check=True)
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_FINDINGS)
        self.assertIn("me@realmail.test", out)

    def test_personal_config_email_refused(self):
        sh(self.repo, "config", "user.email", "me@realmail.test")
        code, out = self.run_gate("publish", "--paths", ".", "-m", "x", "--first-publish")
        self.assertEqual(code, pg.EXIT_REFUSED)

    def test_missing_denylist_is_unverifiable_not_clean(self):
        sh(self.repo, "add", "-A")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = pg.main(["check", "--repo", str(self.repo), "--denylist", str(self.deny) + ".missing"])
        self.assertEqual(code, pg.EXIT_UNVERIFIABLE)

    def test_empty_denylist_is_unverifiable(self):
        self.deny.write_text("# nothing yet\n", encoding="utf-8")
        sh(self.repo, "add", "-A")
        self.assertEqual(self.run_gate("check")[0], pg.EXIT_UNVERIFIABLE)

    def test_allow_entry_clears_one_line_only(self):
        self.write("docs.md", "ssh 192.168.1.50\nssh 192.168.1.51\n")
        self.write(".publish-gate.json", '{"severity": {"private-ip": "block"}, "allow": '
                   '[{"check": "private-ip", "path": "docs.md", "line_contains": "1.50", "reason": "lab"}]}')
        sh(self.repo, "add", "-A")
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_FINDINGS)
        self.assertIn("192.168.1.51", out)
        self.assertNotIn("192.168.1.50", out)

    def test_blanket_allow_refused(self):
        self.write(".publish-gate.json", '{"allow": [{"check": "denylist", "path": "*", "reason": "x"}]}')
        self.assertEqual(self.run_gate("check")[0], pg.EXIT_REFUSED)

    def test_monitor_catches_push_outside_gate(self):
        self.first_publish()
        self.assertEqual(self.run_gate("monitor")[0], pg.EXIT_CLEAN)
        self.write("README.md", "pushed by hand\n")
        sh(self.repo, "commit", "-qam", "manual")
        sh(self.repo, "push", "-q", "origin", "main")
        code, out = self.run_gate("monitor")
        self.assertEqual(code, pg.EXIT_FINDINGS)
        self.assertIn("pushed outside the gate", out)

    def test_publish_refuses_when_remote_moved_past_pin(self):
        self.first_publish()
        self.write("README.md", "pushed by hand\n")
        sh(self.repo, "commit", "-qam", "manual")
        sh(self.repo, "push", "-q", "origin", "main")
        self.write("README.md", "next\n")
        code, out = self.run_gate("publish", "--paths", "README.md", "-m", "x")
        self.assertEqual(code, pg.EXIT_REFUSED)
        self.assertIn("outside the gate", out)

    # --- regressions from the first audit ---

    def test_identical_files_are_not_unverifiable(self):
        self.write("pkg/__init__.py", "")
        self.write("pkg/sub/__init__.py", "")
        sh(self.repo, "add", "-A")
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_CLEAN, out)

    def test_commit_message_is_screened(self):
        code, out = self.run_gate("publish", "--paths", ".", "-m", "thanks Jane Q Realname",
                                  "--first-publish", "--reviewed")
        self.assertEqual(code, pg.EXIT_FINDINGS, out)
        self.assertEqual(sh(self.repo, "ls-remote", "origin"), "")

    def test_certify_checks_before_pinning(self):
        self.write("about.md", "by Jane Q Realname\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "manual")
        sh(self.repo, "push", "-q", "origin", "main")
        code, out = self.run_gate("certify", "--reviewed")
        self.assertEqual(code, pg.EXIT_FINDINGS, out)
        self.assertEqual(pg.load_state(self.repo), {})

    def test_existing_remote_without_pin_scans_all_history(self):
        self.write("old.md", "by Jane Q Realname\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "old")
        (self.repo / "old.md").unlink()
        sh(self.repo, "commit", "-qam", "remove")
        sh(self.repo, "push", "-q", "origin", "main")
        self.write("README.md", "new\n")
        code, out = self.run_gate("publish", "--paths", "README.md", "-m", "x", "--reviewed")
        self.assertEqual(code, pg.EXIT_FINDINGS, out)

    def test_shallow_clone_is_unverifiable(self):
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "one")
        self.write("README.md", "two\n")
        sh(self.repo, "commit", "-qam", "two")
        shallow = Path(self.tmp.name) / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{self.repo.as_posix()}", str(shallow)],
                       check=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = pg.main(["check", "--repo", str(shallow), "--denylist", str(self.deny)])
        self.assertEqual(code, pg.EXIT_UNVERIFIABLE, out.getvalue())

    def test_old_forbidden_name_with_same_bytes_as_current_file(self):
        self.write("notes.txt", "X=1\n")
        self.write(".env", "X=1\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "both")
        (self.repo / ".env").unlink()
        sh(self.repo, "commit", "-qam", "drop env")
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_FINDINGS, out)
        self.assertIn(".env", out)

    def test_bad_severity_value_refused(self):
        self.write(".publish-gate.json", '{"severity": {"secret": "BLOCK"}}')
        self.assertEqual(self.run_gate("check")[0], pg.EXIT_REFUSED)

    def test_text_exemption_needs_line(self):
        self.write(".publish-gate.json", '{"allow": [{"check": "email", "path": "*", "reason": "x"}]}')
        self.assertEqual(self.run_gate("check")[0], pg.EXIT_REFUSED)

    def test_tags_are_not_pushed(self):
        self.first_publish()
        sh(self.repo, "config", "push.followTags", "true")
        self.write("README.md", "v2\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "pre")
        sh(self.repo, "tag", "-a", "v2", "-m", "private note")
        code, out = self.run_gate("publish", "--paths", "README.md", "-m", "x", "--reviewed")
        self.assertEqual(code, pg.EXIT_CLEAN, out)
        self.assertNotIn("refs/tags", sh(self.repo, "ls-remote", "origin"))

    def test_lfs_pointer_is_unverifiable(self):
        self.write("data.csv", "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 9\n")
        sh(self.repo, "add", "-A")
        self.assertEqual(self.run_gate("check")[0], pg.EXIT_UNVERIFIABLE)

    def test_rename_from_outside_scope_refused(self):
        self.write("private/a.md", "x\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "base")
        sh(self.repo, "push", "-q", "origin", "main")
        (self.repo / "docs").mkdir()
        sh(self.repo, "mv", "private/a.md", "docs/a.md")
        code, out = self.run_gate("publish", "--paths", "docs", "-m", "x")
        self.assertEqual(code, pg.EXIT_REFUSED)
        self.assertIn("private/a.md", out)

    def test_dot_slash_scope_accepted(self):
        self.first_publish()
        self.write("src/x.py", "print(1)\n")
        code, out = self.run_gate("publish", "--paths", "./src", "-m", "x")
        self.assertEqual(code, pg.EXIT_REVIEW, out)

    def test_commented_preview_tags_do_not_count(self):
        tags = "".join(f'<meta property="{t}" content="https://x.example/a">' for t in
                       ("og:title", "og:description", "og:url", "og:image"))
        self.write("index.html", f"<html><head><!-- {tags} --></head></html>\n")
        sh(self.repo, "add", "-A")
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_FINDINGS)
        self.assertIn("link-preview", out)

    # --- regressions from the second audit ---

    def test_exemption_on_one_copy_does_not_clear_the_other(self):
        self.write("a.txt", "ssh 192.168.1.50\n")
        self.write("b.txt", "ssh 192.168.1.50\n")
        self.write(".publish-gate.json", '{"severity": {"private-ip": "block"}, "allow": '
                   '[{"check": "private-ip", "path": "a.txt", "line_contains": "1.50", "reason": "lab"}]}')
        sh(self.repo, "add", "-A")
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_FINDINGS, out)
        self.assertIn("b.txt", out)

    def test_differing_push_url_refused(self):
        other = Path(self.tmp.name) / "other.git"
        subprocess.run(["git", "init", "--bare", "-q", str(other)], check=True)
        sh(self.repo, "remote", "set-url", "--push", "origin", str(other))
        code, out = self.run_gate("publish", "--paths", ".", "-m", "x", "--first-publish", "--reviewed")
        self.assertEqual(code, pg.EXIT_REFUSED, out)
        self.assertIn("pushes to", out)

    def test_branch_must_match_checkout(self):
        self.first_publish()
        sh(self.repo, "checkout", "-q", "-b", "feature")
        self.write("README.md", "f\n")
        code, out = self.run_gate("publish", "--paths", "README.md", "-m", "x", "--branch", "main")
        self.assertEqual(code, pg.EXIT_REFUSED, out)

    # --- regressions from the third audit ---

    def test_preview_url_with_bad_port_rejected(self):
        tags = "".join(f'<meta property="{t}" content="https://a.example:invalid/">' for t in
                       ("og:title", "og:description", "og:url", "og:image"))
        self.write("index.html", f'<html><head>{tags}<meta name="twitter:card" content="summary">'
                   "</head></html>\n")
        sh(self.repo, "add", "-A")
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_FINDINGS, out)
        self.assertIn("real host", out)

    @unittest.skipUnless(pg.gitleaks_version() and pg.gitleaks_version() >= pg.GITLEAKS_MIN, "needs gitleaks")
    def test_case_colliding_paths_both_reach_gitleaks(self):
        token = "npm_" + "k3x9q2m7v4b8n1c5z6l0p2r8t4w7y1u3h5j9"
        bad = subprocess.run(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
                             input=f'const t = "{token}";\n', capture_output=True, text=True).stdout.strip()
        ok = subprocess.run(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
                            input="clean\n", capture_output=True, text=True).stdout.strip()
        sh(self.repo, "add", "README.md", "LICENSE")
        sh(self.repo, "update-index", "--add", "--cacheinfo", f"100644,{bad},A.js")
        sh(self.repo, "update-index", "--add", "--cacheinfo", f"100644,{ok},a.js")
        code, out = self.run_gate("check")
        self.assertEqual(code, pg.EXIT_FINDINGS, out)
        self.assertIn("A.js", out)

    def test_selftest_passes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(pg.main(["selftest"]), pg.EXIT_CLEAN)


if __name__ == "__main__":
    unittest.main()
