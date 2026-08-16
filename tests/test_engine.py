import importlib.util
import os
import stat
import sys
import types
from types import SimpleNamespace

import pytest

# Load one engine copy as a plain module; the file has a __main__ guard so
# importing it does not start the CLI.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE_PATH = os.path.join(
    _HERE, "..", "cis-rhel10-ansible", "roles", "cis-rhel10", "files", "ohbs_engine.py"
)

_spec = importlib.util.spec_from_file_location("ohbs_engine_under_test", _ENGINE_PATH)
engine = importlib.util.module_from_spec(_spec)
sys.modules["ohbs_engine_under_test"] = engine
_spec.loader.exec_module(engine)


def _ctx(tmp_path, mode="apply", backup_dir=None, allow_disruptive=False):
    opts = SimpleNamespace(
        mode=mode,
        allow_disruptive=allow_disruptive,
        backup_dir=str(backup_dir) if backup_dir else None,
    )
    return engine.Ctx(opts)


class TestParsingHelpers:
    def test_as_int(self):
        assert engine.as_int("42") == 42
        assert engine.as_int("  7 ") == 7
        assert engine.as_int("abc") is None
        assert engine.as_int(None, 0) == 0

    def test_fmt_mode(self):
        assert engine.fmt_mode(0o644) == "0644"
        assert engine.fmt_mode(0o7777) == "7777"

    def test_mode_ok(self):
        assert engine.mode_ok(0o644, "0644") is True
        assert engine.mode_ok(0o600, "0644") is True
        assert engine.mode_ok(0o777, "0644") is False
        assert engine.mode_ok(0o755, 0o755) is True


class TestAtomicWrite:
    def test_writes_content_and_sets_mode(self, tmp_path):
        target = tmp_path / "target.conf"
        engine.atomic_write(str(target), "hello\n", mode=0o640)
        assert target.read_text() == "hello\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o640

    def test_no_temp_file_left_behind(self, tmp_path):
        target = tmp_path / "target.conf"
        engine.atomic_write(str(target), "content", mode=0o644)
        leftovers = list(tmp_path.glob(".*.cis-tmp"))
        assert leftovers == []

    def test_overwrites_existing_file(self, tmp_path):
        target = tmp_path / "target.conf"
        target.write_text("old")
        engine.atomic_write(str(target), "new", mode=0o644)
        assert target.read_text() == "new"

    def test_creates_parent_directory(self, tmp_path):
        target = tmp_path / "sub" / "dir" / "file.conf"
        engine.atomic_write(str(target), "x", mode=0o644)
        assert target.exists()


class TestBackup:
    def test_copies_file_to_backup_tree(self, tmp_path):
        src = tmp_path / "etc" / "ssh" / "sshd_config"
        src.parent.mkdir(parents=True)
        src.write_text("config")
        backup_root = tmp_path / "backups"
        ctx = _ctx(tmp_path, backup_dir=backup_root)
        engine.backup(ctx, str(src))
        # Backup mirrors the absolute source path under backup_root.
        rel = str(src).lstrip("/")
        backup = backup_root / rel
        assert backup.exists()
        assert backup.read_text() == "config"

    def test_skips_path_traversal(self, tmp_path):
        # Create the file using a normalized path, then pass an unnormalized
        # path containing ".." to backup.
        (tmp_path / "sub").mkdir()
        evil = tmp_path / "evil"
        evil.write_text("bad")
        src = tmp_path / "sub" / ".." / "evil"
        backup_root = tmp_path / "backups"
        ctx = _ctx(tmp_path, backup_dir=backup_root)
        engine.backup(ctx, str(src))
        assert any("path traversal" in n for n in ctx.notes)

    def test_does_not_overwrite_existing_backup(self, tmp_path):
        src = tmp_path / "file.txt"
        src.write_text("new")
        backup_root = tmp_path / "backups"
        existing = backup_root / "file.txt"
        existing.parent.mkdir(parents=True)
        existing.write_text("old")
        ctx = _ctx(tmp_path, backup_dir=backup_root)
        engine.backup(ctx, str(src))
        assert existing.read_text() == "old"

    def test_missing_source_is_noop(self, tmp_path):
        ctx = _ctx(tmp_path, backup_dir=tmp_path / "backups")
        engine.backup(ctx, str(tmp_path / "nope"))
        assert ctx.notes == []

    def test_backup_directory_is_0700_and_file_is_0600(self, tmp_path):
        src = tmp_path / "secret"
        src.write_text("data")
        backup_root = tmp_path / "backups"
        ctx = _ctx(tmp_path, backup_dir=backup_root)
        engine.backup(ctx, str(src))
        rel = str(src).lstrip("/")
        backup = backup_root / rel
        assert backup.exists()
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600
        assert stat.S_IMODE(backup.parent.stat().st_mode) == 0o700

    def test_backup_enforces_permissions_on_existing_backup(self, tmp_path):
        src = tmp_path / "secret"
        src.write_text("data")
        backup_root = tmp_path / "backups"
        # The backup destination mirrors the absolute source path under backup_root.
        rel = str(src).lstrip("/")
        existing = backup_root / rel
        existing.parent.mkdir(parents=True)
        existing.write_text("old")
        os.chmod(existing, 0o644)
        ctx = _ctx(tmp_path, backup_dir=backup_root)
        engine.backup(ctx, str(src))
        assert stat.S_IMODE(existing.stat().st_mode) == 0o600


class TestRestoreFromBackup:
    def test_restores_file_from_backup(self, tmp_path):
        src = tmp_path / "config"
        src.write_text("original")
        backup_root = tmp_path / "backups"
        ctx = _ctx(tmp_path, backup_dir=backup_root)
        engine.backup(ctx, str(src))
        src.write_text("modified")
        ok = engine.restore_from_backup(ctx, str(src))
        assert ok is True
        assert src.read_text() == "original"

    def test_returns_false_when_no_backup(self, tmp_path):
        src = tmp_path / "config"
        src.write_text("original")
        ctx = _ctx(tmp_path, backup_dir=tmp_path / "backups")
        ok = engine.restore_from_backup(ctx, str(src))
        assert ok is False

    def test_skips_path_traversal(self, tmp_path):
        ctx = _ctx(tmp_path, backup_dir=tmp_path / "backups")
        ok = engine.restore_from_backup(ctx, str(tmp_path / ".." / "etc" / "passwd"))
        assert ok is False


class TestWriteFile:
    def test_writes_and_records_change(self, tmp_path):
        target = tmp_path / "out.conf"
        ctx = _ctx(tmp_path, backup_dir=tmp_path / "backups")
        engine.write_file(ctx, str(target), "content\n", mode=0o640)
        assert target.read_text() == "content\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
        assert str(target) in ctx.changed_files


class TestSetKvInFile:
    def test_creates_file_with_header(self, tmp_path):
        target = tmp_path / "new.conf"
        ctx = _ctx(tmp_path)
        engine.set_kv_in_file(ctx, str(target), "KEY", "value", sep="=")
        text = target.read_text()
        assert "KEY=value" in text
        assert "Managed by CIS Ansible hardening" in text

    def test_replaces_existing_key(self, tmp_path):
        target = tmp_path / "cfg"
        target.write_text("KEY=old\nOTHER=1\n")
        ctx = _ctx(tmp_path)
        engine.set_kv_in_file(ctx, str(target), "KEY", "new", sep="=")
        lines = target.read_text().splitlines()
        assert lines.count("KEY=new") == 1
        assert "KEY=old" not in lines
        assert "OTHER=1" in lines

    def test_drops_commented_duplicates(self, tmp_path):
        target = tmp_path / "cfg"
        target.write_text("# KEY=old\nKEY=active\n")
        ctx = _ctx(tmp_path)
        engine.set_kv_in_file(ctx, str(target), "KEY", "active", sep="=")
        lines = target.read_text().splitlines()
        assert lines.count("KEY=active") == 1
        assert not any(l.startswith("# KEY") for l in lines)


class TestCommentOut:
    def test_comments_matching_lines(self, tmp_path):
        target = tmp_path / "cfg"
        target.write_text("keep\nEnable=true\nalso keep\n")
        ctx = _ctx(tmp_path)
        n = engine.comment_out(ctx, str(target), r"^\s*Enable\s*=\s*true")
        assert n == 1
        text = target.read_text()
        assert "# Enable=true" in text
        assert "keep\n" in text

    def test_idempotent(self, tmp_path):
        target = tmp_path / "cfg"
        target.write_text("# Enable=true\n")
        ctx = _ctx(tmp_path)
        n = engine.comment_out(ctx, str(target), r"^\s*Enable\s*=\s*true")
        assert n == 0
        assert target.read_text() == "# Enable=true\n"


class TestWaiverExpiration:
    def test_expired_waiver_detected(self):
        from datetime import date, timedelta
        expired = {"reason": "legacy", "expires": (date.today() - timedelta(days=1)).isoformat()}
        assert engine._waiver_expired(expired)[0] is True

    def test_valid_waiver_not_expired(self):
        from datetime import date, timedelta
        valid = {"reason": "legacy", "expires": (date.today() + timedelta(days=1)).isoformat()}
        assert engine._waiver_expired(valid)[0] is False

    def test_waiver_without_expiry_never_expired(self):
        assert engine._waiver_expired({"reason": "legacy"})[0] is False
        assert engine._waiver_expired("legacy reason")[0] is False
