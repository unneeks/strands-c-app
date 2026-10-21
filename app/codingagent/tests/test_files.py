import shutil

import pytest

from coding import checkpoints
from coding.fs_tools import (
    apply_patch,
    delete_path,
    edit_file,
    list_directory,
    move_path,
    read_file,
    undo_change,
    write_file,
)
from coding.safety import PolicyError, is_sensitive, redact, resolve


# ----------------------------------------------------------------- confinement
def test_resolve_blocks_escape(ws):
    for bad in ("../outside.txt", "/etc/passwd", "~/x", "a/../../b"):
        with pytest.raises(PolicyError):
            resolve(bad)
    assert resolve("src/app.py") == ws / "src" / "app.py"


def test_symlink_escape_is_blocked(ws, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("top secret")
    (ws / "link.txt").symlink_to(outside)
    with pytest.raises(PolicyError):
        read_file("link.txt")


def test_git_dir_is_protected(ws):
    (ws / ".git").mkdir()
    with pytest.raises(PolicyError):
        write_file(".git/config", "x")


def test_sensitive_detection():
    assert is_sensitive(".env") and is_sensitive("cfg/.env.local") and is_sensitive("keys/server.pem")
    assert is_sensitive("x/.aws/config")
    assert not is_sensitive(".env.example") and not is_sensitive("src/app.py")


def test_redaction():
    text = "key=AKIAABCDEFGHIJKLMNOP\npassword = 'hunter2hunter2'\nplain = fine"
    out = redact(text)
    assert "AKIAABCDEFGHIJKLMNOP" not in out and "hunter2hunter2" not in out and "plain = fine" in out


# ------------------------------------------------------------------ read/write
def test_write_read_roundtrip_and_paging(ws):
    body = "\n".join(f"line {i}" for i in range(1, 501))
    assert "Created" in write_file("pkg/mod.py", body)
    out = read_file("pkg/mod.py")
    assert "lines 1-400 of 500" in out and "start_line=401" in out and "     1\tline 1" in out
    assert "line 500" in read_file("pkg/mod.py", start_line=401)


def test_append_and_overwrite(ws):
    write_file("a.txt", "one\n")
    assert "Appended" in write_file("a.txt", "two\n", append=True)
    assert (ws / "a.txt").read_text() == "one\ntwo\n"
    assert "Overwrote" in write_file("a.txt", "x")


def test_binary_and_missing(ws):
    (ws / "b.bin").write_bytes(b"\x00\x01\x02")
    with pytest.raises(ValueError, match="binary"):
        read_file("b.bin")
    with pytest.raises(FileNotFoundError):
        read_file("nope.txt")


# ------------------------------------------------------------------------ edit
def test_edit_unique_multi_and_hint(ws):
    write_file("f.py", "a = 1\nb = 2\na = 1\n")
    with pytest.raises(ValueError, match="matches 2 places"):
        edit_file("f.py", "a = 1", "a = 9")
    assert "1 replacement" in edit_file("f.py", "b = 2", "b = 3")
    out = edit_file("f.py", "a = 1", "a = 9", replace_all=True)
    assert "2 replacement" in out and (ws / "f.py").read_text() == "a = 9\nb = 3\na = 9\n"
    with pytest.raises(ValueError, match="Closest match"):
        edit_file("f.py", "b = 33", "b = 4")


def test_edit_preserves_crlf(ws):
    (ws / "w.txt").write_bytes(b"x = 1\r\ny = 2\r\n")
    edit_file("w.txt", "x = 1\ny = 2", "x = 1\ny = 3")
    assert (ws / "w.txt").read_bytes() == b"x = 1\r\ny = 3\r\n"


# ---------------------------------------------------------------- undo & delete
def test_undo_restores_edit_and_delete_and_create(ws):
    write_file("keep.txt", "original")
    edit_file("keep.txt", "original", "changed")
    cp = checkpoints.list_checkpoints(1)[0]["id"]
    undo_change(cp)
    assert (ws / "keep.txt").read_text() == "original"

    delete_path("keep.txt")
    assert not (ws / "keep.txt").exists()
    undo_change(checkpoints.list_checkpoints(1)[0]["id"])
    assert (ws / "keep.txt").read_text() == "original"

    write_file("new.txt", "hello")
    undo_change(checkpoints.list_checkpoints(1)[0]["id"])
    assert not (ws / "new.txt").exists()
    assert "Recent checkpoints" in undo_change()


def test_delete_dir_needs_recursive_and_is_undoable(ws):
    write_file("d/x.txt", "x")
    with pytest.raises(ValueError, match="recursive"):
        delete_path("d")
    delete_path("d", recursive=True)
    assert not (ws / "d").exists()
    undo_change(checkpoints.list_checkpoints(1)[0]["id"])
    assert (ws / "d" / "x.txt").read_text() == "x"


def test_move_refuses_overwrite(ws):
    write_file("a.txt", "a")
    write_file("b.txt", "b")
    with pytest.raises(ValueError, match="already exists"):
        move_path("a.txt", "b.txt")
    move_path("a.txt", "sub/c.txt")
    assert (ws / "sub" / "c.txt").read_text() == "a" and not (ws / "a.txt").exists()
    undo_change(checkpoints.list_checkpoints(1)[0]["id"])
    assert (ws / "a.txt").exists() and not (ws / "sub" / "c.txt").exists()


def test_list_directory(ws):
    write_file("src/a.py", "x")
    (ws / "node_modules" / "pkg").mkdir(parents=True)
    out = list_directory(".", depth=2)
    assert "src/" in out and "a.py" in out and "node_modules/" in out and "pkg" not in out


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_apply_patch(ws):
    write_file("hello.py", "print('hi')\n")
    patch = (
        "--- a/hello.py\n+++ b/hello.py\n@@ -1 +1,2 @@\n print('hi')\n+print('bye')\n"
    )
    assert "Applied patch" in apply_patch(patch)
    assert (ws / "hello.py").read_text() == "print('hi')\nprint('bye')\n"
    with pytest.raises(ValueError, match="does not apply"):
        apply_patch(patch)
    with pytest.raises(PolicyError):
        apply_patch("--- a/../x\n+++ b/../x\n@@ -0,0 +1 @@\n+boom\n")
