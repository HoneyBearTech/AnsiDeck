"""Git sources (Phase 4E-1): URL and destination checks, a locked-down git, syncing local
repositories into snapshots and read-only playbooks, malicious trees, and the API."""

import base64
import os
import stat
import subprocess
import tarfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app import git_sync
from app.config import get_settings
from app.db import get_sessionmaker
from app.models import AuditEvent, GitSnapshot, GitSource, Playbook, Run
from app.storage import git_mirror_path, git_snapshot_dir, playbook_path
from tests.conftest import make_user_client
from tests.test_projects import _admin, _member, _project
from tests.test_runs import _generate_key_pem

pytestmark = pytest.mark.no_worker

PLAY = "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.ping:\n"
_GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "Tester",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "Tester",
    "GIT_COMMITTER_EMAIL": "t@example.com",
}


def git(repo: Path, *args: str, input: bytes | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, env=_GIT_ENV, input=input
    ).stdout.decode()


def make_repo(path: Path, files: dict[str, str], links: dict[str, str] | None = None) -> Path:
    path.mkdir(parents=True)
    git(path, "init", "-q", "-b", "main")
    commit(path, files, links, "first")
    return path


def commit(
    repo: Path,
    files: dict[str, str | None],
    links: dict[str, str] | None = None,
    message: str = "change",
) -> str:
    for name, content in files.items():
        target = repo / name
        if content is None:
            target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    for name, target in (links or {}).items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, repo / name)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def local_git(monkeypatch):
    monkeypatch.setenv("GIT_ALLOW_LOCAL_SOURCES", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def admin(client: TestClient, local_git) -> TestClient:
    return _admin(client)


def _create(admin: TestClient, repo: Path, project_id: int = 1, **extra) -> dict:
    response = admin.post(
        f"/api/projects/{project_id}/git-sources",
        json={"name": extra.pop("name", "repo"), "url": f"file://{repo}", **extra},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _source(source_id: int) -> GitSource:
    db = get_sessionmaker()()
    try:
        source = db.get(GitSource, source_id)
        db.expunge(source)
        return source
    finally:
        db.close()


def _playbooks(source_id: int) -> dict[str, Playbook]:
    db = get_sessionmaker()()
    try:
        rows = db.scalars(select(Playbook).where(Playbook.source_id == source_id)).all()
        for row in rows:
            db.expunge(row)
        return {p.repo_path: p for p in rows}
    finally:
        db.close()


# ---------------------------------------------------------------- URLs and destinations


@pytest.mark.parametrize(
    ("url", "kind", "host", "port"),
    [
        ("https://github.com/org/repo.git", "https", "github.com", 443),
        ("git@github.com:org/repo.git", "ssh", "github.com", 22),
        ("ssh://git@gitea.lan:2222/org/repo.git", "ssh", "gitea.lan", 2222),
        ("http://gitea.lan:3000/org/repo.git", "http", "gitea.lan", 3000),
        ("https://[2001:db8::1]/repo.git", "https", "2001:db8::1", 443),
    ],
)
def test_supported_urls(url: str, kind: str, host: str, port: int) -> None:
    remote = git_sync.parse_url(url, allow_local=False)
    assert (remote.kind, remote.host, remote.port) == (kind, host, port)


@pytest.mark.parametrize(
    "url",
    [
        "ext::sh -c touch% /tmp/pwned",
        "ext::sh",
        "-oProxyCommand=touch /tmp/x",
        "--upload-pack=touch /tmp/x",
        "file:///etc",
        "/srv/repo.git",
        "git://example.com/repo.git",
        "https://user:token@github.com/org/repo.git",
        "https://-oops/repo.git",
        "ssh://-oProxyCommand=x@host/repo",
        "https://exa mple.com/repo",
        "https://example.com/re\npo",
        "ftp://example.com/repo",
        "https://example.com",
        "",
    ],
)
def test_unsafe_urls_are_refused(url: str) -> None:
    with pytest.raises(git_sync.SyncError):
        git_sync.parse_url(url, allow_local=False)


def test_file_urls_need_the_test_only_setting(monkeypatch) -> None:
    assert git_sync.parse_url("file:///srv/repo", allow_local=True).kind == "file"
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_SECRET_KEY", "a-real-secret-value-of-32-characters")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-real-admin-password")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://ansideck:s3cret-db@db/ansideck")
    monkeypatch.setenv("WORKER_TOKEN", "w" * 32)
    monkeypatch.setenv("GIT_ALLOW_LOCAL_SOURCES", "true")
    from pydantic import ValidationError

    from app.config import Settings

    with pytest.raises(ValidationError, match="GIT_ALLOW_LOCAL_SOURCES"):
        Settings(_env_file=None)


@pytest.mark.parametrize(
    "branch", ["-delete", "a..b", "x y", "x~1", "x^", "a:b", "@", "x.lock", "/x", "x/", ""]
)
def test_bad_branches_are_refused(branch: str) -> None:
    with pytest.raises(git_sync.SyncError):
        git_sync.check_branch(branch)


@pytest.mark.parametrize("subdir", ["..", "a/../b", "-x", "a//b"])
def test_bad_subdirs_are_refused(subdir: str) -> None:
    with pytest.raises(git_sync.SyncError):
        git_sync.check_subdir(subdir)


def test_globs_match_within_directories() -> None:
    assert git_sync.glob_match("site.yml", "*.yml")
    assert not git_sync.glob_match("roles/x/tasks/main.yml", "*.yml")
    assert git_sync.glob_match("playbooks/db.yml", "playbooks/*.yml")
    assert git_sync.glob_match("a/b/c.yml", "**/*.yml")
    assert git_sync.glob_match("c.yml", "**/*.yml")


@pytest.mark.parametrize(
    ("link", "target", "inside"),
    [
        ("a", "b", True),
        ("dir/a", "../b", True),
        ("dir/a", "sub/../b", False),  # `..` after a name could climb through a symlink
        ("a", "../x", False),
        ("dir/a", "../../x", False),
        ("a", "/etc/passwd", False),
        ("a", ".", True),
        ("a", "..", False),
    ],
)
def test_symlink_targets_must_stay_inside(link: str, target: str, inside: bool) -> None:
    assert git_sync._inside(link, target) is inside


def test_private_destinations_need_the_allowlist(client, monkeypatch) -> None:
    import ipaddress

    monkeypatch.setattr(git_sync, "_resolve", lambda host, port: [ipaddress.ip_address("10.1.2.3")])
    remote = git_sync.parse_url("ssh://git@gitea.lan/x.git")
    with pytest.raises(git_sync.SyncError, match="GIT_ALLOWED_PRIVATE_HOSTS"):
        git_sync.destination(remote)
    monkeypatch.setenv("GIT_ALLOWED_PRIVATE_HOSTS", "gitea.lan")
    get_settings.cache_clear()
    assert git_sync.destination(remote) == ("10.1.2.3", True)
    with pytest.raises(git_sync.SyncError, match="non-public"):
        git_sync.destination(git_sync.parse_url("https://169.254.169.254/latest"))

    monkeypatch.setattr(git_sync, "_resolve", lambda host, port: [ipaddress.ip_address("8.8.8.8")])
    with pytest.raises(git_sync.SyncError, match="https"):
        git_sync.destination(git_sync.parse_url("http://example.com/repo.git"))


def test_git_connects_to_the_checked_address_without_secrets_in_argv_or_env() -> None:
    https = git_sync.parse_url("https://git.example.com/org/repo.git")
    token = "tok-sentinel-123"
    with git_sync._Session(https, "203.0.113.9", git_sync.Auth(token=token, username="u")) as s:
        config = s.gitconfig.read_text()
        assert "curloptResolve = git.example.com:443:203.0.113.9" in config
        assert "followRedirects = false" in config
        assert base64.b64encode(f"u:{token}".encode()).decode() in config
        assert stat.S_IMODE(s.gitconfig.stat().st_mode) == 0o600
        assert stat.S_IMODE(s.dir.stat().st_mode) == 0o700
        assert token not in str(s.env)
        assert s.env["GIT_ALLOW_PROTOCOL"] == "https"
        assert not {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} & set(s.env)
        directory = s.dir
    assert not directory.exists()

    ssh = git_sync.parse_url("ssh://git@gitea.example.com:2222/org/repo.git")
    auth = git_sync.Auth(ssh_key="KEY-SENTINEL", known_hosts="[gitea.example.com]:2222 x y\n")
    with git_sync._Session(ssh, "198.51.100.4", auth) as s:
        command = s.env["GIT_SSH_COMMAND"]
        assert "HostName=198.51.100.4" in command
        assert "HostKeyAlias=[gitea.example.com]:2222" in command
        assert "StrictHostKeyChecking=yes" in command and "-F /dev/null" in command
        assert "ProxyCommand=none" in command
        assert "KEY-SENTINEL" not in command and "KEY-SENTINEL" not in str(s.env)
        assert (s.dir / "key").read_text() == "KEY-SENTINEL\n"


def test_git_refuses_other_transports_even_when_handed_one(tmp_path, monkeypatch) -> None:
    """Defense in depth: even if a URL slipped past parse_url, git itself refuses ext::."""
    import ipaddress

    monkeypatch.setattr(git_sync, "_resolve", lambda host, port: [ipaddress.ip_address("8.8.8.8")])
    marker = tmp_path / "pwned"
    sneaky = git_sync.Remote("https", f"ext::sh -c touch% {marker}", "example.com", 443)
    with pytest.raises(git_sync.SyncError):
        git_sync.fetch(sneaky, git_sync.Auth(), tmp_path / "m.git", "main")
    assert not marker.exists()


def test_git_refuses_a_local_path_behind_an_https_remote(admin, tmp_path, monkeypatch) -> None:
    """git allows file:// by default; ours only allows the remote's own transport."""
    import ipaddress

    monkeypatch.setattr(git_sync, "_resolve", lambda host, port: [ipaddress.ip_address("8.8.8.8")])
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    sneaky = git_sync.Remote("https", f"file://{repo}", "example.com", 443)
    with pytest.raises(git_sync.SyncError, match="not allowed"):
        git_sync.fetch(sneaky, git_sync.Auth(), tmp_path / "m.git", "main")


# ---------------------------------------------------------------- syncing


def test_a_source_syncs_into_read_only_playbooks(admin, tmp_path) -> None:
    repo = make_repo(
        tmp_path / "repo",
        {
            "site.yml": PLAY,
            "playbooks/db.yml": PLAY,
            "roles/web/tasks/main.yml": "- ansible.builtin.ping:\n",
            "group_vars/all.yml": "a: 1\n",
            "notes.yml": "just: data\n",
        },
        {"web_role": "roles/web"},
    )
    source = _create(admin, repo)
    assert source["sync_requested_at"] is not None
    assert git_sync.sync_source(source["id"]) == "ok"
    assert git_sync.sync_source(source["id"]) == "unchanged"

    out = admin.get(f"/api/projects/1/git-sources/{source['id']}").json()
    assert out["last_sync_status"] == "ok" and out["playbooks"] == 2
    head = git(repo, "rev-parse", "HEAD").strip()
    assert out["commit"] == head and out["commit_subject"] == "first"

    listed = {p["name"]: p for p in admin.get("/api/playbooks").json()}
    assert set(listed) == {"site.yml", "playbooks/db.yml"}
    site = listed["site.yml"]
    assert (site["source_name"], site["repo_path"], site["commit"]) == ("repo", "site.yml", head)
    assert admin.get(f"/api/playbooks/{site['id']}").json()["content"] == PLAY
    assert admin.put(f"/api/playbooks/{site['id']}", json={"content": PLAY}).status_code == 409
    assert admin.delete(f"/api/playbooks/{site['id']}").status_code == 409

    db = get_sessionmaker()()
    snapshot = db.scalars(select(GitSnapshot)).one()
    db.close()
    tar = git_snapshot_dir(source["id"]) / f"{head}.tar"
    with tarfile.open(tar) as archive:
        names = archive.getnames()
    assert {"site.yml", "roles/web/tasks/main.yml", "group_vars/all.yml", "web_role"} <= set(names)
    assert snapshot.sha256 and snapshot.size_bytes == tar.stat().st_size
    assert not (git_mirror_path(source["id"]) / "hooks").exists()


def test_upstream_changes_mark_removed_playbooks_and_revive_them(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"a.yml": PLAY, "b.yml": PLAY})
    source = _create(admin, repo)
    git_sync.sync_source(source["id"])
    first = _playbooks(source["id"])

    commit(repo, {"b.yml": None, "c.yml": PLAY})
    assert git_sync.sync_source(source["id"]) == "ok"
    second = _playbooks(source["id"])
    assert second["b.yml"].missing_at is not None
    assert second["a.yml"].missing_at is None and "c.yml" in second
    assert second["a.yml"].id == first["a.yml"].id  # ids are stable (CI triggers by id)
    b_id = second["b.yml"].id
    run = admin.post("/api/runs", json={"playbook_id": b_id, "inventory_id": 1, "credential_id": 1})
    assert run.status_code == 409 and "no longer" in run.json()["detail"]

    commit(repo, {"b.yml": PLAY})
    git_sync.sync_source(source["id"])
    assert _playbooks(source["id"])["b.yml"].missing_at is None
    assert _playbooks(source["id"])["b.yml"].id == b_id

    commit(repo, {"b.yml": None})
    git_sync.sync_source(source["id"])
    assert admin.delete(f"/api/playbooks/{b_id}").status_code == 204  # gone upstream: deletable

    db = get_sessionmaker()()
    snapshots = db.scalars(select(GitSnapshot).order_by(GitSnapshot.id)).all()
    db.close()
    assert [s.superseded_at is None for s in snapshots] == [False, False, False, True]
    events = [e for e in _audit("git_source.sync") if e.outcome == "success"]
    assert len(events) == 4


def test_a_subdirectory_and_custom_patterns(admin, tmp_path) -> None:
    repo = make_repo(
        tmp_path / "repo",
        {"ansible/deploy/main.yml": PLAY, "ansible/other.yml": PLAY, "top.yml": PLAY},
    )
    source = _create(admin, repo, subdir="ansible", playbook_globs=["**/*.yml"])
    assert git_sync.sync_source(source["id"]) == "ok"
    assert set(_playbooks(source["id"])) == {"deploy/main.yml", "other.yml"}
    tar = next(git_snapshot_dir(source["id"]).glob("*.tar"))
    with tarfile.open(tar) as archive:
        assert "top.yml" not in archive.getnames()

    admin.patch(f"/api/projects/1/git-sources/{source['id']}", json={"subdir": "nope"})
    assert git_sync.sync_source(source["id"]) == "failed"
    assert "does not exist" in _source(source["id"]).last_sync_error


# ---------------------------------------------------------------- hostile repositories


def test_a_symlink_out_of_the_tree_never_becomes_current(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    source = _create(admin, repo)
    git_sync.sync_source(source["id"])
    good = _source(source["id"]).current_snapshot_id

    commit(repo, {}, {"evil": "/etc/passwd"})
    assert git_sync.sync_source(source["id"]) == "failed"
    failed = _source(source["id"])
    assert "points outside" in failed.last_sync_error
    assert failed.current_snapshot_id == good  # the previous commit stays current
    assert len(list(git_snapshot_dir(source["id"]).glob("*.tar"))) == 1

    git(repo, "rm", "-q", "evil")
    commit(repo, {}, {"sub/escape": "../../outside"})
    assert git_sync.sync_source(source["id"]) == "failed"
    failures = [e for e in _audit("git_source.sync") if e.outcome == "failure"]
    assert len(failures) == 1  # once per failing episode, not per attempt


def test_a_tree_with_a_dotdot_entry_is_rejected_on_fetch(admin, tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    blob = git(repo, "hash-object", "-w", "--stdin", input=b"x\n").strip()
    tree = git(repo, "mktree", input=f"100644 blob {blob}\t..\n".encode()).strip()
    evil = git(repo, "commit-tree", tree, "-m", "evil").strip()
    git(repo, "update-ref", "refs/heads/main", evil)
    source = _create(admin, repo)
    assert git_sync.sync_source(source["id"]) == "failed"
    assert "dotdot" in _source(source["id"]).last_sync_error.lower()  # fsck, at fetch time


def test_submodules_are_not_fetched(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    head = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},vendor/lib")
    (repo / ".gitmodules").write_text('[submodule "x"]\n\tpath = vendor/lib\n\turl = ../x\n')
    git(repo, "add", ".gitmodules")
    git(repo, "commit", "-q", "-m", "submodule")
    source = _create(admin, repo)
    assert git_sync.sync_source(source["id"]) == "ok"
    out = admin.get(f"/api/projects/1/git-sources/{source['id']}").json()
    assert any("submodule vendor/lib" in w for w in out["warnings"])


def test_size_and_file_limits(admin, tmp_path, monkeypatch) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY, "big.bin": "x" * (2 * 1024 * 1024)})
    source = _create(admin, repo)
    monkeypatch.setenv("GIT_MAX_SNAPSHOT_MB", "1")
    get_settings.cache_clear()
    assert git_sync.sync_source(source["id"]) == "failed"
    assert "more than 1 MB" in _source(source["id"]).last_sync_error

    monkeypatch.setenv("GIT_MAX_SNAPSHOT_MB", "50")
    monkeypatch.setenv("GIT_MAX_FILES", "1")
    get_settings.cache_clear()
    assert git_sync.sync_source(source["id"]) == "failed"
    assert "more than 1 files" in _source(source["id"]).last_sync_error

    monkeypatch.setenv("GIT_MAX_FILES", "100")
    monkeypatch.setenv("GIT_MAX_REPO_MB", "1")
    get_settings.cache_clear()
    commit(repo, {"big2.bin": os.urandom(3 * 1024 * 1024).hex()})
    assert git_sync.sync_source(source["id"]) == "failed"
    assert "larger than 1 MB" in _source(source["id"]).last_sync_error
    assert not git_mirror_path(source["id"]).exists()  # an oversized mirror is removed


def _bare_commit(path: Path, top_tree) -> tuple[Path, str]:
    """A bare repository whose one commit has the tree top_tree(mktree) builds."""
    subprocess.run(["git", "init", "-q", "--bare", str(path)], check=True)

    def run(*args: str, input: bytes | None = None) -> str:
        names = ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL")
        env = {**os.environ, "GIT_DIR": str(path), **dict.fromkeys(names, "t")}
        return (
            subprocess.run(["git", *args], input=input, env=env, capture_output=True, check=True)
            .stdout.decode()
            .strip()
        )

    def mktree(entries: list[tuple[str, str, str]]) -> str:
        lines = "".join(f"{mode} {kind} {oid}\t{name}\n" for mode, kind, oid, name in entries)
        return run("mktree", input=lines.encode())

    blob = run("hash-object", "-w", "--stdin", input=b"x")
    return path, run("commit-tree", top_tree(mktree, blob), "-m", "bomb")


def test_a_tree_that_lists_millions_of_files_is_refused_without_reading_them(tmp_path) -> None:
    """A few tree objects, each naming the one below ten times: 10^6 files from 7 objects.
    The listing is cut off at GIT_MAX_FILES instead of read whole into the API's memory."""

    def bomb(mktree, blob):
        tree = mktree([("100644", "blob", blob, f"f{i}") for i in range(10)])
        for _ in range(5):
            tree = mktree([("040000", "tree", tree, f"d{i}") for i in range(10)])
        return tree

    mirror, commit_id = _bare_commit(tmp_path / "bomb.git", bomb)
    started = time.monotonic()
    with pytest.raises(git_sync.SyncError, match="more than 20000 files"):
        git_sync.inspect_tree(mirror, commit_id, None)
    assert time.monotonic() - started < 3  # reading it all took ~15 s and 650 MB


def test_a_listing_of_very_long_paths_is_cut_off_too(tmp_path, monkeypatch) -> None:
    """One file 200 directories deep, each named with 250 characters: a 50 KB path."""
    monkeypatch.setenv("GIT_MAX_FILES", "10")  # so at most 40 KB of listing
    get_settings.cache_clear()

    def deep(mktree, blob):
        tree = mktree([("100644", "blob", blob, "f")])
        for _ in range(200):
            tree = mktree([("040000", "tree", tree, "d" * 250)])
        return tree

    mirror, commit_id = _bare_commit(tmp_path / "deep.git", deep)
    with pytest.raises(git_sync.SyncError, match="more data than expected"):
        git_sync.inspect_tree(mirror, commit_id, None)
    get_settings.cache_clear()


def test_hooks_never_run(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    source = _create(admin, repo)
    git_sync.sync_source(source["id"])
    marker = tmp_path / "hook-ran"
    hooks = git_mirror_path(source["id"]) / "hooks"
    hooks.mkdir()
    for name in ("reference-transaction", "post-checkout", "pre-auto-gc", "post-merge"):
        hook = hooks / name
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
        hook.chmod(0o755)
    commit(repo, {"next.yml": PLAY})
    assert git_sync.sync_source(source["id"]) == "ok"
    assert not marker.exists()


def test_export_attributes_are_ignored(admin, tmp_path) -> None:
    """A snapshot holds the tree as a checkout would: no export-subst, no export-ignore."""
    repo = make_repo(
        tmp_path / "repo",
        {
            "site.yml": PLAY,
            "version.txt": "$Format:%H$\n",
            "hidden.yml": "a: 1\n",
            ".gitattributes": "version.txt export-subst\nhidden.yml export-ignore\n",
        },
    )
    source = _create(admin, repo)
    git_sync.sync_source(source["id"])
    with tarfile.open(next(git_snapshot_dir(source["id"]).glob("*.tar"))) as tar:
        assert "hidden.yml" in tar.getnames()
        assert tar.extractfile("version.txt").read() == b"$Format:%H$\n"


def test_an_unreachable_remote_fails_without_leaking_the_token(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    response = admin.post(
        "/api/projects/1/git-sources",
        json={
            "name": "tok",
            "url": f"file://{repo}",
            "auth_kind": "https_token",
            "https_username": "bot",
            "token": "secret-token-sentinel",
        },
    )
    assert response.status_code == 201, response.text
    assert "secret-token-sentinel" not in response.text
    assert response.json()["has_token"] is True
    shutil_target = repo / ".git"
    shutil_target.rename(repo / ".moved")  # the remote is gone
    assert git_sync.sync_source(response.json()["id"]) == "failed"
    source = _source(response.json()["id"])
    assert source.last_sync_error and "secret-token-sentinel" not in source.last_sync_error
    db = get_sessionmaker()()
    stored = db.get(GitSource, source.id).encrypted_token
    db.close()
    assert b"secret-token-sentinel" not in stored


# ---------------------------------------------------------------- pruning and deleting


def test_old_snapshots_are_pruned_unless_a_run_is_pinned_to_them(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    source = _create(admin, repo)
    git_sync.sync_source(source["id"])
    commit(repo, {"b.yml": PLAY})
    git_sync.sync_source(source["id"])
    commit(repo, {"c.yml": PLAY})
    git_sync.sync_source(source["id"])

    db = get_sessionmaker()()
    first, second, current = (
        (s.id, s.commit) for s in db.scalars(select(GitSnapshot).order_by(GitSnapshot.id)).all()
    )
    first_id, first_commit = first
    second_id, second_commit = second
    db.execute(
        update(GitSnapshot)
        .where(GitSnapshot.id.in_([first_id, second_id]))
        .values(superseded_at=datetime.now(UTC) - timedelta(hours=1))
    )
    pinned = Run(
        project_id=1,
        playbook_name="site.yml",
        inventory_name="i",
        credential_name="c",
        triggered_by="admin",
        status="queued",
        git_snapshot_id=second_id,
        git_commit=second_commit,
    )
    db.add(pinned)
    db.commit()
    assert git_sync.prune_snapshots(db) == 1
    remaining = {s.id for s in db.scalars(select(GitSnapshot))}
    db.close()
    assert remaining == {second_id, current[0]}
    assert not (git_snapshot_dir(source["id"]) / f"{first_commit}.tar").exists()
    assert (git_snapshot_dir(source["id"]) / f"{second_commit}.tar").exists()


def test_deleting_a_source_removes_its_playbooks_and_files(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    source = _create(admin, repo)
    git_sync.sync_source(source["id"])
    playbook_id = _playbooks(source["id"])["site.yml"].id

    db = get_sessionmaker()()
    db.add(
        Run(
            project_id=1,
            playbook_name="site.yml",
            inventory_name="i",
            credential_name="c",
            triggered_by="admin",
            status="queued",
            git_source_id=source["id"],
        )
    )
    db.commit()
    assert admin.delete(f"/api/projects/1/git-sources/{source['id']}").status_code == 409
    db.execute(update(Run).values(status="success"))
    db.commit()
    db.close()

    assert admin.delete(f"/api/projects/1/git-sources/{source['id']}").status_code == 204
    assert admin.get(f"/api/playbooks/{playbook_id}").status_code == 404
    assert not playbook_path(playbook_id).exists()
    assert not git_mirror_path(source["id"]).exists()
    assert not list(git_snapshot_dir(source["id"]).glob("*"))
    assert _audit("git_source.delete")


# ---------------------------------------------------------------- the API


def test_settings_are_validated(admin, tmp_path) -> None:
    base = {"name": "x", "url": "https://example.com/r.git"}
    cases = [
        ({"url": "ext::sh"}, 400),
        ({"url": "git@github.com:o/r.git"}, 400),  # ssh needs a deploy key
        ({"url": "git@github.com:o/r.git", "auth_kind": "ssh_key"}, 400),  # ...from this project
        ({"auth_kind": "ssh_key", "credential_id": 1}, 400),  # https with an ssh key
        ({"auth_kind": "https_token"}, 400),  # without a token
        ({"branch": "a..b"}, 400),
        ({"subdir": "../x"}, 400),
        ({"web_url": "javascript:alert(1)"}, 400),
        ({"playbook_globs": ["../*.yml"]}, 400),
        ({"auto_sync_seconds": 30}, 422),
    ]
    for extra, code in cases:
        response = admin.post("/api/projects/1/git-sources", json={**base, **extra})
        assert response.status_code == code, (extra, response.text)
    assert admin.post("/api/projects/1/git-sources", json=base).status_code == 201
    assert admin.post("/api/projects/1/git-sources", json=base).status_code == 409


def test_ssh_sources_wait_for_a_trusted_host_key(admin) -> None:
    key = admin.post(
        "/api/credentials", json={"name": "deploy", "private_key": _generate_key_pem()}
    ).json()
    created = admin.post(
        "/api/projects/1/git-sources",
        json={
            "name": "ssh",
            "url": "git@gitea.example.com:org/repo.git",
            "auth_kind": "ssh_key",
            "credential_id": key["id"],
        },
    )
    assert created.status_code == 201, created.text
    source = created.json()
    assert source["sync_requested_at"] is None and source["host_keys"] == []
    db = get_sessionmaker()()
    assert source["id"] not in git_sync.due_sources(db)  # not polled before a key is trusted
    db.close()

    blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"\x01" * 32).decode()
    pasted = f"gitea.example.com,10.0.0.5 ssh-ed25519 {blob}\nother.host ssh-rsa AAAA\n"
    trusted = admin.post(
        f"/api/projects/1/git-sources/{source['id']}/trust-host-key", json={"known_hosts": pasted}
    )
    assert trusted.status_code == 200, trusted.text
    assert trusted.json()["host_keys"] == [
        {"type": "ssh-ed25519", "fingerprint": git_sync.fingerprint(blob)}
    ]
    assert _source(source["id"]).ssh_known_hosts == f"gitea.example.com ssh-ed25519 {blob}\n"
    assert _audit("git_source.trust_host_key")

    # Another host: the trust doesn't carry over.
    moved = admin.patch(
        f"/api/projects/1/git-sources/{source['id']}",
        json={"url": "git@elsewhere.example.com:org/repo.git"},
    )
    assert moved.json()["host_keys"] == []
    assert admin.delete(f"/api/credentials/{key['id']}").status_code == 409  # still in use


def test_keyscan_reports_fingerprints(monkeypatch) -> None:
    import ipaddress

    blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + b"\x02" * 32).decode()
    monkeypatch.setattr(git_sync, "_resolve", lambda h, p: [ipaddress.ip_address("8.8.8.8")])
    monkeypatch.setattr(
        git_sync, "_run", lambda cmd, session, **kw: f"8.8.8.8 ssh-ed25519 {blob}\n".encode()
    )
    keys = git_sync.keyscan(git_sync.parse_url("git@forge.example.com:o/r.git"))
    assert keys == [{"type": "ssh-ed25519", "key": blob, "fingerprint": git_sync.fingerprint(blob)}]


def test_the_connection_test_reports_the_branch(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    source = _create(admin, repo)
    result = admin.post(f"/api/projects/1/git-sources/{source['id']}/test").json()
    assert result == {
        "ok": True,
        "error": None,
        "default_branch": "main",
        "branch_exists": True,
        "host_keys": [],
        "host_key_trusted": None,
    }
    admin.patch(f"/api/projects/1/git-sources/{source['id']}", json={"branch": "nope"})
    result = admin.post(f"/api/projects/1/git-sources/{source['id']}/test").json()
    assert result["ok"] is False and "not found" in result["error"]


def test_roles(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    source = _create(admin, repo)
    path = f"/api/projects/1/git-sources/{source['id']}"
    viewer = make_user_client("v1", "viewer")
    operator = make_user_client("o1", "operator")
    assert viewer.get("/api/projects/1/git-sources").status_code == 200
    assert viewer.post(f"{path}/sync").status_code == 403
    assert operator.post(f"{path}/sync").status_code == 202
    assert operator.patch(path, json={"branch": "x"}).status_code == 403
    assert (
        operator.post("/api/projects/1/git-sources", json={"name": "n", "url": "x"}).status_code
        == 403
    )
    assert operator.post(f"{path}/test").status_code == 403
    assert operator.delete(path).status_code == 403
    assert "token" not in str(viewer.get(path).json()).lower().replace("has_token", "")


def test_another_projects_sources_are_invisible(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    other = _project(admin, "Other")
    source = _create(admin, repo, project_id=other)
    member = _member(admin, "a-admin", {1: "admin"})
    for method, suffix, body in (
        ("GET", "", None),
        ("PATCH", "", {"branch": "x"}),
        ("DELETE", "", None),
        ("GET", "/snapshots", None),
        ("POST", "/test", None),
        ("POST", "/trust-host-key", {"known_hosts": "x"}),
        ("POST", "/sync", None),
    ):
        # Through their own project's path, and through the other project's.
        mine = member.request(
            method, f"/api/projects/1/git-sources/{source['id']}{suffix}", json=body
        )
        assert mine.status_code == 404, (method, suffix)
        theirs = member.request(
            method, f"/api/projects/{other}/git-sources/{source['id']}{suffix}", json=body
        )
        assert theirs.status_code == 404, (method, suffix)
    assert member.get(f"/api/projects/{other}/git-sources").status_code == 404
    assert (
        member.post(
            f"/api/projects/{other}/git-sources", json={"name": "n", "url": "x"}
        ).status_code
        == 404
    )


def test_a_project_with_sources_cant_be_deleted(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    other = _project(admin, "Doomed")
    _create(admin, repo, project_id=other)
    response = admin.delete(f"/api/projects/{other}")
    assert response.status_code == 409 and "1 git sources" in response.json()["detail"]


def test_due_sources(admin, tmp_path) -> None:
    repo = make_repo(tmp_path / "repo", {"site.yml": PLAY})
    polled = _create(admin, repo, name="polled")
    manual = _create(admin, repo, name="manual", auto_sync_seconds=0)
    off = _create(admin, repo, name="off", enabled=False)
    db = get_sessionmaker()()
    assert set(git_sync.due_sources(db)) == {polled["id"], manual["id"]}  # both requested
    db.close()
    for source in (polled, manual, off):
        git_sync.sync_source(source["id"])
    db = get_sessionmaker()()
    assert git_sync.due_sources(db) == []
    db.execute(
        update(GitSource)
        .where(GitSource.id.in_([polled["id"], manual["id"], off["id"]]))
        .values(last_sync_started_at=datetime.now(UTC) - timedelta(hours=1))
    )
    db.commit()
    assert git_sync.due_sources(db) == [polled["id"]]  # manual: only on request; off: never
    db.close()


def _audit(action: str) -> list[AuditEvent]:
    db = get_sessionmaker()()
    try:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))
    finally:
        db.close()
