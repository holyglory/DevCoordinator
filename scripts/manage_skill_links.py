#!/usr/bin/env python3
"""Plan, apply, verify, and roll back canonical Holy Skills symlinks.

The command deliberately requires every installation root to be named.  It
never derives a target from HOME because desktop runtimes can override HOME.
Only skills present under the selected repository's ``skills`` directory are
managed; unrelated entries in an installation root are never touched.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator


VERSION = 2
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
JOURNAL_NAME = "journal.json"
SAFE_APPLY_STATES = {"missing", "copied_match", "direct_link"}


class LinkManagerError(RuntimeError):
    """A safe, user-actionable link-management failure."""


class LockedRoot:
    """An exclusively locked target-root directory and its stable identity."""

    __slots__ = ("path", "descriptor", "device", "inode")

    def __init__(self, path: Path, descriptor: int, device: int, inode: int) -> None:
        self.path = path
        self.descriptor = descriptor
        self.device = device
        self.inode = inode

    def journal_identity(self) -> dict[str, int]:
        return {"device": self.device, "inode": self.inode}


def lexical_exists(path: Path) -> bool:
    """Return True for normal paths and broken symlinks."""

    return os.path.lexists(path)


def require_absolute(raw: str, label: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        raise LinkManagerError(f"{label} must be an explicit absolute path: {raw!r}")
    return path


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        fsync_directory(path.parent)
    finally:
        if lexical_exists(temporary):
            temporary.unlink()


def tree_digest(root: Path) -> str:
    """Hash names, types, link targets, modes, and file contents without following links."""

    digest = hashlib.sha256()
    paths = [root]
    paths.extend(
        sorted(
            (
                item
                for item in root.rglob("*")
                if "__pycache__" not in item.relative_to(root).parts
                and item.suffix != ".pyc"
                and item.name != ".DS_Store"
            ),
            key=lambda item: item.relative_to(root).as_posix(),
        )
    )
    for path in paths:
        relative = "." if path == root else path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            kind = "link"
            content = os.readlink(path).encode("utf-8", errors="surrogateescape")
        elif path.is_dir():
            kind = "directory"
            content = b""
        elif path.is_file():
            kind = "file"
            content = path.read_bytes()
        else:
            kind = "other"
            content = b""
        for part in (relative.encode("utf-8"), kind.encode("ascii"), str(mode).encode("ascii"), content):
            digest.update(part)
            digest.update(b"\0")
    return digest.hexdigest()


def canonical_repository(raw: str | Path) -> Path:
    repository = require_absolute(str(raw), "--repo-root")
    if repository.is_symlink():
        raise LinkManagerError(f"repository root must not itself be a symlink: {repository}")
    try:
        repository = repository.resolve(strict=True)
    except FileNotFoundError as error:
        raise LinkManagerError(f"repository root does not exist: {repository}") from error
    if not (repository / "skills").is_dir():
        raise LinkManagerError(f"repository has no skills directory: {repository}")
    return repository


def canonical_target_roots(raw_roots: Iterable[str | Path], repository: Path) -> list[Path]:
    raw_list = list(raw_roots)
    if not raw_list:
        raise LinkManagerError("at least one explicit --target-root is required")
    roots: list[Path] = []
    seen: set[Path] = set()
    for raw in raw_list:
        root = require_absolute(str(raw), "--target-root")
        if root.is_symlink():
            raise LinkManagerError(f"target root must be a real directory, not a symlink: {root}")
        try:
            resolved = root.resolve(strict=True)
        except FileNotFoundError as error:
            raise LinkManagerError(f"target root does not exist: {root}") from error
        if not resolved.is_dir():
            raise LinkManagerError(f"target root is not a directory: {resolved}")
        if is_within(resolved, repository) or is_within(repository, resolved):
            raise LinkManagerError(f"target root must be outside the canonical repository: {resolved}")
        if resolved in seen:
            raise LinkManagerError(f"duplicate target root: {resolved}")
        roots.append(resolved)
        seen.add(resolved)
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if is_within(root, other) or is_within(other, root):
                raise LinkManagerError(f"target roots must not be nested: {root} and {other}")
    return roots


def target_root_identity(root: Path) -> dict[str, int]:
    """Capture a target root without following a replacement symlink."""

    try:
        metadata = root.lstat()
    except FileNotFoundError as error:
        raise LinkManagerError(f"target root disappeared before it could be locked: {root}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LinkManagerError(f"target root is no longer a real directory: {root}")
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def revalidate_locked_root(locked: LockedRoot) -> None:
    """Require the selected path to still name the directory held by the lock."""

    expected = (locked.device, locked.inode)
    descriptor_metadata = os.fstat(locked.descriptor)
    if not stat.S_ISDIR(descriptor_metadata.st_mode) or (
        descriptor_metadata.st_dev,
        descriptor_metadata.st_ino,
    ) != expected:
        raise LinkManagerError(f"locked target root descriptor changed unexpectedly: {locked.path}")
    try:
        path_metadata = locked.path.lstat()
    except FileNotFoundError as error:
        raise LinkManagerError(f"target root path disappeared while locked: {locked.path}") from error
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISDIR(path_metadata.st_mode):
        raise LinkManagerError(f"target root path was replaced while locked: {locked.path}")
    if (path_metadata.st_dev, path_metadata.st_ino) != expected:
        raise LinkManagerError(f"target root identity changed while locked: {locked.path}")


@contextmanager
def lock_target_roots(
    roots: list[Path],
    *,
    expected_identities: list[dict[str, int]] | None = None,
) -> Iterator[list[LockedRoot]]:
    """Exclusively lock all roots in deterministic order and retain directory fds.

    Directory locks disappear automatically if the process is interrupted.  The
    retained descriptors also let mutations stay anchored to the selected
    directory even if an uncooperative process renames its path.
    """

    if expected_identities is None:
        expected_identities = [target_root_identity(root) for root in roots]
    if len(expected_identities) != len(roots):
        raise LinkManagerError("target-root identity count does not match target roots")
    expected_by_path = {root: expected_identities[index] for index, root in enumerate(roots)}
    acquired: dict[Path, LockedRoot] = {}
    try:
        for root in sorted(roots, key=lambda item: str(item)):
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(root, flags)
            except OSError as error:
                raise LinkManagerError(f"cannot safely open target root for locking: {root}: {error}") from error
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                metadata = os.fstat(descriptor)
                expected = expected_by_path[root]
                if not stat.S_ISDIR(metadata.st_mode) or (
                    metadata.st_dev != expected.get("device")
                    or metadata.st_ino != expected.get("inode")
                ):
                    raise LinkManagerError(f"target root identity changed before lock acquisition: {root}")
                locked = LockedRoot(root, descriptor, metadata.st_dev, metadata.st_ino)
                revalidate_locked_root(locked)
                acquired[root] = locked
            except BaseException:
                os.close(descriptor)
                raise
        ordered = [acquired[root] for root in roots]
        for locked in ordered:
            revalidate_locked_root(locked)
        yield ordered
    finally:
        for root in reversed(sorted(acquired, key=lambda item: str(item))):
            descriptor = acquired[root].descriptor
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def lexical_exists_at(locked: LockedRoot, name: str) -> bool:
    try:
        os.stat(name, dir_fd=locked.descriptor, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def fsync_locked_root(locked: LockedRoot) -> None:
    os.fsync(locked.descriptor)


def managed_skills(repository: Path, selected: Iterable[str] | None = None) -> list[str]:
    available = {
        path.name
        for path in (repository / "skills").iterdir()
        if path.is_dir() and not path.is_symlink() and (path / "SKILL.md").is_file()
    }
    if selected:
        names = set(selected)
        invalid = sorted(name for name in names if Path(name).name != name or name in {".", ".."})
        if invalid:
            raise LinkManagerError(f"invalid skill names: {', '.join(invalid)}")
        missing = sorted(names - available)
        if missing:
            raise LinkManagerError(f"skills are not canonical repository skills: {', '.join(missing)}")
        return sorted(names)
    if not available:
        raise LinkManagerError(f"no canonical skills found under {repository / 'skills'}")
    return sorted(available)


def resolved_link_target(path: Path) -> tuple[str, Path]:
    raw = os.readlink(path)
    target = Path(raw)
    if not target.is_absolute():
        target = path.parent / target
    return raw, target


def classify_installation(destination: Path, source: Path, source_digest: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "destination": str(destination),
        "source": str(source),
    }
    if destination.is_symlink():
        raw, target = resolved_link_target(destination)
        result["link_target"] = raw
        result["resolved_link_target"] = str(target.resolve(strict=False))
        if raw == str(source) and target == source and source.is_dir():
            result["status"] = "direct_link"
        elif target.is_symlink():
            result["status"] = "chained_link"
        elif not target.exists():
            result["status"] = "broken_link"
        else:
            result["status"] = "noncanonical_link"
        return result
    if destination.is_dir():
        installed_digest = tree_digest(destination)
        result["digest"] = installed_digest
        result["status"] = "copied_match" if installed_digest == source_digest else "divergent_directory"
        return result
    if not lexical_exists(destination):
        result["status"] = "missing"
        return result
    if destination.is_file():
        result["status"] = "unexpected_file"
        result["digest"] = hashlib.sha256(destination.read_bytes()).hexdigest()
        return result
    metadata = destination.lstat()
    result["status"] = "unexpected_object"
    result["object_type"] = stat.S_IFMT(metadata.st_mode)
    result["object_mode"] = stat.S_IMODE(metadata.st_mode)
    result["object_device"] = metadata.st_rdev
    return result


def build_plan_from_canonical(
    repository: Path,
    target_roots: list[Path],
    selected_skills: Iterable[str] | None = None,
) -> dict[str, Any]:
    skills = managed_skills(repository, selected_skills)
    digests = {name: tree_digest(repository / "skills" / name) for name in skills}
    entries: list[dict[str, Any]] = []
    for root_index, root in enumerate(target_roots):
        for skill in skills:
            entry = classify_installation(root / skill, repository / "skills" / skill, digests[skill])
            entry.update({"root_index": root_index, "target_root": str(root), "skill": skill})
            entries.append(entry)
    return {
        "version": VERSION,
        "repository_root": str(repository),
        "target_roots": [str(path) for path in target_roots],
        "skills": skills,
        "entries": entries,
    }


def build_plan(
    repository_raw: str | Path,
    target_roots_raw: Iterable[str | Path],
    selected_skills: Iterable[str] | None = None,
) -> dict[str, Any]:
    repository = canonical_repository(repository_raw)
    target_roots = canonical_target_roots(target_roots_raw, repository)
    return build_plan_from_canonical(repository, target_roots, selected_skills)


def direct_link_matches(destination: Path, source: Path) -> bool:
    if not destination.is_symlink():
        return False
    raw, target = resolved_link_target(destination)
    return raw == str(source) and target == source and source.is_dir()


def render_plan(plan: dict[str, Any]) -> str:
    lines = [f"canonical repository: {plan['repository_root']}"]
    for entry in plan["entries"]:
        lines.append(f"{entry['status']:<21} {entry['destination']}")
    counts: dict[str, int] = {}
    for entry in plan["entries"]:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    lines.append("summary: " + ", ".join(f"{name}={counts[name]}" for name in sorted(counts)))
    return "\n".join(lines)


def prepare_transaction(path_raw: str | Path, repository: Path, target_roots: list[Path]) -> Path:
    raw_path = require_absolute(str(path_raw), "--transaction-dir")
    if lexical_exists(raw_path):
        raise LinkManagerError(f"transaction directory already exists; refusing partial/stale transaction: {raw_path}")
    parent = raw_path.parent.resolve(strict=True)
    path = parent / raw_path.name
    if lexical_exists(path):
        raise LinkManagerError(f"transaction directory already exists; refusing partial/stale transaction: {path}")
    if is_within(path, repository) or any(is_within(path, root) for root in target_roots):
        raise LinkManagerError("transaction directory must be outside the repository and all target roots")
    different_filesystems = [root for root in target_roots if root.stat().st_dev != parent.stat().st_dev]
    if different_filesystems:
        raise LinkManagerError(
            "transaction directory must share a filesystem with every target root so backups use atomic rename: "
            + ", ".join(str(root) for root in different_filesystems)
        )
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    (path / "backups").mkdir(mode=0o700)
    os.chmod(path / "backups", 0o700)
    fsync_directory(path.parent)
    return path


def journal_entries(plan: dict[str, Any], transaction: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for entry in plan["entries"]:
        if entry["status"] == "direct_link":
            continue
        backup = transaction / "backups" / f"root-{entry['root_index']}" / entry["skill"]
        result.append(
            {
                "root_index": entry["root_index"],
                "target_root": entry["target_root"],
                "skill": entry["skill"],
                "destination": entry["destination"],
                "source": entry["source"],
                "backup": str(backup),
                "before": {key: value for key, value in entry.items() if key not in {"root_index", "target_root", "skill", "destination", "source"}},
                "stage": "pending",
            }
        )
    return result


def save_journal(transaction: Path, journal: dict[str, Any]) -> None:
    atomic_json_write(transaction / JOURNAL_NAME, journal)


def remove_path_at(locked: LockedRoot, name: str) -> None:
    """Remove one child without resolving the target-root path again."""

    metadata = os.stat(name, dir_fd=locked.descriptor, follow_symlinks=False)
    if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
        remove_tree_at(locked.descriptor, name)
    else:
        os.unlink(name, dir_fd=locked.descriptor)


def remove_tree_at(parent_descriptor: int, name: str) -> None:
    """Recursively unlink a real child directory using only descriptor-relative paths."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    child_descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        for child_name in os.listdir(child_descriptor):
            metadata = os.stat(child_name, dir_fd=child_descriptor, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                remove_tree_at(child_descriptor, child_name)
            else:
                os.unlink(child_name, dir_fd=child_descriptor)
        os.fsync(child_descriptor)
    finally:
        os.close(child_descriptor)
    os.rmdir(name, dir_fd=parent_descriptor)


def validate_journal(journal: dict[str, Any], transaction: Path) -> None:
    if journal.get("version") != VERSION:
        raise LinkManagerError("unsupported or missing transaction journal version")
    repository = Path(journal.get("repository_root", ""))
    roots = [Path(item) for item in journal.get("target_roots", [])]
    if not repository.is_absolute() or not roots:
        raise LinkManagerError("transaction journal has invalid repository or target roots")
    identities = journal.get("target_root_identities")
    if not isinstance(identities, list) or len(identities) != len(roots):
        raise LinkManagerError("transaction journal has invalid target-root identities")
    for identity in identities:
        if not isinstance(identity, dict) or not all(
            isinstance(identity.get(key), int) and identity[key] >= 0 for key in ("device", "inode")
        ):
            raise LinkManagerError("transaction journal contains an invalid target-root identity")
    for entry in journal.get("entries", []):
        skill = entry.get("skill", "")
        root_index = entry.get("root_index")
        if Path(skill).name != skill or not isinstance(root_index, int) or not 0 <= root_index < len(roots):
            raise LinkManagerError("transaction journal contains an invalid skill or root index")
        expected_destination = roots[root_index] / skill
        expected_source = repository / "skills" / skill
        expected_backup = transaction / "backups" / f"root-{root_index}" / skill
        if Path(entry.get("destination", "")) != expected_destination:
            raise LinkManagerError("transaction journal destination escaped its target root")
        if Path(entry.get("source", "")) != expected_source:
            raise LinkManagerError("transaction journal source escaped the canonical skills directory")
        if Path(entry.get("backup", "")) != expected_backup:
            raise LinkManagerError("transaction journal backup escaped its transaction directory")


def load_journal(transaction_raw: str | Path) -> tuple[Path, dict[str, Any]]:
    raw_transaction = require_absolute(str(transaction_raw), "--transaction-dir")
    if raw_transaction.is_symlink() or not raw_transaction.is_dir():
        raise LinkManagerError(f"transaction directory does not exist or is a symlink: {raw_transaction}")
    transaction = raw_transaction.resolve(strict=True)
    journal_path = transaction / JOURNAL_NAME
    if not journal_path.is_file() or journal_path.is_symlink():
        raise LinkManagerError(f"transaction journal does not exist or is unsafe: {journal_path}")
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LinkManagerError(f"cannot read transaction journal: {error}") from error
    if not isinstance(journal, dict):
        raise LinkManagerError("transaction journal must be a JSON object")
    validate_journal(journal, transaction)
    return transaction, journal


def matches_before(path: Path, before: dict[str, Any]) -> bool:
    status_name = before.get("status")
    if status_name == "missing":
        return not lexical_exists(path)
    if status_name in {"copied_match", "divergent_directory"}:
        return path.is_dir() and not path.is_symlink() and tree_digest(path) == before.get("digest")
    if status_name in {"direct_link", "chained_link", "broken_link", "noncanonical_link"}:
        return path.is_symlink() and os.readlink(path) == before.get("link_target")
    if status_name == "unexpected_file":
        return path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == before.get("digest")
    if status_name == "unexpected_object":
        if not lexical_exists(path):
            return False
        metadata = path.lstat()
        return (
            stat.S_IFMT(metadata.st_mode) == before.get("object_type")
            and stat.S_IMODE(metadata.st_mode) == before.get("object_mode")
            and metadata.st_rdev == before.get("object_device")
        )
    return lexical_exists(path)


def preflight_rollback(
    journal: dict[str, Any],
    locked_roots: list[LockedRoot],
    *,
    force: bool,
) -> None:
    for entry in reversed(journal.get("entries", [])):
        if entry.get("stage") == "concurrent_change_preserved":
            continue
        locked = locked_roots[entry["root_index"]]
        revalidate_locked_root(locked)
        destination = Path(entry["destination"])
        source = Path(entry["source"])
        backup = Path(entry["backup"])
        before = entry.get("before", {})
        backup_exists = lexical_exists(backup)
        destination_exists = lexical_exists_at(locked, entry["skill"])
        if backup_exists and not matches_before(backup, before):
            raise LinkManagerError(f"transaction backup no longer matches its recorded pre-apply state: {backup}")
        if backup_exists and destination_exists and not force and not direct_link_matches(destination, source):
            raise LinkManagerError(f"refusing to overwrite a post-apply change during rollback: {destination}")
        if not backup_exists and before.get("status") == "missing":
            if destination_exists and not force and not direct_link_matches(destination, source):
                raise LinkManagerError(f"refusing to remove a post-apply change during rollback: {destination}")
        elif not backup_exists and entry.get("stage") not in {"pending", "prepared", "rolled_back"}:
            if not matches_before(destination, before):
                raise LinkManagerError(f"transaction backup is missing for {destination}; manual recovery required")


def rollback_locked(
    transaction: Path,
    journal: dict[str, Any],
    locked_roots: list[LockedRoot],
    *,
    force: bool,
) -> dict[str, Any]:
    if journal.get("status") == "rolled_back":
        return journal
    preflight_rollback(journal, locked_roots, force=force)
    journal["status"] = "rolling_back"
    save_journal(transaction, journal)
    for entry in reversed(journal.get("entries", [])):
        if entry.get("stage") == "concurrent_change_preserved":
            continue
        locked = locked_roots[entry["root_index"]]
        revalidate_locked_root(locked)
        destination = Path(entry["destination"])
        source = Path(entry["source"])
        backup = Path(entry["backup"])
        before = entry.get("before", {})
        before_status = before.get("status")
        backup_exists = lexical_exists(backup)
        destination_exists = lexical_exists_at(locked, entry["skill"])

        if backup_exists:
            if destination_exists:
                if not force and not direct_link_matches(destination, source):
                    raise LinkManagerError(f"refusing to overwrite a post-apply change during rollback: {destination}")
                remove_path_at(locked, entry["skill"])
            os.replace(backup, entry["skill"], dst_dir_fd=locked.descriptor)
            fsync_locked_root(locked)
        elif before_status == "missing":
            if destination_exists:
                if not force and not direct_link_matches(destination, source):
                    raise LinkManagerError(f"refusing to remove a post-apply change during rollback: {destination}")
                remove_path_at(locked, entry["skill"])
                fsync_locked_root(locked)
        elif entry.get("stage") not in {"pending", "prepared", "rolled_back"}:
            if not matches_before(destination, before):
                raise LinkManagerError(f"transaction backup is missing for {destination}; manual recovery required")
        if not matches_before(destination, before):
            raise LinkManagerError(f"rollback did not restore the recorded pre-apply state: {destination}")
        entry["stage"] = "rolled_back"
        save_journal(transaction, journal)
    journal["status"] = "rolled_back"
    save_journal(transaction, journal)
    return journal


def rollback_transaction(transaction_raw: str | Path, *, force: bool = False) -> dict[str, Any]:
    transaction, journal = load_journal(transaction_raw)
    if journal.get("status") == "rolled_back":
        return journal
    roots = [Path(item) for item in journal["target_roots"]]
    identities = journal["target_root_identities"]
    with lock_target_roots(roots, expected_identities=identities) as locked_roots:
        return rollback_locked(transaction, journal, locked_roots, force=force)


def apply_links(
    repository_raw: str | Path,
    target_roots_raw: Iterable[str | Path],
    transaction_raw: str | Path,
    *,
    selected_skills: Iterable[str] | None = None,
    allow_noncanonical: bool = False,
    failure_after: int | None = None,
) -> dict[str, Any]:
    repository = canonical_repository(repository_raw)
    roots = canonical_target_roots(target_roots_raw, repository)
    initial_identities = [target_root_identity(root) for root in roots]
    with lock_target_roots(roots, expected_identities=initial_identities) as locked_roots:
        # The mutating plan is deliberately built only after every root lock is
        # held. A concurrent invocation therefore replans the state left by the
        # first invocation instead of acting on the same stale directories.
        plan = build_plan_from_canonical(repository, roots, selected_skills)
        unsafe = [entry for entry in plan["entries"] if entry["status"] not in SAFE_APPLY_STATES]
        if unsafe and not allow_noncanonical:
            details = ", ".join(f"{entry['status']}:{entry['destination']}" for entry in unsafe)
            raise LinkManagerError(
                "refusing divergent, broken, chained, or unexpected installations without "
                f"--allow-noncanonical after review: {details}"
            )
        transaction = prepare_transaction(transaction_raw, repository, roots)
        for locked in locked_roots:
            revalidate_locked_root(locked)
        journal: dict[str, Any] = {
            "version": VERSION,
            "status": "prepared",
            "repository_root": str(repository),
            "target_roots": [str(path) for path in roots],
            "target_root_identities": [locked.journal_identity() for locked in locked_roots],
            "skills": plan["skills"],
            "entries": journal_entries(plan, transaction),
        }
        save_journal(transaction, journal)
        journal["status"] = "applying"
        save_journal(transaction, journal)
        linked = 0
        try:
            for entry in journal["entries"]:
                locked = locked_roots[entry["root_index"]]
                revalidate_locked_root(locked)
                destination = Path(entry["destination"])
                source = Path(entry["source"])
                backup = Path(entry["backup"])
                backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(backup.parent, 0o700)
                entry["stage"] = "prepared"
                save_journal(transaction, journal)

                # Recheck the exact planned state immediately before moving it.
                # A newly-created or edited entry remains in place and is never
                # mistaken for the object that the user approved for backup.
                if not matches_before(destination, entry["before"]):
                    entry["stage"] = "concurrent_change_preserved"
                    save_journal(transaction, journal)
                    raise LinkManagerError(f"installation changed after planning; refusing to move it: {destination}")

                if lexical_exists_at(locked, entry["skill"]):
                    if lexical_exists(backup):
                        raise LinkManagerError(f"transaction backup path unexpectedly exists: {backup}")
                    os.replace(entry["skill"], backup, src_dir_fd=locked.descriptor)
                    fsync_locked_root(locked)
                    fsync_directory(backup.parent)
                    if not matches_before(backup, entry["before"]):
                        # An uncooperative writer raced the immediate check. Put
                        # the moved object back without overwriting anything it
                        # created afterward, then leave this entry out of rollback.
                        if not lexical_exists_at(locked, entry["skill"]):
                            os.replace(backup, entry["skill"], dst_dir_fd=locked.descriptor)
                            fsync_locked_root(locked)
                            entry["stage"] = "concurrent_change_preserved"
                            save_journal(transaction, journal)
                        raise LinkManagerError(f"installation changed during backup; preserved it: {destination}")
                    entry["stage"] = "backup_moved"
                    save_journal(transaction, journal)

                temporary_name = f".{entry['skill']}.holyskills-{uuid.uuid4().hex}"
                try:
                    os.symlink(str(source), temporary_name, dir_fd=locked.descriptor)
                    os.replace(
                        temporary_name,
                        entry["skill"],
                        src_dir_fd=locked.descriptor,
                        dst_dir_fd=locked.descriptor,
                    )
                finally:
                    if lexical_exists_at(locked, temporary_name):
                        os.unlink(temporary_name, dir_fd=locked.descriptor)
                fsync_locked_root(locked)
                entry["stage"] = "linked"
                save_journal(transaction, journal)
                revalidate_locked_root(locked)
                if not direct_link_matches(destination, source):
                    raise LinkManagerError(f"direct link verification failed immediately after apply: {destination}")
                linked += 1
                if failure_after is not None and linked >= failure_after:
                    raise RuntimeError("injected partial apply failure")

            for plan_entry in plan["entries"]:
                locked = locked_roots[plan_entry["root_index"]]
                revalidate_locked_root(locked)
                if not direct_link_matches(Path(plan_entry["destination"]), Path(plan_entry["source"])):
                    raise LinkManagerError(f"final direct link verification failed: {plan_entry['destination']}")
            journal["status"] = "applied"
            save_journal(transaction, journal)
            return journal
        except BaseException as error:
            journal["status"] = "rollback_pending"
            journal["error"] = f"{type(error).__name__}: {error}"
            save_journal(transaction, journal)
            try:
                rollback_locked(transaction, journal, locked_roots, force=False)
            except BaseException as rollback_error:
                raise LinkManagerError(
                    f"apply failed ({error}); automatic rollback also failed ({rollback_error}); inspect {transaction}"
                ) from rollback_error
            raise LinkManagerError(f"apply failed and was rolled back: {error}") from error


def add_repository_arguments(parser: argparse.ArgumentParser, *, transaction: bool = False) -> None:
    parser.add_argument(
        "--repo-root",
        default=str(REPOSITORY_ROOT),
        help="Canonical repository root (defaults to the repository containing this script).",
    )
    parser.add_argument(
        "--target-root",
        action="append",
        required=True,
        help="Absolute skills installation root; repeat for every runtime. Never inferred from HOME.",
    )
    parser.add_argument("--skill", action="append", help="Manage one canonical skill; repeat as needed.")
    if transaction:
        parser.add_argument("--transaction-dir", required=True, help="New absolute directory for journal and backups.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan", help="Inspect topology without changing it.")
    add_repository_arguments(plan_parser)
    verify_parser = subparsers.add_parser("verify", help="Require every managed path to be a direct canonical link.")
    add_repository_arguments(verify_parser)
    apply_parser = subparsers.add_parser("apply", help="Atomically install direct links with rollback backups.")
    add_repository_arguments(apply_parser, transaction=True)
    apply_parser.add_argument(
        "--allow-noncanonical",
        action="store_true",
        help="After reviewing plan output, preserve and replace divergent/broken/chained/unexpected paths.",
    )
    rollback_parser = subparsers.add_parser("rollback", help="Restore the exact pre-apply paths from a transaction.")
    rollback_parser.add_argument("--transaction-dir", required=True, help="Absolute transaction directory.")
    rollback_parser.add_argument("--force", action="store_true", help="Overwrite changes made after apply.")
    rollback_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "rollback":
            result = rollback_transaction(args.transaction_dir, force=args.force)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else f"transaction {result['status']}: {args.transaction_dir}")
            return 0
        plan = build_plan(args.repo_root, args.target_root, args.skill)
        if args.command == "plan":
            print(json.dumps(plan, indent=2, sort_keys=True) if args.json else render_plan(plan))
            return 0
        if args.command == "verify":
            failures = [entry for entry in plan["entries"] if entry["status"] != "direct_link"]
            print(json.dumps(plan, indent=2, sort_keys=True) if args.json else render_plan(plan))
            return 1 if failures else 0
        result = apply_links(
            args.repo_root,
            args.target_root,
            args.transaction_dir,
            selected_skills=args.skill,
            allow_noncanonical=args.allow_noncanonical,
        )
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else f"transaction applied: {args.transaction_dir}")
        return 0
    except LinkManagerError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
