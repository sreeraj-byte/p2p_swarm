"""Unit tests for metadata construction, canonicalization, and Section 14.5 path safety.

Covers:
- Section 6: Deterministic canonicalization, Swarm ID, slice arithmetic
- Section 14.5: Exhaustive path safety tests (traversal, colons, Windows reserved names, etc.)
- Section 17: Malicious metadata rejection, empty folder rejection, disk space checks
"""

import hashlib
import json
import os
from pathlib import Path
import pytest

from common.metadata import (
    MetadataValidationError,
    build_metadata,
    calculate_piece_arithmetic,
    canonicalize_metadata,
    compute_swarm_id,
    compute_swarm_id_short,
    map_piece_to_slices,
    validate_metadata,
    validate_path_component,
    validate_relative_path,
)
import config


def test_deterministic_canonicalization() -> None:
    """Verify that different dictionary key insertion orders yield identical canonical bytes."""
    meta1 = {
        "version": 1,
        "root": "shared",
        "total_size": 100,
        "piece_size": 65536,
        "piece_hashes": ["a" * 64],
        "files": [{"path": "a.txt", "length": 100, "sha256": "b" * 64}],
    }
    # Reverse key order
    meta2 = {
        "files": [{"sha256": "b" * 64, "path": "a.txt", "length": 100}],
        "piece_hashes": ["a" * 64],
        "piece_size": 65536,
        "total_size": 100,
        "root": "shared",
        "version": 1,
    }

    canon1 = canonicalize_metadata(meta1)
    canon2 = canonicalize_metadata(meta2)

    assert canon1 == canon2
    assert compute_swarm_id(meta1) == compute_swarm_id(meta2)
    assert compute_swarm_id_short(compute_swarm_id(meta1)) == compute_swarm_id(meta1)[:16]


def test_piece_arithmetic() -> None:
    """Test piece count calculations according to Section 6.3."""
    # 0 bytes -> 0 pieces
    assert calculate_piece_arithmetic(0, 65536) == 0
    # Exactly one piece
    assert calculate_piece_arithmetic(65536, 65536) == 1
    # One byte over one piece
    assert calculate_piece_arithmetic(65537, 65536) == 2
    # Multiple full pieces
    assert calculate_piece_arithmetic(131072, 65536) == 2


@pytest.mark.parametrize(
    "bad_path",
    [
        "/absolute/path.txt",
        "C:/drive/file.txt",
        "D:\\drive\\file.txt",
        "relative/../traversal.txt",
        "../escape.txt",
        "nested/./dot.txt",
        "double//slash.txt",
        "with\\backslash.txt",
        "colon:stream.txt",
        "null\x00byte.txt",
        "control\x1fcharacter.txt",
        "ends_with_dot.",
        "ends_with_space ",
        "folder /file.txt",
        "folder./file.txt",
        "CON",
        "con.txt",
        "AUX",
        "aux.pdf",
        "NUL",
        "COM1",
        "com9.dat",
        "LPT1",
        "lpt5.log",
        "a" * 256,  # Component > 255 bytes
    ],
)
def test_path_safety_rejections(bad_path: str) -> None:
    """Section 14.5: Ensure all dangerous or malformed path components are rejected."""
    with pytest.raises(MetadataValidationError):
        validate_relative_path(bad_path)


def test_reject_case_colliding_duplicate_paths() -> None:
    """Section 14.5: Reject duplicate paths, including case-insensitive collisions."""
    valid_hash = "a" * 64
    meta = {
        "version": 1,
        "root": "shared",
        "piece_size": 65536,
        "total_size": 200,
        "files": [
            {"path": "Folder/Doc.txt", "length": 100, "sha256": valid_hash},
            {"path": "folder/doc.txt", "length": 100, "sha256": valid_hash},
        ],
        "piece_hashes": [valid_hash],
    }
    with pytest.raises(MetadataValidationError, match="Duplicate or case-colliding"):
        validate_metadata(meta)


def test_reject_total_size_mismatch() -> None:
    """Metadata validation must reject when total_size does not match sum of file lengths."""
    valid_hash = "a" * 64
    meta = {
        "version": 1,
        "root": "shared",
        "piece_size": 65536,
        "total_size": 500,  # Mismatch: sum of files is 300
        "files": [
            {"path": "f1.txt", "length": 100, "sha256": valid_hash},
            {"path": "f2.txt", "length": 200, "sha256": valid_hash},
        ],
        "piece_hashes": [valid_hash],
    }
    with pytest.raises(MetadataValidationError, match="does not match sum of file lengths"):
        validate_metadata(meta)


def test_reject_piece_hashes_count_mismatch() -> None:
    """Metadata validation must reject if piece_hashes count != expected pieces."""
    valid_hash = "a" * 64
    meta = {
        "version": 1,
        "root": "shared",
        "piece_size": 65536,
        "total_size": 100000,  # Needs 2 pieces (65536 + 34464)
        "files": [{"path": "f1.txt", "length": 100000, "sha256": valid_hash}],
        "piece_hashes": [valid_hash],  # Provided only 1 piece hash
    }
    with pytest.raises(MetadataValidationError, match="does not match expected pieces"):
        validate_metadata(meta)


def test_build_metadata_from_directory(tmp_path: Path) -> None:
    """Test build_metadata correctly builds canonical metadata, hashes, and ignores symlinks."""
    shared_dir = tmp_path / "test_shared"
    shared_dir.mkdir()

    # Create nested structure
    sub = shared_dir / "notes"
    sub.mkdir()
    f1 = sub / "doc.txt"
    f1.write_bytes(b"A" * 1000)

    f2 = shared_dir / "zero.dat"
    f2.write_bytes(b"")

    f3 = shared_dir / "large.bin"
    f3.write_bytes(b"B" * 70000)

    # Create a symlink pointing to f1 (must be skipped per Section 8.3)
    symlink_file = shared_dir / "link.txt"
    try:
        symlink_file.symlink_to(f1)
    except (OSError, NotImplementedError):
        pass  # Skip if OS / permissions don't allow symlinks

    meta, canonical_bytes, swarm_id = build_metadata(shared_dir, piece_size=65536)

    assert meta["root"] == "test_shared"
    assert meta["total_size"] == 71000
    # Files must be sorted deterministically by POSIX relative path
    paths = [f["path"] for f in meta["files"]]
    assert paths == sorted(paths)
    assert "large.bin" in paths
    assert "notes/doc.txt" in paths
    assert "zero.dat" in paths
    assert "link.txt" not in paths  # Symlink was skipped!

    # Validate output
    validate_metadata(meta, out_dir=tmp_path)


def test_build_metadata_single_file(tmp_path: Path) -> None:
    """Single file sharing: root must be empty string per Section 6.4."""
    file_path = tmp_path / "single.mp4"
    file_path.write_bytes(b"VideoPayload" * 5000)

    meta, _, swarm_id = build_metadata(file_path, piece_size=65536)
    assert meta["root"] == ""
    assert len(meta["files"]) == 1
    assert meta["files"][0]["path"] == "single.mp4"
    assert meta["total_size"] == len(file_path.read_bytes())


def test_build_metadata_empty_dir_fails(tmp_path: Path) -> None:
    """Building metadata on an empty directory must raise ValueError."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    with pytest.raises(ValueError, match="No valid, readable files"):
        build_metadata(empty_dir)


def test_build_metadata_skips_symlinks_unreadable_and_os_artifacts(tmp_path: Path) -> None:
    """Folder scanner must skip symlinked files/dirs, unreadable files, and OS artifacts
    (.DS_Store, Thumbs.db, desktop.ini).
    """
    src_dir = tmp_path / "sender_folder"
    src_dir.mkdir()

    # Valid files
    (src_dir / "valid1.txt").write_bytes(b"ValidContent1")
    sub = src_dir / "subdir"
    sub.mkdir()
    (sub / "valid2.txt").write_bytes(b"ValidContent2")

    # OS artifacts to skip
    (src_dir / ".DS_Store").write_bytes(b"macOS metadata")
    (src_dir / "Thumbs.db").write_bytes(b"Windows thumbnail cache")
    (sub / "desktop.ini").write_bytes(b"Windows folder icon")
    (sub / ".ds_store").write_bytes(b"lowercase mac artifact")

    # Symlinked file
    symlink_file = src_dir / "sym_file.txt"
    try:
        symlink_file.symlink_to(src_dir / "valid1.txt")
    except (OSError, NotImplementedError):
        pass

    # Symlinked directory
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_bytes(b"Secret")
    symlink_dir = src_dir / "sym_dir"
    try:
        symlink_dir.symlink_to(outside_dir)
    except (OSError, NotImplementedError):
        pass

    # Unreadable file simulation (chmod 000 on Unix)
    unreadable = src_dir / "unreadable.dat"
    unreadable.write_bytes(b"CannotReadMe")
    try:
        unreadable.chmod(0o000)
    except OSError:
        pass

    try:
        meta, _, _ = build_metadata(src_dir, piece_size=config.MIN_PIECE_SIZE)
        paths = [f["path"] for f in meta["files"]]

        # Valid files must be included
        assert "valid1.txt" in paths
        assert "subdir/valid2.txt" in paths

        # OS artifacts must NOT be included
        assert ".DS_Store" not in paths
        assert "Thumbs.db" not in paths
        assert "subdir/desktop.ini" not in paths
        assert "subdir/.ds_store" not in paths

        # Symlinks must NOT be included
        assert "sym_file.txt" not in paths
        assert not any(p.startswith("sym_dir") for p in paths)

        # Unreadable file must NOT be included if permissions prevented read
        if not os.access(str(unreadable), os.R_OK):
            assert "unreadable.dat" not in paths
    finally:
        try:
            unreadable.chmod(0o644)
        except OSError:
            pass


def _make_base_valid_metadata() -> dict:
    valid_hash = "a" * 64
    return {
        "version": 1,
        "root": "shared",
        "piece_size": config.MIN_PIECE_SIZE,
        "total_size": 100,
        "files": [{"path": "doc.txt", "length": 100, "sha256": valid_hash}],
        "piece_hashes": [valid_hash],
    }


def test_validation_rule_version() -> None:
    """Section 6.5: Version must strictly be integer 1."""
    meta = _make_base_valid_metadata()

    # Wrong version number
    meta["version"] = 2
    with pytest.raises(MetadataValidationError, match="version"):
        validate_metadata(meta)

    # Version 0
    meta["version"] = 0
    with pytest.raises(MetadataValidationError, match="version"):
        validate_metadata(meta)

    # Boolean True (which is an int in Python if not checked strictly)
    meta["version"] = True
    with pytest.raises(MetadataValidationError, match="version"):
        validate_metadata(meta)

    # String version
    meta["version"] = "1"
    with pytest.raises(MetadataValidationError, match="version"):
        validate_metadata(meta)


@pytest.mark.parametrize("missing_key", ["version", "root", "piece_size", "total_size", "files", "piece_hashes"])
def test_validation_rule_missing_fields(missing_key: str) -> None:
    """Section 6.5: All top-level fields are mandatory."""
    meta = _make_base_valid_metadata()
    del meta[missing_key]
    with pytest.raises(MetadataValidationError, match="missing required keys"):
        validate_metadata(meta)


def test_validation_rule_wrong_types() -> None:
    """Section 6.5: Field types must be strictly checked."""
    # root must be string
    meta = _make_base_valid_metadata()
    meta["root"] = 12345
    with pytest.raises(MetadataValidationError, match="'root' must be a string"):
        validate_metadata(meta)

    # files must be a list
    meta = _make_base_valid_metadata()
    meta["files"] = {"path": "doc.txt"}
    with pytest.raises(MetadataValidationError, match="'files' must be a list"):
        validate_metadata(meta)

    # file entry must be a dictionary
    meta = _make_base_valid_metadata()
    meta["files"] = ["not-a-dict"]
    with pytest.raises(MetadataValidationError, match="not a dictionary"):
        validate_metadata(meta)

    # file path must be string
    meta = _make_base_valid_metadata()
    meta["files"][0]["path"] = 100
    with pytest.raises(MetadataValidationError, match="'path' must be a string"):
        validate_metadata(meta)

    # file length must be non-negative integer
    meta = _make_base_valid_metadata()
    meta["files"][0]["length"] = -5
    with pytest.raises(MetadataValidationError, match="invalid length"):
        validate_metadata(meta)

    meta["files"][0]["length"] = "100"
    with pytest.raises(MetadataValidationError, match="invalid length"):
        validate_metadata(meta)

    # total_size must be int
    meta = _make_base_valid_metadata()
    meta["total_size"] = "100"
    with pytest.raises(MetadataValidationError, match="total_size"):
        validate_metadata(meta)

    # piece_hashes must be list
    meta = _make_base_valid_metadata()
    meta["piece_hashes"] = "a" * 64
    with pytest.raises(MetadataValidationError, match="piece_hashes"):
        validate_metadata(meta)


def test_validation_rule_piece_size_range() -> None:
    """Section 6.5: piece_size must be in [MIN_PIECE_SIZE, MAX_PIECE_SIZE]."""
    meta = _make_base_valid_metadata()

    # Smaller than minimum (16 KiB - 1)
    meta["piece_size"] = config.MIN_PIECE_SIZE - 1
    with pytest.raises(MetadataValidationError, match="out of allowed range"):
        validate_metadata(meta)

    # Larger than maximum (4 MiB + 1)
    meta["piece_size"] = config.MAX_PIECE_SIZE + 1
    with pytest.raises(MetadataValidationError, match="out of allowed range"):
        validate_metadata(meta)

    # Non-integer piece size
    meta["piece_size"] = float(config.DEFAULT_PIECE_SIZE)
    with pytest.raises(MetadataValidationError, match="out of allowed range"):
        validate_metadata(meta)


def test_validation_rule_max_files() -> None:
    """Section 6.5: Number of files cannot exceed MAX_FILES (10000)."""
    meta = _make_base_valid_metadata()
    # Mock files list exceeding MAX_FILES
    fake_files = [{"path": f"f{i}.txt", "length": 0, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} for i in range(config.MAX_FILES + 1)]
    meta["files"] = fake_files
    meta["total_size"] = 0
    meta["piece_hashes"] = []
    with pytest.raises(MetadataValidationError, match="exceeds MAX_FILES"):
        validate_metadata(meta)


def test_validation_rule_max_total_bytes() -> None:
    """Section 6.5: total_size cannot exceed MAX_TOTAL_BYTES (50 GiB)."""
    meta = _make_base_valid_metadata()
    too_large = config.MAX_TOTAL_BYTES + 1
    meta["total_size"] = too_large
    meta["files"] = [{"path": "huge.dat", "length": too_large, "sha256": "a" * 64}]
    meta["piece_hashes"] = ["a" * 64] * calculate_piece_arithmetic(too_large, meta["piece_size"])
    with pytest.raises(MetadataValidationError, match="exceeds MAX_TOTAL_BYTES"):
        validate_metadata(meta)


def test_validation_rule_max_pieces() -> None:
    """Section 6.5: Piece count cannot exceed MAX_PIECES (100000)."""
    meta = _make_base_valid_metadata()
    # 100001 pieces with MIN_PIECE_SIZE = 16384 -> total_size = 100001 * 16384
    too_many_pieces = config.MAX_PIECES + 1
    total_size = too_many_pieces * config.MIN_PIECE_SIZE
    meta["total_size"] = total_size
    meta["files"] = [{"path": "big.bin", "length": total_size, "sha256": "a" * 64}]
    meta["piece_hashes"] = ["a" * 64] * too_many_pieces
    with pytest.raises(MetadataValidationError, match="exceeds MAX_PIECES"):
        validate_metadata(meta)


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "a" * 63,         # 63 chars (too short)
        "a" * 65,         # 65 chars (too long)
        "a" * 63 + "G",   # Non-hex char 'G'
        "A" * 64,         # Uppercase hex (must be lowercase hex)
        "a" * 60 + "!!!!",# Punctuation
    ],
)
def test_validation_rule_64_hex_hashes(invalid_hash: str) -> None:
    """Section 6.5: All file and piece hashes must be lowercase 64-hex SHA-256 strings."""
    # Test invalid piece hash
    meta = _make_base_valid_metadata()
    meta["piece_hashes"] = [invalid_hash]
    with pytest.raises(MetadataValidationError, match="Piece hash .* is invalid"):
        validate_metadata(meta)

    # Test invalid file hash
    meta = _make_base_valid_metadata()
    meta["files"][0]["sha256"] = invalid_hash
    with pytest.raises(MetadataValidationError, match="invalid sha256 hash"):
        validate_metadata(meta)


def test_validation_rule_insufficient_disk_space(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Section 6.5: Reject if available disk space is less than total_size."""
    meta = _make_base_valid_metadata()
    total_len = 10_000_000  # 10 MB required
    meta["total_size"] = total_len
    meta["files"][0]["length"] = total_len
    num_pieces = calculate_piece_arithmetic(total_len, meta["piece_size"])
    meta["piece_hashes"] = ["a" * 64] * num_pieces

    # Mock shutil.disk_usage to return only 5 MB free
    from collections import namedtuple
    Usage = namedtuple("Usage", ["total", "used", "free"])
    monkeypatch.setattr("shutil.disk_usage", lambda path: Usage(total=20_000_000, used=15_000_000, free=5_000_000))

    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(MetadataValidationError, match="Insufficient disk space"):
        validate_metadata(meta, out_dir=dest)


def test_unicode_normalization_and_collision_rejection(tmp_path: Path) -> None:
    """Verify Section 14.5 & cross-platform Unicode normalization (NFC/NFD collision detection)."""
    import unicodedata

    # cafe with accent: NFC vs NFD
    nfc_name = unicodedata.normalize("NFC", "caf\u00e9.txt")
    nfd_name = unicodedata.normalize("NFD", "caf\u00e9.txt")
    assert nfc_name != nfd_name  # Different byte/character representations

    # 1. Collision detection in validate_metadata
    meta = _make_base_valid_metadata()
    meta["files"] = [
        {"path": nfc_name, "length": 100, "sha256": "0" * 64},
        {"path": nfd_name, "length": 200, "sha256": "1" * 64},
    ]
    meta["total_size"] = 300
    meta["piece_hashes"] = ["a" * 64]
    with pytest.raises(MetadataValidationError, match="Duplicate or case-colliding file path"):
        validate_metadata(meta)

    # 2. Folder scanning normalizes NFD filenames to NFC
    folder = tmp_path / "unicode_share"
    folder.mkdir()
    (folder / nfd_name).write_bytes(b"CafeContent")

    built_meta, _, _ = build_metadata(folder)
    assert len(built_meta["files"]) == 1
    # Path in metadata must be canonical NFC
    assert built_meta["files"][0]["path"] == nfc_name
    assert unicodedata.is_normalized("NFC", built_meta["files"][0]["path"])

