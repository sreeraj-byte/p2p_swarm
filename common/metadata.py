"""Metadata generation, canonicalization, piece arithmetic, and path safety validation.

This module implements Section 6 and Section 14.5 of PROJECT_SPEC.md.
"""

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Set, Tuple
import unicodedata

import config


class MetadataValidationError(Exception):
    """Raised when metadata fails semantic, structural, or path-safety validation."""
    pass


# Windows reserved device names (Section 14.5)
_WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

# Regex to check for 64-character lowercase hex strings (SHA-256)
_HEX64_REGEX = re.compile(r"^[0-9a-f]{64}$")

# OS artifacts ignored by the folder scanner
IGNORED_FILENAMES: Set[str] = {
    ".ds_store",
    "thumbs.db",
    "desktop.ini",
}


@dataclass(frozen=True)
class FileSlice:
    """Represents an overlap between a piece and a specific file in the continuous stream.

    Attributes:
        file_index: The 0-based index of the file in metadata['files'].
        rel_path: The relative path of the file as declared in metadata.
        offset_in_file: Byte offset within the file where this slice begins.
        length: Number of bytes from this file belonging to the piece.
    """
    file_index: int
    rel_path: str
    offset_in_file: int
    length: int


def validate_path_component(component: str) -> None:
    """Validate a single path component against Section 14.5 security rules.

    Args:
        component: Path segment (e.g. filename or directory name).

    Raises:
        MetadataValidationError: If the component violates security rules.
    """
    if not component or component == "." or component == "..":
        raise MetadataValidationError(f"Invalid path component: '{component}'")

    if "\\" in component or ":" in component:
        raise MetadataValidationError(f"Path component contains illegal backslash or colon: '{component}'")

    # Check for NUL or ASCII control characters (< 32)
    for ch in component:
        if ord(ch) < 32:
            raise MetadataValidationError(f"Path component contains ASCII control characters: {repr(component)}")

    # Component length cap: 255 bytes in UTF-8
    if len(component.encode("utf-8")) > 255:
        raise MetadataValidationError(f"Path component exceeds 255 bytes: '{component[:20]}...'")

    # Reject components ending with a dot or space
    if component.endswith(".") or component.endswith(" "):
        raise MetadataValidationError(f"Path component cannot end with dot or space: '{component}'")

    # Reject Windows reserved device names (e.g. CON, AUX, COM1, NUL with or without extension)
    base_name = component.split(".")[0].upper()
    if base_name in _WINDOWS_RESERVED_NAMES:
        raise MetadataValidationError(f"Path component matches Windows reserved name: '{component}'")


def validate_relative_path(path_str: str) -> None:
    """Validate a full relative path against Section 14.5 security requirements.

    Args:
        path_str: POSIX relative path (e.g. 'notes/lecture.pdf').

    Raises:
        MetadataValidationError: If path is unsafe or malformed.
    """
    if not path_str or not isinstance(path_str, str):
        raise MetadataValidationError("Path must be a non-empty string.")

    if path_str.startswith("/") or "\\" in path_str or ":" in path_str:
        raise MetadataValidationError(f"Path must be relative with POSIX forward slashes: '{path_str}'")

    # Split into components and validate each
    components = path_str.split("/")
    for comp in components:
        validate_path_component(comp)


def canonicalize_metadata(metadata: Dict[str, Any]) -> bytes:
    """Convert a metadata dictionary into canonical UTF-8 JSON bytes (Section 6.4).

    Canonical format ensures deterministic hashing:
      json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    Args:
        metadata: Metadata dictionary.

    Returns:
        Canonical UTF-8 encoded bytes.
    """
    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_swarm_id(metadata: Dict[str, Any]) -> str:
    """Compute the Swarm ID (SHA-256 hex digest of canonical metadata bytes).

    The Swarm ID is strictly computed from canonical metadata and is never
    embedded inside the metadata itself.

    Args:
        metadata: Metadata dictionary.

    Returns:
        64-character lowercase hex string.
    """
    canonical_bytes = canonicalize_metadata(metadata)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_swarm_id_short(swarm_id: str) -> str:
    """Return the first 16 hex characters of a Swarm ID (used in UDP discovery)."""
    return swarm_id[:16]


def calculate_piece_arithmetic(total_size: int, piece_size: int) -> int:
    """Calculate the expected number of pieces for a given total size and piece size.

    Args:
        total_size: Total continuous stream size in bytes.
        piece_size: Byte size of a full piece.

    Returns:
        Number of pieces (0 if total_size == 0).
    """
    if total_size <= 0:
        return 0
    return math.ceil(total_size / piece_size)


def get_file_stream_offsets(files: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
    """Compute start and end byte offsets for each file in the continuous stream.

    Returns:
        List of (start_offset, end_offset) tuples for each file in files.
    """
    offsets = []
    current_offset = 0
    for f in files:
        length = f["length"]
        offsets.append((current_offset, current_offset + length))
        current_offset += length
    return offsets


def map_piece_to_slices(metadata: Dict[str, Any], piece_index: int) -> List[FileSlice]:
    """Map a piece index to the list of file slices it spans in the continuous byte stream.

    In P2P Swarm, all files are concatenated into one continuous virtual stream.
    A piece may cover:
      - A part of a single file
      - Multiple contiguous files (e.g. if files are small)
      - The end of one file and the start of the next file
    Empty (0-byte) files occupy 0 bytes in the stream and do not produce slices.

    Args:
        metadata: Validated metadata dictionary.
        piece_index: 0-based piece index.

    Returns:
        List of FileSlice objects detailing file index, relative path, offset in file, and length.

    Raises:
        IndexError: If piece_index is out of range.
    """
    total_size = metadata["total_size"]
    piece_size = metadata["piece_size"]
    num_pieces = calculate_piece_arithmetic(total_size, piece_size)

    if piece_index < 0 or piece_index >= num_pieces:
        raise IndexError(f"Piece index {piece_index} out of range [0, {num_pieces})")

    # Byte interval of this piece in the virtual continuous stream: [piece_start, piece_end)
    piece_start = piece_index * piece_size
    piece_end = min((piece_index + 1) * piece_size, total_size)

    slices: List[FileSlice] = []
    current_stream_pos = 0

    for idx, file_info in enumerate(metadata["files"]):
        file_len = file_info["length"]
        file_start = current_stream_pos
        file_end = current_stream_pos + file_len
        current_stream_pos = file_end

        # Skip zero-byte files as they have no data bytes in the stream
        if file_len == 0:
            continue

        # Check for overlap between [piece_start, piece_end) and [file_start, file_end)
        overlap_start = max(piece_start, file_start)
        overlap_end = min(piece_end, file_end)

        if overlap_start < overlap_end:
            offset_in_file = overlap_start - file_start
            slice_len = overlap_end - overlap_start
            slices.append(
                FileSlice(
                    file_index=idx,
                    rel_path=file_info["path"],
                    offset_in_file=offset_in_file,
                    length=slice_len,
                )
            )

        # Early exit once we have moved past the end of this piece
        if current_stream_pos >= piece_end:
            break

    return slices


def get_piece_indices_for_file(metadata: Dict[str, Any], file_index: int) -> Set[int]:
    """Return the set of distinct piece indices overlapping a specific file.

    Zero-byte files return an empty set.

    Args:
        metadata: Validated metadata dictionary.
        file_index: Index of file in metadata['files'].

    Returns:
        Set of piece indices that contain data for this file.
    """
    files = metadata["files"]
    if file_index < 0 or file_index >= len(files):
        raise IndexError(f"File index {file_index} out of range [0, {len(files)})")

    file_len = files[file_index]["length"]
    if file_len == 0:
        return set()

    offsets = get_file_stream_offsets(files)
    file_start, file_end = offsets[file_index]
    piece_size = metadata["piece_size"]

    first_piece = file_start // piece_size
    last_piece = (file_end - 1) // piece_size

    return set(range(first_piece, last_piece + 1))


def validate_metadata(
    metadata: Dict[str, Any],
    out_dir: Optional[Path] = None,
) -> None:
    """Validate metadata structure, limits, hashes, and path safety before disk access.

    This function enforces all requirements from Section 6.5 and Section 14.5.

    Args:
        metadata: Dictionary loaded from JSON.
        out_dir: Optional destination directory for disk space and path resolution check.

    Raises:
        MetadataValidationError: If any validation rule is violated.
    """
    if not isinstance(metadata, dict):
        raise MetadataValidationError("Metadata must be a dictionary.")

    required_keys = {"version", "root", "piece_size", "total_size", "files", "piece_hashes"}
    missing = required_keys - set(metadata.keys())
    if missing:
        raise MetadataValidationError(f"Metadata missing required keys: {sorted(missing)}")

    # 1. Version check (strictly int, excluding bool)
    version = metadata["version"]
    if type(version) is not int or version != config.PROTOCOL_VERSION:
        raise MetadataValidationError(
            f"Unsupported or invalid protocol version: {version} (expected {config.PROTOCOL_VERSION})"
        )

    # 2. Root check
    root = metadata["root"]
    if type(root) is not str:
        raise MetadataValidationError("Metadata 'root' must be a string.")
    if root != "":
        validate_path_component(root)

    # 3. Piece size bounds (strictly int, within [MIN, MAX])
    piece_size = metadata["piece_size"]
    if type(piece_size) is not int or piece_size < config.MIN_PIECE_SIZE or piece_size > config.MAX_PIECE_SIZE:
        raise MetadataValidationError(
            f"piece_size {piece_size} out of allowed range [{config.MIN_PIECE_SIZE}, {config.MAX_PIECE_SIZE}]"
        )

    # 4. Files list validation
    files = metadata["files"]
    if type(files) is not list:
        raise MetadataValidationError("Metadata 'files' must be a list.")
    if len(files) == 0:
        raise MetadataValidationError("Metadata 'files' cannot be empty.")
    if len(files) > config.MAX_FILES:
        raise MetadataValidationError(f"File count {len(files)} exceeds MAX_FILES ({config.MAX_FILES})")

    seen_paths_case_folded: Set[str] = set()
    calculated_total_size = 0

    for idx, f in enumerate(files):
        if type(f) is not dict:
            raise MetadataValidationError(f"File entry {idx} is not a dictionary.")
        if not {"path", "length", "sha256"}.issubset(f.keys()):
            raise MetadataValidationError(f"File entry {idx} missing required fields (path, length, sha256).")

        path_str = f["path"]
        if type(path_str) is not str:
            raise MetadataValidationError(f"File entry {idx} 'path' must be a string.")
        validate_relative_path(path_str)

        # Check duplicate paths, including case-insensitive and Unicode-equivalent duplicates (Section 14.5)
        path_folded = unicodedata.normalize("NFC", path_str).lower()
        if path_folded in seen_paths_case_folded:
            raise MetadataValidationError(f"Duplicate or case-colliding file path: '{path_str}'")
        seen_paths_case_folded.add(path_folded)

        length = f["length"]
        if type(length) is not int or length < 0:
            raise MetadataValidationError(f"File '{path_str}' has invalid length: {length}")
        calculated_total_size += length

        sha256_str = f["sha256"]
        if type(sha256_str) is not str or not _HEX64_REGEX.match(sha256_str):
            raise MetadataValidationError(f"File '{path_str}' has invalid sha256 hash: {sha256_str}")

    # 5. Total size consistency and limits
    total_size = metadata["total_size"]
    if type(total_size) is not int or total_size != calculated_total_size:
        raise MetadataValidationError(
            f"total_size ({total_size}) does not match sum of file lengths ({calculated_total_size})"
        )
    if total_size > config.MAX_TOTAL_BYTES:
        raise MetadataValidationError(
            f"total_size {total_size} exceeds MAX_TOTAL_BYTES ({config.MAX_TOTAL_BYTES})"
        )

    # 6. Piece count and hashes validation
    expected_pieces = calculate_piece_arithmetic(total_size, piece_size)
    if expected_pieces > config.MAX_PIECES:
        raise MetadataValidationError(
            f"Piece count {expected_pieces} exceeds MAX_PIECES ({config.MAX_PIECES})"
        )

    piece_hashes = metadata["piece_hashes"]
    if type(piece_hashes) is not list or len(piece_hashes) != expected_pieces:
        raise MetadataValidationError(
            f"piece_hashes count ({len(piece_hashes) if isinstance(piece_hashes, list) else type(piece_hashes)}) "
            f"does not match expected pieces ({expected_pieces})"
        )

    for idx, p_hash in enumerate(piece_hashes):
        if type(p_hash) is not str or not _HEX64_REGEX.match(p_hash):
            raise MetadataValidationError(f"Piece hash at index {idx} is invalid: {p_hash}")

    # 7. Destination directory checks (path resolution, symlinks, & disk space)
    if out_dir is not None:
        out_dir_path = Path(out_dir).resolve()

        # Check free disk space on out_dir or its closest existing ancestor (Section 6.5)
        check_dir = out_dir_path
        while not check_dir.exists() and check_dir != check_dir.parent:
            check_dir = check_dir.parent

        try:
            free_bytes = shutil.disk_usage(check_dir).free
            if free_bytes < total_size:
                raise MetadataValidationError(
                    f"Insufficient disk space: required {total_size} bytes, available {free_bytes} bytes."
                )
        except OSError as err:
            raise MetadataValidationError(f"Failed to check disk usage on {check_dir}: {err}") from err

        # Verify all target file paths resolve inside out_dir (no directory traversal or symlink escape)
        for f in files:
            target_rel = Path(root) / Path(f["path"]) if root else Path(f["path"])
            target_candidate = out_dir_path / target_rel

            # Symlink safety check: never follow symlinks when writing (Section 14.5)
            curr = target_candidate
            while curr != out_dir_path and curr != curr.parent:
                if curr.is_symlink():
                    resolved_symlink = curr.resolve()
                    try:
                        if os.path.commonpath([str(out_dir_path), str(resolved_symlink)]) != str(out_dir_path):
                            raise MetadataValidationError(
                                f"Symlink '{curr}' resolves outside target directory: '{resolved_symlink}'"
                            )
                    except ValueError as err:
                        raise MetadataValidationError(
                            f"Symlink '{curr}' escape across drive roots: {err}"
                        ) from err
                    raise MetadataValidationError(
                        f"Symlinks are forbidden in destination path: '{curr}'"
                    )
                curr = curr.parent

            resolved_target = target_candidate.resolve()
            try:
                common = os.path.commonpath([str(out_dir_path), str(resolved_target)])
                if common != str(out_dir_path):
                    raise MetadataValidationError(f"Path traversal detected: {f['path']} resolves outside target")
            except ValueError as err:
                raise MetadataValidationError(f"Path traversal escape across drives/roots: {err}") from err


def build_metadata(
    source_path: Path,
    piece_size: Optional[int] = None,
) -> Tuple[Dict[str, Any], bytes, str]:
    """Build metadata from a file or folder on disk with deterministic canonical sorting.

    Args:
        source_path: Path to a file or directory.
        piece_size: Optional custom piece size; defaults to config.DEFAULT_PIECE_SIZE.

    Returns:
        Tuple of (metadata_dict, canonical_bytes, swarm_id).

    Raises:
        FileNotFoundError: If source_path does not exist.
        ValueError: If source_path is empty or contains no readable files.
    """
    source = Path(source_path).resolve()
    if not source.exists():
        raise FileNotFoundError(f"Source path does not exist: {source}")

    file_entries: List[Dict[str, Any]] = []
    root_name = ""

    if source.is_file():
        # Single file share: root is empty string (Section 6.4)
        root_name = ""
        file_len = source.stat().st_size
        with open(source, "rb") as fp:
            hasher = hashlib.sha256()
            while chunk := fp.read(65536):
                hasher.update(chunk)
            file_sha256 = hasher.hexdigest()

        file_entries.append({
            "path": unicodedata.normalize("NFC", source.name),
            "length": file_len,
            "sha256": file_sha256,
        })
    elif source.is_dir():
        # Directory share: root is folder name
        root_name = unicodedata.normalize("NFC", source.name)
        validate_path_component(root_name)

        # Collect all non-symlink regular files recursively
        discovered_files: List[Tuple[str, Path]] = []
        for root_dir, dirnames, filenames in os.walk(source, followlinks=False):
            # Do not traverse into symlinked subdirectories (Section 8.3)
            dirnames[:] = [d for d in dirnames if not (Path(root_dir) / d).is_symlink()]
            dirnames.sort()
            filenames.sort()
            for fname in filenames:
                # Skip OS artifacts (.DS_Store, Thumbs.db, desktop.ini)
                if fname.lower() in IGNORED_FILENAMES:
                    continue

                file_path = Path(root_dir) / fname
                if file_path.is_symlink():
                    continue  # Do not follow symlinks (Section 8.3)
                if not file_path.is_file():
                    continue

                rel_posix = unicodedata.normalize("NFC", file_path.relative_to(source).as_posix())
                try:
                    validate_relative_path(rel_posix)
                except MetadataValidationError:
                    continue  # Skip unsafe paths if present

                discovered_files.append((rel_posix, file_path))

        # Deterministic sorting by POSIX UTF-8 string comparison (Section 6.2)
        discovered_files.sort(key=lambda item: item[0].encode("utf-8"))

        for rel_posix, file_path in discovered_files:
            try:
                file_len = file_path.stat().st_size
                hasher = hashlib.sha256()
                with open(file_path, "rb") as fp:
                    while chunk := fp.read(65536):
                        hasher.update(chunk)
                file_entries.append({
                    "path": rel_posix,
                    "length": file_len,
                    "sha256": hasher.hexdigest(),
                })
            except (OSError, PermissionError):
                continue  # Skip unreadable files with a warning in caller (Section 8.3)

    if not file_entries:
        raise ValueError(f"No valid, readable files found in '{source_path}'.")

    total_size = sum(f["length"] for f in file_entries)

    # Choose piece size: default 64 KiB, or larger power of two if MAX_PIECES would be exceeded
    chosen_piece_size = piece_size if piece_size else config.DEFAULT_PIECE_SIZE
    if total_size > 0:
        while (total_size / chosen_piece_size) > config.MAX_PIECES and chosen_piece_size < config.MAX_PIECE_SIZE:
            chosen_piece_size *= 2

    # Compute piece hashes across the continuous concatenated stream
    piece_hashes: List[str] = []
    if total_size > 0:
        piece_hasher = hashlib.sha256()
        current_piece_bytes = 0

        # Generator that streams file bytes in deterministic order
        def stream_bytes():
            if source.is_file():
                with open(source, "rb") as fp:
                    while chunk := fp.read(65536):
                        yield chunk
            else:
                for entry in file_entries:
                    file_path = source / Path(entry["path"])
                    with open(file_path, "rb") as fp:
                        while chunk := fp.read(65536):
                            yield chunk

        for chunk in stream_bytes():
            chunk_offset = 0
            while chunk_offset < len(chunk):
                needed = chosen_piece_size - current_piece_bytes
                available = len(chunk) - chunk_offset
                to_take = min(needed, available)

                piece_hasher.update(chunk[chunk_offset : chunk_offset + to_take])
                current_piece_bytes += to_take
                chunk_offset += to_take

                if current_piece_bytes == chosen_piece_size:
                    piece_hashes.append(piece_hasher.hexdigest())
                    piece_hasher = hashlib.sha256()
                    current_piece_bytes = 0

        # Final piece hash if last piece is shorter
        if current_piece_bytes > 0:
            piece_hashes.append(piece_hasher.hexdigest())

    metadata: Dict[str, Any] = {
        "version": config.PROTOCOL_VERSION,
        "root": root_name,
        "piece_size": chosen_piece_size,
        "total_size": total_size,
        "files": file_entries,
        "piece_hashes": piece_hashes,
    }

    canonical_bytes = canonicalize_metadata(metadata)
    swarm_id = hashlib.sha256(canonical_bytes).hexdigest()
    return metadata, canonical_bytes, swarm_id
