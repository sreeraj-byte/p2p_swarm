"""Thread-safe piece reader (sender side) and piece writer (receiver side).

This module implements Section 6.6 and Section 10 of PROJECT_SPEC.md.

Key design points:
- PieceReader reads continuous byte ranges across multiple files on the sender.
- PieceWriter writes incoming pieces concurrently directly at their target file
  offsets inside pre-allocated .part files.
- Zero-length files are created immediately upon initialization.
- When all pieces for a file have been written, PieceWriter flushes, verifies the
  file's SHA-256 against metadata, and atomically renames the .part file to its
  final destination name.
"""

from collections import OrderedDict
import hashlib
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Set

from common.metadata import (
    FileSlice,
    MetadataValidationError,
    get_piece_indices_for_file,
    map_piece_to_slices,
    validate_metadata,
)
import config


class PieceIOError(Exception):
    """Raised when reading or writing pieces encounters an I/O or integrity failure."""
    pass


class PieceReader:
    """Thread-safe piece reader for senders.

    Reads any piece by its index across file boundaries from the continuous byte stream.
    Manages an LRU pool of open file handles to respect OS handle limits while
    ensuring high throughput for parallel requests.
    """

    def __init__(
        self,
        source_path: Path,
        metadata: Dict[str, Any],
        max_open_handles: int = 32,
    ) -> None:
        """Initialize the piece reader.

        Args:
            source_path: Path to shared file or directory on sender.
            metadata: Canonical metadata dictionary.
            max_open_handles: Maximum number of open file handles kept in LRU cache.
        """
        self.source_path = Path(source_path).resolve()
        self.metadata = metadata
        self.max_open_handles = max_open_handles

        # Determine directory root anchor
        if self.source_path.is_file() and not metadata.get("root"):
            self.base_dir = self.source_path.parent
        elif (self.source_path / metadata.get("root", "")).is_dir():
            self.base_dir = self.source_path / metadata["root"]
        elif self.source_path.name == metadata.get("root", ""):
            self.base_dir = self.source_path
        else:
            self.base_dir = self.source_path

        # Thread safety lock for handle cache operations
        self._lock = threading.Lock()
        self._handles: OrderedDict[str, Any] = OrderedDict()

    def _get_file_handle(self, rel_path: str):
        """Retrieve an open read-only handle from LRU cache or open a new one."""
        full_path = self.source_path if self.source_path.is_file() else (self.base_dir / rel_path)

        if rel_path in self._handles:
            self._handles.move_to_end(rel_path)
            return self._handles[rel_path]

        if len(self._handles) >= self.max_open_handles:
            # Close least recently used handle
            _, old_fp = self._handles.popitem(last=False)
            try:
                old_fp.close()
            except OSError:
                pass

        fp = open(full_path, "rb")
        self._handles[rel_path] = fp
        return fp

    def read_piece(self, piece_index: int) -> bytes:
        """Read a complete piece by its 0-based index across file boundaries.

        Args:
            piece_index: Index of piece to read.

        Returns:
            Raw bytes of the piece.

        Raises:
            PieceIOError: If read fails or data length does not match expected size.
            IndexError: If piece_index is invalid.
        """
        slices: List[FileSlice] = map_piece_to_slices(self.metadata, piece_index)
        piece_buffer = bytearray()

        with self._lock:
            for s in slices:
                fp = self._get_file_handle(s.rel_path)
                try:
                    fp.seek(s.offset_in_file)
                    data = fp.read(s.length)
                    if len(data) != s.length:
                        raise PieceIOError(
                            f"Short read for file '{s.rel_path}' at offset {s.offset_in_file}: "
                            f"expected {s.length} bytes, got {len(data)}"
                        )
                    piece_buffer.extend(data)
                except OSError as err:
                    raise PieceIOError(f"Error reading file '{s.rel_path}': {err}") from err

        return bytes(piece_buffer)

    def close(self) -> None:
        """Close all open file handles."""
        with self._lock:
            for fp in self._handles.values():
                try:
                    fp.close()
                except OSError:
                    pass
            self._handles.clear()


class PieceWriter:
    """Thread-safe piece writer for receivers.

    Implements Section 6.6:
    - Pre-allocates each file as '<final_path>.part' to full size.
    - Zero-byte files are created immediately.
    - Writes incoming pieces directly at exact file offsets.
    - Multiple worker threads write concurrently with per-file locking.
    - Atomically verifies file SHA-256 and renames '.part' to final upon completion.
    """

    def __init__(
        self,
        out_dir: Path,
        metadata: Dict[str, Any],
        overwrite: bool = False,
    ) -> None:
        """Initialize writer, pre-allocate .part files, and create 0-byte files.

        Args:
            out_dir: Destination directory.
            metadata: Metadata dictionary.
            overwrite: If True, overwrite existing files; else raise FileExistsError.

        Raises:
            FileExistsError: If target file exists and overwrite is False.
            MetadataValidationError: If metadata fails validation or disk space check.
        """
        self.out_dir = Path(out_dir).resolve()
        self.metadata = metadata
        self.overwrite = overwrite

        # Validate metadata and disk space (Section 6.5)
        validate_metadata(self.metadata, out_dir=self.out_dir)

        self.root_name = self.metadata.get("root", "")
        self.target_base = (self.out_dir / self.root_name) if self.root_name else self.out_dir

        self.files = self.metadata["files"]
        num_files = len(self.files)

        # Per-file locks to allow concurrent writes to distinct files
        self._file_locks = [threading.Lock() for _ in range(num_files)]
        # Global state lock for completed pieces and remaining piece counts
        self._state_lock = threading.Lock()

        self._completed_pieces: Set[int] = set()
        self._remaining_pieces: Dict[int, Set[int]] = {}
        self._completed_files: List[str] = []

        # Prepare target directory
        self.target_base.mkdir(parents=True, exist_ok=True)

        # Pre-allocation phase
        for idx, file_info in enumerate(self.files):
            rel_path = file_info["path"]
            final_path = self.target_base / rel_path
            part_path = Path(str(final_path) + ".part")

            # Symlink safety check: never follow symlinks when writing (Section 14.5)
            curr = final_path
            while curr != self.out_dir and curr != curr.parent:
                if curr.is_symlink():
                    raise MetadataValidationError(f"Symlinks are forbidden in destination path: '{curr}'")
                curr = curr.parent

            if part_path.is_symlink():
                raise MetadataValidationError(f"Symlinks are forbidden in destination path: '{part_path}'")

            if final_path.exists() and not self.overwrite:
                raise FileExistsError(
                    f"Target file already exists: '{final_path}'. Pass --overwrite to replace."
                )

            # Ensure parent directories exist
            final_path.parent.mkdir(parents=True, exist_ok=True)

            file_len = file_info["length"]
            if file_len == 0:
                # Zero-length files are created immediately (Section 6.6)
                final_path.touch(exist_ok=self.overwrite)
                self._remaining_pieces[idx] = set()
                self._completed_files.append(rel_path)
            else:
                # Pre-allocate sparse/sized .part file
                with open(part_path, "wb") as fp:
                    if file_len > 0:
                        fp.truncate(file_len)

                # Track pieces overlapping this file
                overlapping_pieces = get_piece_indices_for_file(self.metadata, idx)
                self._remaining_pieces[idx] = overlapping_pieces

    def get_remaining_pieces(self) -> Set[int]:
        """Return the set of all piece indices still missing across the swarm."""
        total_pieces = len(self.metadata["piece_hashes"])
        with self._state_lock:
            all_pieces = set(range(total_pieces))
            return all_pieces - self._completed_pieces

    def write_piece(self, piece_index: int, piece_data: bytes) -> List[str]:
        """Verify and write a piece to disk across its overlapping files.

        Args:
            piece_index: 0-based piece index.
            piece_data: Raw byte payload of the piece.

        Returns:
            List of relative paths of any files that were completed by this piece.

        Raises:
            ValueError: If piece hash does not match metadata.
            PieceIOError: If disk write or file verification fails.
            IndexError: If piece_index is out of range.
        """
        piece_hashes = self.metadata["piece_hashes"]
        if piece_index < 0 or piece_index >= len(piece_hashes):
            raise IndexError(f"Piece index {piece_index} out of bounds.")

        # Ignore duplicate delivery (Section 6.6)
        with self._state_lock:
            if piece_index in self._completed_pieces:
                return []

        # 1. Verify piece hash against metadata (Section 9.3)
        expected_hash = piece_hashes[piece_index]
        actual_hash = hashlib.sha256(piece_data).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(
                f"Piece {piece_index} hash mismatch: expected {expected_hash}, got {actual_hash}"
            )

        slices = map_piece_to_slices(self.metadata, piece_index)
        expected_len = sum(s.length for s in slices)
        if len(piece_data) != expected_len:
            raise PieceIOError(
                f"Piece {piece_index} length mismatch: expected {expected_len} bytes, got {len(piece_data)}"
            )

        # 2. Write each slice to its corresponding .part file under per-file lock
        slice_offset_in_piece = 0
        for s in slices:
            slice_bytes = piece_data[slice_offset_in_piece : slice_offset_in_piece + s.length]
            slice_offset_in_piece += s.length

            final_path = self.target_base / s.rel_path
            part_path = Path(str(final_path) + ".part")

            with self._file_locks[s.file_index]:
                try:
                    with open(part_path, "r+b") as fp:
                        fp.seek(s.offset_in_file)
                        fp.write(slice_bytes)
                        fp.flush()
                except OSError as err:
                    raise PieceIOError(f"Failed writing slice to '{part_path}': {err}") from err

        # 3. Update completion state and check for completed files
        files_completed_now: List[str] = []
        with self._state_lock:
            self._completed_pieces.add(piece_index)

            for s in slices:
                f_idx = s.file_index
                remaining = self._remaining_pieces.get(f_idx, set())
                remaining.discard(piece_index)

                if len(remaining) == 0 and s.rel_path not in self._completed_files:
                    # All pieces for this file have arrived: verify file SHA-256 and rename
                    self._finalize_file(f_idx)
                    self._completed_files.append(s.rel_path)
                    files_completed_now.append(s.rel_path)

        return files_completed_now

    def _finalize_file(self, file_index: int) -> None:
        """Verify the complete file's SHA-256 checksum and atomically rename .part to final.

        Must be called under self._state_lock.
        """
        file_info = self.files[file_index]
        rel_path = file_info["path"]
        expected_sha256 = file_info["sha256"]

        final_path = self.target_base / rel_path
        part_path = Path(str(final_path) + ".part")

        # Compute SHA-256 of completed .part file
        hasher = hashlib.sha256()
        with self._file_locks[file_index]:
            try:
                with open(part_path, "rb") as fp:
                    while chunk := fp.read(65536):
                        hasher.update(chunk)
            except OSError as err:
                raise PieceIOError(f"Failed reading '{part_path}' for final verification: {err}") from err

            actual_sha256 = hasher.hexdigest()
            if actual_sha256 != expected_sha256:
                raise PieceIOError(
                    f"File '{rel_path}' checksum mismatch after assembly: "
                    f"expected {expected_sha256}, got {actual_sha256}"
                )

            # Atomic rename from .part to final (cross-platform atomic replace)
            try:
                os.replace(part_path, final_path)
            except OSError as err:
                raise PieceIOError(f"Failed renaming '{part_path}' to '{final_path}': {err}") from err

    def is_complete(self) -> bool:
        """Return True if all pieces have been received and verified."""
        total_pieces = len(self.metadata["piece_hashes"])
        with self._state_lock:
            return len(self._completed_pieces) == total_pieces

    def completed_files_count(self) -> int:
        """Return number of fully assembled and verified files."""
        with self._state_lock:
            return len(self._completed_files)

    def close(self) -> None:
        """Close piece writer resources (no-op as writes use scoped file descriptors)."""
        pass
