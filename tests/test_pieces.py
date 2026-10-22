"""Unit tests for PieceReader and PieceWriter covering all boundary and concurrency cases.

Required boundary cases tested:
1. Empty file (0 bytes)
2. 1-byte file
3. File smaller than one piece (sharing piece with neighbouring file)
4. File ending exactly on a piece boundary
5. Short last piece
6. A piece spanning three files
7. Out-of-order piece arrival
8. Duplicate piece arrival (idempotency)
9. Concurrent multi-threaded piece writes
10. Hash mismatch rejection
11. Refusal to overwrite existing files without --overwrite
"""

import concurrent.futures
import hashlib
from pathlib import Path
import random
import pytest

from common.metadata import (
    build_metadata,
    calculate_piece_arithmetic,
    map_piece_to_slices,
)
from common.pieces import PieceIOError, PieceReader, PieceWriter
import config


def test_empty_file_boundary(tmp_path: Path) -> None:
    """Boundary Case 1: Empty file (0 bytes).

    Receiver creates 0-byte files immediately with no pieces needed.
    """
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    empty_file = src_dir / "zero.txt"
    empty_file.write_bytes(b"")

    meta, _, _ = build_metadata(src_dir, piece_size=config.MIN_PIECE_SIZE)
    assert meta["total_size"] == 0
    assert len(meta["piece_hashes"]) == 0

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)

    # Empty file must be created immediately upon initialization
    assert writer.is_complete()
    assert writer.completed_files_count() == 1
    dest_file = dest_dir / "src" / "zero.txt"
    assert dest_file.exists()
    assert dest_file.stat().st_size == 0


def test_one_byte_file_boundary(tmp_path: Path) -> None:
    """Boundary Case 2: 1-byte file.

    Generates 1 piece of length 1 byte. Reader and writer handle it cleanly.
    """
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    one_byte = src_dir / "one.bin"
    one_byte.write_bytes(b"Z")

    meta, _, _ = build_metadata(src_dir, piece_size=config.MIN_PIECE_SIZE)
    assert meta["total_size"] == 1
    assert len(meta["piece_hashes"]) == 1

    reader = PieceReader(src_dir, meta)
    piece0 = reader.read_piece(0)
    reader.close()
    assert piece0 == b"Z"

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)
    completed = writer.write_piece(0, piece0)

    assert writer.is_complete()
    assert "one.bin" in completed
    dest_file = dest_dir / "src" / "one.bin"
    assert dest_file.read_bytes() == b"Z"


def test_file_smaller_than_one_piece(tmp_path: Path) -> None:
    """Boundary Case 3: File smaller than one piece, sharing a piece with a neighbor."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    # Piece size is 16 KiB
    piece_size = config.MIN_PIECE_SIZE
    f1_content = b"SmallFile1" * 100   # 1000 bytes (< 16 KiB)
    f2_content = b"SmallFile2" * 2000  # 20000 bytes (> 16 KiB)

    (src_dir / "a_small.txt").write_bytes(f1_content)
    (src_dir / "b_large.txt").write_bytes(f2_content)

    meta, _, _ = build_metadata(src_dir, piece_size=piece_size)
    assert meta["total_size"] == len(f1_content) + len(f2_content)
    assert len(meta["piece_hashes"]) == 2

    # Piece 0 should contain all of a_small.txt plus the start of b_large.txt
    slices = map_piece_to_slices(meta, 0)
    assert len(slices) == 2
    assert slices[0].rel_path == "a_small.txt"
    assert slices[0].length == len(f1_content)
    assert slices[1].rel_path == "b_large.txt"
    assert slices[1].length == piece_size - len(f1_content)

    reader = PieceReader(src_dir, meta)
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)

    for i in range(len(meta["piece_hashes"])):
        data = reader.read_piece(i)
        writer.write_piece(i, data)
    reader.close()

    assert writer.is_complete()
    assert (dest_dir / "src" / "a_small.txt").read_bytes() == f1_content
    assert (dest_dir / "src" / "b_large.txt").read_bytes() == f2_content


def test_file_ending_exactly_on_piece_boundary(tmp_path: Path) -> None:
    """Boundary Case 4: File ending exactly on a piece boundary."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    piece_size = config.MIN_PIECE_SIZE  # 16384 bytes

    # Exactly 2 full pieces
    f1_content = b"E" * (2 * piece_size)
    f2_content = b"NextFile" * 50

    (src_dir / "exact.dat").write_bytes(f1_content)
    (src_dir / "next.dat").write_bytes(f2_content)

    meta, _, _ = build_metadata(src_dir, piece_size=piece_size)
    assert meta["files"][0]["length"] == 2 * piece_size

    # Piece 1 covers the second half of exact.dat and terminates exactly at file boundary
    slices_p1 = map_piece_to_slices(meta, 1)
    assert len(slices_p1) == 1
    assert slices_p1[0].rel_path == "exact.dat"
    assert slices_p1[0].offset_in_file == piece_size
    assert slices_p1[0].length == piece_size

    # Piece 2 starts immediately with next.dat
    slices_p2 = map_piece_to_slices(meta, 2)
    assert len(slices_p2) == 1
    assert slices_p2[0].rel_path == "next.dat"
    assert slices_p2[0].offset_in_file == 0

    reader = PieceReader(src_dir, meta)
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)

    for i in range(len(meta["piece_hashes"])):
        data = reader.read_piece(i)
        writer.write_piece(i, data)
    reader.close()

    assert writer.is_complete()
    assert (dest_dir / "src" / "exact.dat").read_bytes() == f1_content
    assert (dest_dir / "src" / "next.dat").read_bytes() == f2_content


def test_short_last_piece(tmp_path: Path) -> None:
    """Boundary Case 5: Last piece is shorter than standard piece_size."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    piece_size = config.MIN_PIECE_SIZE  # 16384 bytes
    total_len = piece_size + 500  # Last piece is only 500 bytes

    payload = b"ShortPieceTest" * (total_len // 14 + 1)
    payload = payload[:total_len]
    (src_dir / "data.bin").write_bytes(payload)

    meta, _, _ = build_metadata(src_dir, piece_size=piece_size)
    assert len(meta["piece_hashes"]) == 2

    reader = PieceReader(src_dir, meta)
    p0 = reader.read_piece(0)
    p1 = reader.read_piece(1)
    reader.close()

    assert len(p0) == piece_size
    assert len(p1) == 500

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)
    writer.write_piece(0, p0)
    writer.write_piece(1, p1)

    assert writer.is_complete()
    assert (dest_dir / "src" / "data.bin").read_bytes() == payload


def test_piece_spanning_three_files(tmp_path: Path) -> None:
    """Boundary Case 6: A single piece spans three distinct files.

    File 1 tail + File 2 (entirely within this piece) + File 3 head.
    """
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    piece_size = config.MIN_PIECE_SIZE  # 16384 bytes

    # In piece 0:
    # f1: 5,000 bytes
    # f2: 2,000 bytes (entirely inside piece 0)
    # f3: 15,000 bytes (first 9,384 bytes inside piece 0, remaining in piece 1)
    f1_data = b"1" * 5000
    f2_data = b"2" * 2000
    f3_data = b"3" * 15000

    (src_dir / "file1.txt").write_bytes(f1_data)
    (src_dir / "file2.txt").write_bytes(f2_data)
    (src_dir / "file3.txt").write_bytes(f3_data)

    meta, _, _ = build_metadata(src_dir, piece_size=piece_size)
    slices_p0 = map_piece_to_slices(meta, 0)

    # Must span exactly 3 files!
    assert len(slices_p0) == 3
    assert slices_p0[0].rel_path == "file1.txt"
    assert slices_p0[0].length == 5000
    assert slices_p0[1].rel_path == "file2.txt"
    assert slices_p0[1].length == 2000
    assert slices_p0[2].rel_path == "file3.txt"
    assert slices_p0[2].length == (piece_size - 7000)

    reader = PieceReader(src_dir, meta)
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)

    # Read and write all pieces
    for i in range(len(meta["piece_hashes"])):
        chunk = reader.read_piece(i)
        writer.write_piece(i, chunk)
    reader.close()

    assert writer.is_complete()
    assert (dest_dir / "src" / "file1.txt").read_bytes() == f1_data
    assert (dest_dir / "src" / "file2.txt").read_bytes() == f2_data
    assert (dest_dir / "src" / "file3.txt").read_bytes() == f3_data


def test_out_of_order_piece_writes(tmp_path: Path) -> None:
    """Test pieces arriving out of order (e.g. reverse or shuffled)."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    piece_size = config.MIN_PIECE_SIZE
    data = b"OutOfOrderTest" * 10000
    (src_dir / "test.bin").write_bytes(data)

    meta, _, _ = build_metadata(src_dir, piece_size=piece_size)
    num_pieces = len(meta["piece_hashes"])
    assert num_pieces > 3

    reader = PieceReader(src_dir, meta)
    pieces = [reader.read_piece(i) for i in range(num_pieces)]
    reader.close()

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)

    # Shuffle indices
    order = list(range(num_pieces))
    random.seed(42)
    random.shuffle(order)

    for idx in order:
        writer.write_piece(idx, pieces[idx])

    assert writer.is_complete()
    assert (dest_dir / "src" / "test.bin").read_bytes() == data


def test_duplicate_piece_writes_ignored(tmp_path: Path) -> None:
    """Writing duplicate pieces should be safely ignored without error."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    piece_size = config.MIN_PIECE_SIZE
    (src_dir / "dup.txt").write_bytes(b"DuplicateData" * 2000)

    meta, _, _ = build_metadata(src_dir, piece_size=piece_size)
    reader = PieceReader(src_dir, meta)
    p0 = reader.read_piece(0)
    reader.close()

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)

    # Write piece 0 twice
    res1 = writer.write_piece(0, p0)
    res2 = writer.write_piece(0, p0)
    assert res2 == []  # Ignored on second call


def test_concurrent_multithreaded_writes(tmp_path: Path) -> None:
    """Stress test: multiple threads writing different pieces concurrently to PieceWriter."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    piece_size = config.MIN_PIECE_SIZE

    # Create several files with varying sizes
    files_data = {
        "doc1.dat": b"A" * 30000,
        "nested/doc2.dat": b"B" * 50000,
        "doc3.dat": b"C" * 12000,
    }
    for rel_p, d in files_data.items():
        p = src_dir / rel_p
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(d)

    meta, _, _ = build_metadata(src_dir, piece_size=piece_size)
    reader = PieceReader(src_dir, meta)
    num_pieces = len(meta["piece_hashes"])
    all_pieces = [reader.read_piece(i) for i in range(num_pieces)]
    reader.close()

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)

    # Concurrently write pieces using 8 threads
    def write_worker(idx: int):
        writer.write_piece(idx, all_pieces[idx])

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(write_worker, i) for i in range(num_pieces)]
        concurrent.futures.wait(futures)
        for f in futures:
            f.result()  # Raise any thread exceptions

    assert writer.is_complete()
    for rel_p, d in files_data.items():
        assert (dest_dir / "src" / rel_p).read_bytes() == d


def test_corrupted_piece_hash_mismatch(tmp_path: Path) -> None:
    """PieceWriter must reject pieces whose SHA-256 does not match metadata."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "secret.txt").write_bytes(b"GoodOriginalBytes" * 1000)

    meta, _, _ = build_metadata(src_dir, piece_size=config.MIN_PIECE_SIZE)
    reader = PieceReader(src_dir, meta)
    p0 = reader.read_piece(0)
    reader.close()

    # Corrupt one byte
    corrupted_p0 = bytearray(p0)
    corrupted_p0[0] ^= 0xFF
    corrupted_p0 = bytes(corrupted_p0)

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    writer = PieceWriter(dest_dir, meta)

    with pytest.raises(ValueError, match="hash mismatch"):
        writer.write_piece(0, corrupted_p0)


def test_refuse_overwrite_existing_file(tmp_path: Path) -> None:
    """PieceWriter must refuse to overwrite existing files unless overwrite=True."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "target.txt").write_bytes(b"FreshContent" * 100)

    meta, _, _ = build_metadata(src_dir, piece_size=config.MIN_PIECE_SIZE)

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    # Pre-create the target file
    (dest_dir / "src").mkdir(parents=True, exist_ok=True)
    (dest_dir / "src" / "target.txt").write_bytes(b"OldExistingContent")

    with pytest.raises(FileExistsError, match="Target file already exists"):
        PieceWriter(dest_dir, meta, overwrite=False)

    # With overwrite=True, it should succeed without error
    writer = PieceWriter(dest_dir, meta, overwrite=True)
    assert not writer.is_complete()


def test_concurrent_piecereader_random_reads(tmp_path: Path) -> None:
    """Stress test: 8 threads reading random pieces simultaneously from one PieceReader,
    verified byte-for-byte against the continuous source data.
    """
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    piece_size = config.MIN_PIECE_SIZE  # 16384 bytes

    # Create several files of varying sizes spanning multiple pieces
    files_data = {
        "file_a.bin": b"ChunkA" * 5000,        # 30,000 bytes
        "nested/file_b.bin": b"ChunkB" * 8000, # 48,000 bytes
        "file_c.bin": b"ChunkC" * 2000,        # 12,000 bytes
    }
    for rel_path, data in files_data.items():
        p = src_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    meta, _, _ = build_metadata(src_dir, piece_size=piece_size)
    num_pieces = len(meta["piece_hashes"])
    total_size = meta["total_size"]

    # Construct the continuous byte stream in canonical file order
    source_stream = bytearray()
    for f in meta["files"]:
        source_stream.extend((src_dir / f["path"]).read_bytes())
    source_bytes = bytes(source_stream)

    reader = PieceReader(src_dir, meta)

    def worker_random_reads(worker_id: int):
        rng = random.Random(worker_id * 100 + 42)
        for _ in range(40):
            idx = rng.randint(0, num_pieces - 1)
            piece_data = reader.read_piece(idx)

            # Expected byte range in the continuous stream
            expected_start = idx * piece_size
            expected_end = min((idx + 1) * piece_size, total_size)
            expected_piece = source_bytes[expected_start:expected_end]

            # Byte-for-byte comparison
            assert piece_data == expected_piece
            # SHA-256 comparison against metadata
            assert hashlib.sha256(piece_data).hexdigest() == meta["piece_hashes"][idx]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker_random_reads, i) for i in range(8)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    reader.close()


def test_symlink_in_output_directory_pointing_outside(tmp_path: Path) -> None:
    """Security test: an existing symlink inside out_dir pointing outside must be rejected."""
    victim_dir = tmp_path / "outside_victim"
    victim_dir.mkdir()

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    target_base = dest_dir / "src"
    target_base.mkdir(parents=True, exist_ok=True)

    # Create symlink pointing outside destination directory
    evil_link = target_base / "evil_link"
    try:
        evil_link.symlink_to(victim_dir)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform")

    meta = {
        "version": 1,
        "root": "src",
        "piece_size": config.MIN_PIECE_SIZE,
        "total_size": 100,
        "files": [{"path": "evil_link/secret.txt", "length": 100, "sha256": "a" * 64}],
        "piece_hashes": ["a" * 64],
    }

    with pytest.raises(Exception, match="(Symlink|Path traversal)"):
        PieceWriter(dest_dir, meta)


def test_symlink_inside_output_directory_forbidden(tmp_path: Path) -> None:
    """Section 14.5: Never follow symlinks when writing, even if inside out_dir."""
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    target_base = dest_dir / "src"
    target_base.mkdir(parents=True, exist_ok=True)

    real_sub = target_base / "real_dir"
    real_sub.mkdir()
    internal_link = target_base / "internal_link"
    try:
        internal_link.symlink_to(real_sub)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform")

    meta = {
        "version": 1,
        "root": "src",
        "piece_size": config.MIN_PIECE_SIZE,
        "total_size": 100,
        "files": [{"path": "internal_link/data.txt", "length": 100, "sha256": "b" * 64}],
        "piece_hashes": ["b" * 64],
    }

    with pytest.raises(Exception, match="Symlinks are forbidden"):
        PieceWriter(dest_dir, meta)
