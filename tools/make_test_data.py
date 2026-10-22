"""Generate edge-case test directory structure for P2P Swarm testing and viva demonstrations.

Follows Section 18:
Creates a sample directory containing:
- an empty file (0 bytes)
- a 1-byte file
- a file of exactly k * piece_size bytes
- files of piece_size - 1 and piece_size + 1 bytes
- a 5 MB random payload file
- nested directory structures
- a file with a Unicode name
"""

import argparse
import os
from pathlib import Path
import sys

# Ensure project root is on sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config


def create_test_dataset(out_dir: Path, piece_size: int = config.DEFAULT_PIECE_SIZE) -> None:
    """Populate out_dir with boundary test files.

    Args:
        out_dir: Target directory path.
        piece_size: Chunk size in bytes (defaults to 64 KiB).
    """
    target = Path(out_dir).resolve()
    target.mkdir(parents=True, exist_ok=True)

    print(f"Creating edge-case test dataset in: {target}")
    print(f"Base piece size: {piece_size} bytes")

    # 1. Empty file (0 bytes)
    empty_path = target / "empty.txt"
    empty_path.write_bytes(b"")
    print(f"  [OK] Empty file (0 B): {empty_path.name}")

    # 2. 1-byte file
    one_byte_path = target / "one_byte.bin"
    one_byte_path.write_bytes(b"\x42")
    print(f"  [OK] 1-byte file: {one_byte_path.name}")

    # 3. File ending exactly on a piece boundary (2 * piece_size)
    exact_boundary_path = target / "exact_boundary.bin"
    # Use deterministic repeating pattern
    pattern = b"EXACT-PIECE-BOUNDARY-DATA-CHUNK"
    repeats = (2 * piece_size) // len(pattern)
    exact_data = (pattern * (repeats + 1))[: 2 * piece_size]
    exact_boundary_path.write_bytes(exact_data)
    print(f"  [OK] Exact boundary file ({len(exact_data)} B = 2 pieces): {exact_boundary_path.name}")

    # 4. File of piece_size - 1 bytes
    minus_one_path = target / "piece_minus_one.dat"
    minus_one_data = (b"M" * (piece_size - 1))
    minus_one_path.write_bytes(minus_one_data)
    print(f"  [OK] Piece - 1 file ({len(minus_one_data)} B): {minus_one_path.name}")

    # 5. File of piece_size + 1 bytes
    plus_one_path = target / "piece_plus_one.dat"
    plus_one_data = (b"P" * (piece_size + 1))
    plus_one_path.write_bytes(plus_one_data)
    print(f"  [OK] Piece + 1 file ({len(plus_one_data)} B): {plus_one_path.name}")

    # 6. 5 MB random / pseudo-random file
    five_mb_path = target / "random_5mb.bin"
    five_mb_size = 5 * 1024 * 1024  # 5,242,880 bytes
    print(f"  [..] Generating 5 MB payload: {five_mb_path.name}...")
    chunk = os.urandom(65536)
    with open(five_mb_path, "wb") as fp:
        written = 0
        while written < five_mb_size:
            to_write = min(len(chunk), five_mb_size - written)
            fp.write(chunk[:to_write])
            written += to_write
    print(f"  [OK] 5 MB payload ({five_mb_size} B): {five_mb_path.name}")

    # 7. Nested directories
    sub_dir = target / "nested" / "deep" / "docs"
    sub_dir.mkdir(parents=True, exist_ok=True)
    nested_file = sub_dir / "notes.txt"
    nested_file.write_text("Nested document inside subfolder structure.\n", encoding="utf-8")
    print(f"  [OK] Nested directory file: {nested_file.relative_to(target)}")

    # 8. Unicode filename
    unicode_file = target / "unicode_тест_файл_🚀.txt"
    unicode_file.write_text("UTF-8 unicode content with emojis and non-latin script.\n", encoding="utf-8")
    print(f"  [OK] Unicode filename: {unicode_file.name}")

    print("Test dataset generation complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate P2P Swarm edge-case test dataset.")
    parser.add_argument(
        "--out",
        type=str,
        default="sample_data",
        help="Destination directory for test files (default: sample_data)",
    )
    parser.add_argument(
        "--piece-size",
        type=int,
        default=config.DEFAULT_PIECE_SIZE,
        help=f"Base piece size in bytes (default: {config.DEFAULT_PIECE_SIZE})",
    )
    args = parser.parse_args()

    create_test_dataset(Path(args.out), piece_size=args.piece_size)


if __name__ == "__main__":
    main()
