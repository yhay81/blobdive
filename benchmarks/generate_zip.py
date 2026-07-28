#!/usr/bin/env python3
"""Generate a deterministic stored ZIP fixture for BlobDive benchmarks."""

from __future__ import annotations

import argparse
import pathlib
import zipfile


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("entries must be at least 1")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--entries", required=True, type=positive_integer)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        args.output,
        mode="w",
        compression=zipfile.ZIP_STORED,
        allowZip64=True,
    ) as archive:
        for index in range(args.entries):
            info = zipfile.ZipInfo(
                filename=f"entries/{index:09d}.txt",
                date_time=(2020, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, f"entry-{index:09d}\n".encode())


if __name__ == "__main__":
    main()
