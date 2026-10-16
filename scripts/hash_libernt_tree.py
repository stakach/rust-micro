#!/usr/bin/env python3
"""Hash the extracted installed tree independently of NTFS metadata and file order."""

import hashlib
import os
import sys
from pathlib import Path


def hash_tree(root: Path) -> str:
    digest = hashlib.sha256()
    paths = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"unexpected symlink: {path}")
        name = os.fsencode(path.relative_to(root).as_posix())
        digest.update(len(name).to_bytes(4, "little"))
        digest.update(name)
        if path.is_dir():
            digest.update(b"D")
            continue
        if not path.is_file():
            raise ValueError(f"unexpected entry: {path}")
        digest.update(b"F")
        digest.update(path.stat().st_size.to_bytes(8, "little"))
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: hash_libernt_tree.py <installed-tree>")
    print(hash_tree(Path(sys.argv[1])))
