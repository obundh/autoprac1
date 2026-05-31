# -*- coding: utf-8 -*-
"""Compatibility entry point for Local Pixel Mouse Assistant.

The public repository stores the generated single-file app source in small
fragments under ``src/local_pixel_mouse_assistant_parts`` so the GitHub app can
publish it reliably. Running this file reconstructs and executes that source.
"""

from __future__ import annotations

from pathlib import Path


PARTS_DIR = Path(__file__).resolve().parent / "src" / "local_pixel_mouse_assistant_parts"


def main() -> None:
    parts = sorted(PARTS_DIR.glob("part_*.pyfrag"))
    if not parts:
        raise RuntimeError(f"source fragments not found: {PARTS_DIR}")
    source = "".join(part.read_text(encoding="utf-8") for part in parts)
    exec(compile(source, "local_pixel_mouse_assistant.py", "exec"), globals())


if __name__ == "__main__":
    main()
