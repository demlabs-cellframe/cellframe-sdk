#!/usr/bin/env python3
"""
Fix-up for dap_mock_autowrap generated headers.

dap_mock_autowrap.sh writes a full macro system into "<macros>.map_content", but the main
"<macros>" header currently doesn't include it. This breaks builds with:
  unknown type name '_DAP_MOCK_MAP'

This script appends the map content to the macros header if the main header does not
define _DAP_MOCK_MAP yet.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re


def _has_mock_map_definition(text: str) -> bool:
    return re.search(r"^[ \t]*#define[ \t]+_DAP_MOCK_MAP\b", text, flags=re.MULTILINE) is not None


def _has_param_count_route_macros(text: str) -> bool:
    return re.search(
        r"^[ \t]*#define[ \t]+_DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_\d+\b",
        text,
        flags=re.MULTILINE,
    ) is not None


def _collect_impl_cond_counts(text: str) -> list[int]:
    counts: set[int] = set()
    for m in re.finditer(r"^[ \t]*#define[ \t]+_DAP_MOCK_MAP_IMPL_COND_(\d+)\b", text, flags=re.MULTILINE):
        try:
            counts.add(int(m.group(1)))
        except ValueError:
            continue
    return sorted(counts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--macros", required=True, help="Path to *_mock_macros.h")
    ap.add_argument("--map-content", required=True, help="Path to *_mock_macros.h.map_content")
    args = ap.parse_args()

    macros_path = Path(args.macros)
    map_path = Path(args.map_content)

    if not macros_path.exists():
        raise SystemExit(f"macros header not found: {macros_path}")
    if not map_path.exists():
        raise SystemExit(f"map_content not found: {map_path}")

    macros_text = macros_path.read_text(encoding="utf-8", errors="replace")
    need_append_map = not _has_mock_map_definition(macros_text)

    if need_append_map:
        map_text = map_path.read_text(encoding="utf-8", errors="replace")
        if not map_text.strip():
            raise SystemExit(f"map_content is empty: {map_path}")

        with macros_path.open("a", encoding="utf-8") as f:
            f.write("\n\n/* BEGIN _DAP_MOCK_MAP system (auto-injected) */\n")
            f.write(map_text)
            f.write("\n/* END _DAP_MOCK_MAP system */\n")

    # The dap-sdk templates currently don't emit the param-count routing macros
    # (_DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_N). Generate them based on
    # existing _DAP_MOCK_MAP_IMPL_COND_N blocks to keep builds working.
    macros_text = macros_path.read_text(encoding="utf-8", errors="replace")
    if not _has_param_count_route_macros(macros_text):
        counts = _collect_impl_cond_counts(macros_text)
        if not counts:
            # Nothing to route (no generated map impl conditionals). This happens for targets that
            # don't use DAP_MOCK_WRAPPER_CUSTOM. Keep it non-fatal.
            return 0

        with macros_path.open("a", encoding="utf-8") as f:
            f.write("\n\n/* BEGIN param-count route macros (auto-injected) */\n")
            for c in counts:
                if c == 0:
                    f.write("#ifndef _DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_0\n")
                    f.write(
                        "#define _DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_0(param_count_val, first_arg, macro, ...) \\\n"
                    )
                    f.write(
                        "    _DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_0_CHECK(first_arg, macro, __VA_ARGS__)\n"
                    )
                    f.write("#endif\n\n")
                else:
                    f.write(f"#ifndef _DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_{c}\n")
                    f.write(
                        f"#define _DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_{c}(param_count_val, first_arg, macro, ...) \\\n"
                    )
                    f.write(f"    _DAP_MOCK_MAP_IMPL_COND_{c}(macro, __VA_ARGS__)\n")
                    f.write("#endif\n\n")
            f.write("/* END param-count route macros */\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
