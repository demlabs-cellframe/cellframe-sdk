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


def _get_max_nargs(text: str) -> int:
    """Extract MAX_ARGS_COUNT from _DAP_MOCK_NARGS_IMPL definition."""
    # Look for _DAP_MOCK_NARGS_IMPL(_1, _2, ..., _N, N, ...) N
    m = re.search(r"#define\s+_DAP_MOCK_NARGS_IMPL\(([^)]+)\)", text)
    if m:
        params = m.group(1)
        # Count _N parameters (format: _1, _2, _3, ..., _MAX, N, ...)
        underscores = re.findall(r"_(\d+)", params)
        if underscores:
            return max(int(x) for x in underscores)
    return 2


def _has_map_n_macro(text: str, n: int) -> bool:
    """Check if _DAP_MOCK_MAP_N is defined."""
    return re.search(rf"^[ \t]*#define[ \t]+_DAP_MOCK_MAP_{n}\b", text, flags=re.MULTILINE) is not None


def _has_count_params_impl_n(text: str, n: int) -> bool:
    """Check if _DAP_MOCK_MAP_COUNT_PARAMS_IMPL_N is defined."""
    return re.search(rf"^[ \t]*#define[ \t]+_DAP_MOCK_MAP_COUNT_PARAMS_IMPL_{n}\b", text, flags=re.MULTILINE) is not None


def _generate_map_n_macro(n: int) -> str:
    """Generate _DAP_MOCK_MAP_N macro for N parameters."""
    if n == 0:
        return "#define _DAP_MOCK_MAP_0(macro) \\\n    \n"
    
    params = []
    calls = []
    for i in range(1, n + 1):
        params.append(f"type{i}, name{i}")
        calls.append(f"macro(type{i}, name{i})")
    
    return f"#define _DAP_MOCK_MAP_{n}(macro, {', '.join(params)}) \\\n    {', '.join(calls)}\n"


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

    # Re-read the file after potential map append
    macros_text = macros_path.read_text(encoding="utf-8", errors="replace")
    
    # Fix _DAP_MOCK_NARGS if it doesn't support enough arguments
    # Check if we need more args by looking for _DAP_MOCK_MAP_COUNT_PARAMS_IMPL errors
    current_max_nargs = _get_max_nargs(macros_text)
    
    # Calculate required max args based on PARAM counts in wrappers
    # Look for patterns like PARAM(...), PARAM(...) which indicate param count
    wrapper_matches = re.findall(r"_DAP_MOCK_WRAPPER_CUSTOM_FOR_\w+\([^)]+\).*?PARAM\s*\([^)]+\)", macros_text, re.DOTALL)
    max_params_needed = 0
    for wrapper in wrapper_matches:
        param_count = len(re.findall(r"PARAM\s*\(", wrapper))
        if param_count > max_params_needed:
            max_params_needed = param_count
    
    # Each PARAM expands to 2 args (type, name), plus 2 for safety margin
    required_max_nargs = max(max_params_needed * 2 + 2, 12)  # minimum 12 for safety
    
    if current_max_nargs < required_max_nargs:
        # Need to fix _DAP_MOCK_NARGS_IMPL
        new_impl_params = ", ".join(f"_{i}" for i in range(1, required_max_nargs + 1))
        new_sequence = ", ".join(str(i) for i in range(required_max_nargs, -1, -1))
        
        # Replace the old NARGS_IMPL definition
        old_nargs_pattern = r"#define _DAP_MOCK_NARGS_IMPL\([^)]+\) N\n#define _DAP_MOCK_NARGS\(\.\.\.\) _DAP_MOCK_NARGS_IMPL\([^)]+\)"
        new_nargs = f"#define _DAP_MOCK_NARGS_IMPL({new_impl_params}, N, ...) N\n#define _DAP_MOCK_NARGS(...) _DAP_MOCK_NARGS_IMPL(__VA_ARGS__, {new_sequence})"
        
        macros_text = re.sub(old_nargs_pattern, new_nargs, macros_text)
        macros_path.write_text(macros_text, encoding="utf-8")
        
    # Re-read after NARGS fix
    macros_text = macros_path.read_text(encoding="utf-8", errors="replace")
    
    # Add missing _DAP_MOCK_MAP_N macros
    additions = []
    for n in range(0, 7):  # Support up to 6 parameters
        if not _has_map_n_macro(macros_text, n):
            additions.append(_generate_map_n_macro(n))
    
    # Add missing _DAP_MOCK_MAP_COUNT_PARAMS_IMPL_N macros
    for arg_count in range(0, 13):  # Support up to 12 args (6 params * 2)
        if not _has_count_params_impl_n(macros_text, arg_count):
            param_count = arg_count // 2
            if arg_count == 0:
                additions.append(f"#define _DAP_MOCK_MAP_COUNT_PARAMS_IMPL_0(arg_count_val, ...) 0\n")
            elif arg_count == 1:
                # Special case for single arg (check for void)
                pass  # Usually already defined
            else:
                additions.append(f"#define _DAP_MOCK_MAP_COUNT_PARAMS_IMPL_{arg_count}(arg_count_val, ...) {param_count}\n")
    
    if additions:
        with macros_path.open("a", encoding="utf-8") as f:
            f.write("\n\n/* BEGIN missing _DAP_MOCK_MAP macros (auto-injected) */\n")
            for add in additions:
                f.write(add)
            f.write("/* END missing _DAP_MOCK_MAP macros */\n")

    # Re-read after additions
    macros_text = macros_path.read_text(encoding="utf-8", errors="replace")

    # The dap-sdk templates currently don't emit the param-count routing macros
    # (_DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_N). Generate them based on
    # existing _DAP_MOCK_MAP_IMPL_COND_N blocks to keep builds working.
    if not _has_param_count_route_macros(macros_text):
        counts = _collect_impl_cond_counts(macros_text)
        # Also add routing for common param counts even if IMPL_COND not found
        for n in range(0, 7):
            counts.append(n)
        counts = sorted(set(counts))
        
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
                        "    _DAP_MOCK_MAP_0(macro)\n"
                    )
                    f.write("#endif\n\n")
                else:
                    f.write(f"#ifndef _DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_{c}\n")
                    f.write(
                        f"#define _DAP_MOCK_MAP_CHECK_VOID_BY_PARAM_COUNT_ROUTE_{c}(param_count_val, first_arg, macro, ...) \\\n"
                    )
                    f.write(f"    _DAP_MOCK_MAP_{c}(macro, __VA_ARGS__)\n")
                    f.write("#endif\n\n")
            f.write("/* END param-count route macros */\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
