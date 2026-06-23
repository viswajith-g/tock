# import subprocess
# import sys
# import collections
# import re

# def analyze_kernel(elf_path):
#     # Use nm with demangling to see the 'capsules_core::adc' structure
#     nm_cmd = ['arm-none-eabi-nm', '--print-size', '--size-sort', '--demangle', elf_path]
    
#     try:
#         output = subprocess.check_output(nm_cmd, text=True)
#     except Exception as e:
#         print(f"Error running nm: {e}")
#         return

#     # Data structures
#     capsule_data = collections.defaultdict(lambda: {"total": 0, "symbols": []})
#     system_overhead = collections.defaultdict(int)

#     # Patterns to identify Tock capsules
#     # Looking for: capsules_core::name or capsules_extra::name or capsules_system::name
#     capsule_re = re.compile(r'capsules_(core|extra|system)::([a-z0-9_]+)')

#     for line in output.splitlines():
#         parts = line.split()
#         if len(parts) < 4: continue
        
#         try:
#             size = int(parts[1], 16)
#         except ValueError: continue
        
#         symbol_full = " ".join(parts[3:])

#         # 1. Check if it's a known Capsule path
#         match = capsule_re.search(symbol_full)
#         if match:
#             category = match.group(2).upper()
#             capsule_data[category]["total"] += size
#             capsule_data[category]["symbols"].append((symbol_full, size))
        
#         # 2. Check for general System/Kernel/Chip logic
#         else:
#             # Use the top-level namespace (e.g., 'kernel', 'nrf52', 'core')
#             root_namespace = symbol_full.split("::")[0]
#             system_overhead[root_namespace] += size

#     # --- PRINTING RESULTS ---
    
#     print(f"{'CATEGORY':<30} | {'SIZE (Bytes)':<10}")
#     print("=" * 45)

#     # Sort capsules by size
#     sorted_capsules = sorted(capsule_data.items(), key=lambda x: x[1]["total"], reverse=True)
    
#     for name, data in sorted_capsules:
#         print(f"\n[{name}] Total: {data['total']} bytes")
#         # Show top 2 largest contributors in this capsule
#         for sym, s_size in sorted(data["symbols"], key=lambda x: x[1], reverse=True)[:2]:
#             clean_sym = sym.split("::")[-1] # Show only the function/struct name
#             print(f"  - {clean_sym:<27} | {s_size}")

#     print(f"\n\n{'SYSTEM OVERHEAD':<30} | {'SIZE (Bytes)':<10}")
#     print("-" * 45)
#     for name, size in sorted(system_overhead.items(), key=lambda x: x[1], reverse=True):
#         if size > 100: # Filter noise
#             print(f"{name:<30} | {size}")

# if __name__ == "__main__":
#     if len(sys.argv) < 2:
#         print("Usage: python3 script.py <path_to_elf>")
#     else:
#         analyze_kernel(sys.argv[1])

#!/usr/bin/env python3
"""
Tock OS kernel size breakdown tool.
Usage: python3 kernel_breakdown.py <path_to_elf>

Requires: arm-none-eabi-nm, rustfilt (cargo install rustfilt)
"""

import subprocess
import sys
import collections
import re


def demangle(symbols: list[str]) -> list[str]:
    """Pipe symbol names through rustfilt for proper Rust demangling."""
    try:
        result = subprocess.run(
            ["rustfilt"],
            input="\n".join(symbols),
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.splitlines()
    except FileNotFoundError:
        sys.exit("Error: rustfilt not found. Install it with: cargo install rustfilt")


def run_nm(elf_path: str) -> str:
    try:
        return subprocess.check_output(
            # No --demangle here — we do it ourselves with rustfilt
            ["arm-none-eabi-nm", "--print-size", "--size-sort", elf_path],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        sys.exit("Error: arm-none-eabi-nm not found. Is the ARM toolchain on your PATH?")
    except subprocess.CalledProcessError as e:
        sys.exit(f"Error running nm: {e}")


# Matches capsules_core::foo, capsules_extra::foo, capsules_system::foo
# After demangling, symbols look like:
#   <capsules_core::adc::AdcDedicated as kernel::syscall_driver::SyscallDriver>::command
CAPSULE_RE = re.compile(r'capsules_(core|extra|system)::([a-z0-9_]+)')


def parse(nm_output: str):
    lines = [l for l in nm_output.splitlines() if len(l.split()) >= 4]

    raw_symbols = []
    sizes = []
    for line in lines:
        parts = line.split()
        try:
            size = int(parts[1], 16)
        except ValueError:
            continue
        if size == 0:
            continue
        raw_symbols.append(parts[3])
        sizes.append(size)

    demangled = demangle(raw_symbols)

    # capsule_module -> { total, symbols: [(demangled_name, size)] }
    capsules = collections.defaultdict(lambda: {"total": 0, "symbols": []})
    # everything else bucketed by top-level crate
    other = collections.defaultdict(int)

    for sym, size in zip(demangled, sizes):
        match = CAPSULE_RE.search(sym)
        if match:
            module = match.group(2)  # e.g. "adc", "console", "sha256"
            capsules[module]["total"] += size
            capsules[module]["symbols"].append((sym, size))
        else:
            root = sym.split("::")[0].lstrip("<").strip()
            other[root] += size

    return capsules, other


def shorten(sym: str, max_len: int = 80) -> str:
    sym = sym.strip("<")
    return sym[:max_len] + "…" if len(sym) > max_len else sym


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: kernel_breakdown.py <path_to_elf>")

    elf = sys.argv[1]
    print(f"\nAnalyzing: {elf}\n")

    nm_out = run_nm(elf)
    capsules, other = parse(nm_out)

    # ── Capsule breakdown ────────────────────────────────────────────────────
    sorted_caps = sorted(capsules.items(), key=lambda x: x[1]["total"], reverse=True)
    total_capsule = sum(d["total"] for d in capsules.values())

    print("=" * 72)
    print(f"  CAPSULE BREAKDOWN  (total: {total_capsule} B)")
    print("=" * 72)
    print(f"  {'CAPSULE':<20} {'TOTAL (B)':>10}")
    print(f"  {'-'*20}  {'-'*10}")

    for module, data in sorted_caps:
        print(f"  {module:<20} {data['total']:>10}")
        for sym, size in sorted(data["symbols"], key=lambda x: x[1], reverse=True):
            print(f"      {size:>8}  {shorten(sym)}")

    # ── Everything else ──────────────────────────────────────────────────────
    total_other = sum(other.values())
    other_rows = sorted(other.items(), key=lambda x: x[1], reverse=True)
    other_rows = [(k, v) for k, v in other_rows if v > 100]

    print()
    print("=" * 72)
    print(f"  OTHER / KERNEL / CHIP  (total: {total_other} B)")
    print("=" * 72)
    print(f"  {'CRATE':<30} {'SIZE (B)':>10}")
    print(f"  {'-'*30}  {'-'*10}")
    for name, size in other_rows:
        print(f"  {name:<30} {size:>10}")

    grand_total = total_capsule + total_other
    print()
    print(f"  Grand total (text symbols): {grand_total} B")
    print()


if __name__ == "__main__":
    main()
