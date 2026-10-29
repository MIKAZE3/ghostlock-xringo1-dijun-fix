#!/usr/bin/env python3
"""Locate kallsyms_token_table / token_index in the raw arm64 Image (v2).

A token table is 256 consecutive NUL-terminated ASCII strings. Immediately
after it sits kallsyms_token_index: 256 * u16, non-decreasing, where entry i is
the byte offset of token i inside the table. Scanning with that pair of
constraints is far more robust than assuming the table ends flush.
"""
import struct

IMAGE = "dijun-Image"


def main():
    data = open(IMAGE, "rb").read()
    n = len(data)
    print(f"image {n} bytes")

    cands = []
    # idx_off is where the u16[256] array starts; must be 2-byte aligned.
    for idx_off in range(2, n - 512, 2):
        if data[idx_off] != 0 or data[idx_off + 1] != 0:
            continue                       # vals[0] must be 0
        v1 = data[idx_off + 2] | (data[idx_off + 3] << 8)
        if not (1 <= v1 <= 8):
            continue                       # token 1 starts within first chars
        # cheap monotonic check on the remaining pairs
        prev = v1
        ok = True
        for k in range(2, 256):
            o = idx_off + 2 * k
            v = data[o] | (data[o + 1] << 8)
            if v < prev or v > 16384:
                ok = False
                break
            prev = v
        if not ok:
            continue

        # walk back 256 NUL-terminated strings from just before idx_off
        end = idx_off
        while end > 0 and data[end - 1] == 0:
            end -= 1                       # skip alignment padding NULs
        pos = end
        starts = []
        for _ in range(256):
            while pos > 0 and data[pos - 1] != 0:
                pos -= 1
            starts.append(pos)
            if pos > 0:
                pos -= 1                   # step over the NUL
        table_off = pos
        starts.reverse()                   # now starts[0] is first token

        # every byte in the table must be printable or NUL
        region = data[table_off:end]
        if any(b != 0 and not (0x20 <= b < 0x7F) for b in region):
            continue
        # token offsets must line up with the string starts we walked back
        vals = struct.unpack_from("<256H", data, idx_off)
        if [s - table_off for s in starts] != list(vals):
            continue
        tokens = []
        for i, s in enumerate(starts):
            e = end if i == 255 else starts[i + 1] - 1
            tokens.append(data[s:e].decode("ascii", "replace"))
        cands.append((table_off, idx_off, tokens))
        if len(cands) >= 3:
            break

    print(f"candidates: {len(cands)}")
    for table_off, idx_off, tokens in cands:
        joined = "".join(tokens)
        print(f"\n  table@0x{table_off:X} index@0x{idx_off:X}")
        nonempty = [t for t in tokens if t]
        print(f"  non-empty tokens: {len(nonempty)}")
        print(f"  sample: {nonempty[:20]}")
        for probe in ("sys_select", "futex", "rt_mutex", "selinux", "kallsyms"):
            print(f"    '{probe}': {probe in joined}")


if __name__ == "__main__":
    main()