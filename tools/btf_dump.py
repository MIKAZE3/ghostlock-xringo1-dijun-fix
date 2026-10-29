#!/usr/bin/env python3
"""Parse the BTF blob embedded in the XRING O1 (dijun) kernel Image.

BTF is the authoritative source for struct layouts of this exact build, so it
lets us verify the offsets GhostLock/KSuRoot assume instead of guessing.
"""
import struct
import sys

IMAGE = "dijun-Image"
BTF_OFF = 0x16D8EFC

KIND_NAMES = {
    0: "UNKN", 1: "INT", 2: "PTR", 3: "ARRAY", 4: "STRUCT", 5: "UNION",
    6: "ENUM", 7: "FWD", 8: "TYPEDEF", 9: "VOLATILE", 10: "CONST",
    11: "RESTRICT", 12: "FUNC", 13: "FUNC_PROTO", 14: "VAR", 15: "DATASEC",
    16: "FLOAT", 17: "DECL_TAG", 18: "TYPE_TAG", 19: "ENUM64",
}
# extra bytes per kind when vlen is not fixed by the count
EXTRA = {1: 4, 3: 12, 14: 4, 17: 4, 18: 0}


class Btf:
    def __init__(self, data, off):
        (magic, version, flags, hdr_len, type_off, type_len,
         str_off, str_len) = struct.unpack_from("<HBBIIIII", data, off)
        if magic != 0xEB9F:
            raise SystemExit(f"bad BTF magic 0x{magic:04X} at 0x{off:X}")
        self.version = version
        self.type_start = off + hdr_len + type_off
        self.type_end = self.type_start + type_len
        self.str_start = off + hdr_len + str_off
        self.str_end = self.str_start + str_len
        self.data = data
        self.types = [None]          # BTF type ids are 1-based
        self._parse()

    def string(self, off):
        if off == 0:
            return ""
        start = self.str_start + off
        end = self.data.find(b"\x00", start)
        return self.data[start:end].decode("utf-8", "replace")

    def _parse(self):
        d, pos, end = self.data, self.type_start, self.type_end
        while pos < end:
            name_off, info, size_or_type = struct.unpack_from("<III", d, pos)
            pos += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kind_flag = (info >> 31) & 1
            t = {
                "id": len(self.types),
                "name": self.string(name_off),
                "kind": kind,
                "kind_name": KIND_NAMES.get(kind, f"?{kind}"),
                "vlen": vlen,
                "kind_flag": kind_flag,
                "size_or_type": size_or_type,
                "members": None,
            }
            if kind in (4, 5):                       # STRUCT / UNION
                members = []
                for _ in range(vlen):
                    m_name, m_type, m_off = struct.unpack_from("<III", d, pos)
                    pos += 12
                    if kind_flag:
                        bit_off = m_off & 0xFFFFFF
                        bit_size = m_off >> 24
                    else:
                        bit_off, bit_size = m_off, 0
                    members.append({
                        "name": self.string(m_name),
                        "type": m_type,
                        "bit_off": bit_off,
                        "bit_size": bit_size,
                    })
                t["members"] = members
                t["size"] = size_or_type
            elif kind == 3:                          # ARRAY
                pos += 12
            elif kind == 6:                          # ENUM
                pos += 8 * vlen
            elif kind == 19:                         # ENUM64
                pos += 12 * vlen
            elif kind == 13:                         # FUNC_PROTO
                pos += 8 * vlen
            elif kind == 15:                         # DATASEC
                pos += 12 * vlen
            else:
                pos += EXTRA.get(kind, 0)
                if kind in (1, 4, 5, 6, 15, 19):
                    t["size"] = size_or_type
            self.types.append(t)

    def find_struct(self, name):
        for t in self.types:
            if t and t["kind"] in (4, 5) and t["name"] == name:
                return t
        return None


def dump_struct(btf, name, want=None, limit=400):
    t = btf.find_struct(name)
    if not t:
        print(f"!! struct {name} not found")
        return None
    print(f"\n=== struct {name} (size 0x{t['size']:X} = {t['size']} bytes, "
          f"{len(t['members'])} members) ===")
    shown = 0
    for m in t["members"]:
        if want and m["name"] not in want:
            continue
        off = m["bit_off"] // 8
        print(f"  +0x{off:04X}  {m['name']}")
        shown += 1
        if shown >= limit:
            break
    if want:
        found = {m["name"] for m in t["members"]}
        for w in want:
            if w not in found:
                print(f"  -- {w}: NOT PRESENT")
    return t


def offsets_of(btf, name):
    t = btf.find_struct(name)
    if not t:
        return {}
    return {m["name"]: m["bit_off"] // 8 for m in t["members"]}


def main():
    with open(IMAGE, "rb") as f:
        data = f.read()
    btf = Btf(data, BTF_OFF)
    print(f"BTF version {btf.version}, {len(btf.types)-1} types parsed")
    print(f"type section 0x{btf.type_start:X}..0x{btf.type_end:X}, "
          f"strings 0x{btf.str_start:X}..0x{btf.str_end:X}")

    checks = [
        ("task_struct", ["cred", "real_cred", "comm", "pid", "tgid",
                         "pi_waiters", "pi_blocked_on", "pi_lock",
                         "pi_top_task", "seccomp", "tasks", "real_parent",
                         "thread_info", "uclamp_req", "atomic_flags"]),
        ("cred", ["uid", "gid", "euid", "cap_effective", "cap_permitted",
                  "security", "user", "user_ns", "ucounts", "group_info"]),
        ("rt_mutex_waiter", ["tree", "pi_tree", "task", "lock", "wake_state",
                             "ww_ctx"]),
        ("rt_mutex", ["owner", "wait_lock", "waiters", "rt_tree"]),
        ("seccomp", ["mode", "filter_count", "filter"]),
    ]
    for name, want in checks:
        dump_struct(btf, name, want)

    # struct sizes are independent evidence for the waiter layout
    print("\n=== struct sizes ===")
    for name in ["task_struct", "cred", "rt_mutex_waiter", "rt_mutex",
                 "rt_mutex_base", "seccomp", "thread_info"]:
        t = btf.find_struct(name)
        if t:
            print(f"  {name}: 0x{t['size']:X} ({t['size']})")


if __name__ == "__main__":
    main()