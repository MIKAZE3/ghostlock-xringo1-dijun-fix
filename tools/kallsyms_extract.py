#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kallsyms_extract.py -- 从 arm64 内核映像 (PE32+ COFF / 原始 Image) 中自动定位并解析
Linux kallsyms 符号表，输出 "符号名 -> 映像偏移"。

不依赖 pyelftools / 第三方库。映像约定 "文件偏移 == 虚拟地址 (ImageBase=0)"。

自动定位思路（全部基于结构自洽性，不硬编码地址）:
  1. kallsyms_token_index: 256 个 u16, 首元素 0, 严格递增, 且每个值必须是前面
     256 个 NUL 结尾字符串的累计偏移 -> 用前缀和精确校验.
  2. kallsyms_token_table = token_index 之前 256 个 C 字符串 (总长 = idx[255]+1+pad).
  3. kallsyms_markers: token_table 之前的 u32 数组, 首元素 0, 严格递增,
     每 256 个符号一项 -> 向前回溯得到数组起点.
  4. kallsyms_names: 压缩流 (1 字节长度 + N 个 token 索引字节). 起点未知, 但
     "第 256*k 条记录结束位置 - start == markers[k]" 这一约束可精确定位起点;
     搜索窗口由 markers[-1] 与剩余记录上界推出.
  5. 已解出的 names 反推实际记录条数 = kallsyms_num_syms, 并与 names 之前
     4 字节的 u32 对照.
  6. kallsyms_offsets: token_index 之后的 s32 数组, 长度 = num_syms (按地址排序,
     单调不减). 其后 8 字节即 kallsyms_relative_base (0xffffffc0xxxxxxxx).

用法:
  python kallsyms_extract.py dijun-Image                 # 定位 + 校验 + 打印关键符号
  python kallsyms_extract.py dijun-Image --dump syms.tsv # 导出全部符号
  python kallsyms_extract.py dijun-Image --lookup start_kernel do_select
  python kallsyms_extract.py dijun-Image --json layout.json
"""
import struct
import sys
import json
import argparse
import bisect


class Image:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self.n = len(self.data)

    def u16(self, o):
        return struct.unpack_from("<H", self.data, o)[0]

    def u32(self, o):
        return struct.unpack_from("<I", self.data, o)[0]

    def s32(self, o):
        return struct.unpack_from("<i", self.data, o)[0]

    def u64(self, o):
        return struct.unpack_from("<Q", self.data, o)[0]

    def find(self, pat, start=0, end=None):
        if end is None:
            end = self.n
        return self.data.find(pat, start, end)


def find_token_index(img):
    """返回 (token_index_off, token_table_off, n_tokens=256)。"""
    d = img.data
    o = 0
    while True:
        o = d.find(b"\x00\x00", o)
        if o < 0:
            return None
        if o % 2 == 0:
            idx = list(struct.unpack_from("<256H", d, o))
            if idx[0] == 0 and 100 < idx[255] < 20000 and \
               all(idx[i] < idx[i + 1] for i in range(255)):
                # 用前缀和验证 token_table 起点:
                # 表长 = idx[255] + len(最后一个 token) + 1 + 对齐 padding
                for pad in range(0, 80):
                    s = o - idx[255] - 1 - pad
                    if s < 0:
                        continue
                    if not (0 <= s and s + idx[255] + 1 <= o):
                        continue
                    p, ok = s, True
                    nonempty = 0
                    for k in range(256):
                        if p - s != idx[k]:
                            ok = False
                            break
                        q = d.find(b"\x00", p, o + 1)
                        if q < 0:
                            ok = False
                            break
                        if any(c < 0x20 or c > 0x7e for c in d[p:q]):
                            ok = False
                            break
                        if q > p:
                            nonempty += 1
                        p = q + 1
                    # 真实 token 表绝大多数表项非空; 全 0 的递增 u16 序列是假阳性
                    if ok and p <= o and nonempty >= 64:
                        return o, s, 256
        o += 1


def find_markers(img, table_off):
    """token_table 之前紧跟 kallsyms_markers(u32, 首项 0, 严格递增)."""
    for pad in range(0, 8, 4):
        end = table_off - pad
        if end < 8 or end % 4:
            continue
        vals = []
        p = end
        while p - 4 >= 0:
            v = img.u32(p - 4)
            if vals and v >= vals[-1]:
                break
            vals.append(v)
            p -= 4
            if v == 0:
                break
        vals.reverse()
        if len(vals) >= 50 and vals[0] == 0 and all(
                vals[i] < vals[i + 1] for i in range(len(vals) - 1)):
            diffs = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]
            if min(diffs) > 16 and max(diffs) < 20000:
                return end - 4 * len(vals), vals
    return None, None


def find_names(img, n_markers, markers, names_end):
    """在 [names_end - markers[-1] - 256*160, names_end - markers[-1]] 内搜索 names 起点。"""
    lo = max(0, names_end - markers[-1] - 256 * 160)
    hi = names_end - markers[-1]
    for s in range(lo, hi + 1):
        # 快速校验前若干个 256 组边界
        p, ok = s, True
        for k in range(1, min(n_markers, 4)):
            for _ in range(256):
                p += 1 + img.data[p]
                if p > names_end:
                    ok = False
                    break
            if not ok or p - s != markers[k]:
                ok = False
                break
        if not ok:
            continue
        # 完整解析: 记录长度为 0 只可能是尾部对齐 padding, 遇到即停止
        p, cnt = s, 0
        while p < names_end and img.data[p] != 0:
            p += 1 + img.data[p]
            cnt += 1
            if p > names_end:
                break
        if 0 <= names_end - p <= 8:
            return s, cnt
    return None, None


def parse_kallsyms(img, verbose=True):
    r = {}
    ti = find_token_index(img)
    if not ti:
        raise SystemExit("token_index not found")
    r["token_index"] = ti[0]
    r["token_table"] = ti[1]
    idx = list(struct.unpack_from("<256H", img.data, ti[0]))
    tokens = []
    for k in range(256):
        e = img.data.find(b"\x00", ti[1] + idx[k])
        tokens.append(img.data[ti[1] + idx[k]:e])
    r["token_table_size"] = idx[255] + 1 + (ti[0] - (ti[1] + idx[255] + 1))

    ms, markers = find_markers(img, ti[1])
    if ms is None:
        raise SystemExit("markers not found")
    r["markers"] = ms
    r["markers_count"] = len(markers)

    # names 结束位置: markers 起点之前可能 0..4 字节对齐 padding
    names_end = ms
    s, n = find_names(img, len(markers), markers, names_end)
    if s is None:
        # 允许 names 尾部 4 字节 padding
        for pad in (4, 8, 2):
            s, n = find_names(img, len(markers), markers, ms - pad)
            if s is not None:
                names_end = ms - pad
                break
    if s is None:
        raise SystemExit("names not found")
    r["names"] = s
    r["names_size"] = names_end - s
    r["num_syms"] = n

    # num_syms u32 应紧邻 names 之前（允许 0..8 字节 0 padding）
    for back in (4, 8, 12, 16):
        if s - back >= 0 and img.u32(s - back) == n:
            r["num_syms_field"] = s - back
            break

    def expand(p):
        ln = img.data[p]
        p += 1
        out = []
        for i in range(ln):
            t = tokens[img.data[p + i]]
            if t:
                out.append(t.decode("latin1"))
        return "".join(out), p + ln

    names = []
    p = s
    for _ in range(n):
        nm, p = expand(p)
        names.append(nm)
    assert all(names), "empty symbol name decoded (bad names start?)"
    r["names_end"] = p

    # offsets 紧跟 token_index 之后(4/8 对齐)
    off_pos = ti[0] + 512
    while off_pos < img.n and off_pos % 4:
        off_pos += 1
    offs = [img.s32(off_pos + 4 * k) for k in range(n)]
    # 校验单调不减 & 其后 8 字节为内核线性地址
    dec = sum(1 for k in range(1, n) if offs[k] < offs[k - 1])
    rb = img.u64(off_pos + 4 * n)
    if dec > n // 1000 or not (0xffffff8000000000 <= rb <= 0xffffffffffffffff):
        # 兜底: 在 token_index 后 16 字节内找真正的起点
        for cand in range(ti[0] + 512, ti[0] + 512 + 16, 4):
            o2 = [img.s32(cand + 4 * k) for k in range(n)]
            if sum(1 for k in range(1, n) if o2[k] < o2[k - 1]) <= n // 1000:
                rb2 = img.u64(cand + 4 * n)
                if 0xffffff8000000000 <= rb2 <= 0xffffffffffffffff:
                    off_pos, offs, rb = cand, o2, rb2
                    break
    r["offsets"] = off_pos
    r["offsets_size"] = 4 * n
    r["relative_base"] = rb
    r["relative_base_off"] = off_pos + 4 * n
    r["decreases"] = dec

    syms = [(names[i][1:], names[i][0], offs[i]) for i in range(n)]
    r["symbols"] = syms
    if verbose:
        print("[+] token_index  0x%08X  (256*2 = 512 B)" % r["token_index"])
        print("[+] token_table  0x%08X  (%d B)" % (r["token_table"], r["token_table_size"]))
        print("[+] markers      0x%08X  (%d * 4 = %d B)" % (ms, len(markers), 4 * len(markers)))
        print("[+] names        0x%08X  (%d B, %.2f B/sym)" %
              (s, r["names_size"], r["names_size"] / n))
        print("[+] num_syms     0x%08X  = %d" % (r.get("num_syms_field", -1), n))
        print("[+] offsets      0x%08X  (%d * 4 = %d B)" % (off_pos, n, 4 * n))
        print("[+] relative_base 0x%08X = 0x%016X" % (r["relative_base_off"], rb))
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--dump")
    ap.add_argument("--json")
    ap.add_argument("--lookup", nargs="*")
    ap.add_argument("--anchors", nargs="*", default=["init_task=0x020DE280",
                                                    "init_cred=0x020F0548"])
    a = ap.parse_args()
    img = Image(a.image)
    r = parse_kallsyms(img)
    by_name = {}
    for nm, ty, off in r["symbols"]:
        by_name.setdefault(nm, []).append((ty, off))

    print("\n[*] anchors:")
    ok_all = True
    for spec in a.anchors:
        nm, val = spec.split("=")
        want = int(val, 16)
        got = [o for _, o in by_name.get(nm, [])]
        ok = want in got
        ok_all &= ok
        print("    %-12s expect 0x%08X  got %s  %s" %
              (nm, want, [hex(x) for x in got] or "MISSING", "OK" if ok else "FAIL"))

    print("\n[*] key symbols:")
    for nm in ["core_sys_select", "do_select", "futex_wait_requeue_pi",
               "rt_mutex_adjust_prio_chain", "__arm64_sys_getpid", "start_kernel"]:
        for ty, off in by_name.get(nm, []):
            print("    %-28s %s  0x%08X" % (nm, ty, off))

    if a.lookup:
        print()
        for nm in a.lookup:
            for ty, off in by_name.get(nm, []):
                print("    %-40s %s  0x%08X" % (nm, ty, off))

    if a.dump:
        with open(a.dump, "w", encoding="utf-8") as f:
            f.write("# idx\ttype\timage_offset\tname\n")
            for i, (nm, ty, off) in enumerate(r["symbols"]):
                f.write("%d\t%s\t0x%08X\t%s\n" % (i, ty, off, nm))
        print("\n[+] wrote %s (%d symbols)" % (a.dump, len(r["symbols"])))

    if a.json:
        meta = {k: v for k, v in r.items() if k != "symbols"}
        meta["image_size"] = img.n
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        print("[+] wrote %s" % a.json)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())