# Linux Kernel v7.0-rc1 - Linux Kernel v7.0-rc3 Vulnerabilities

## Summary

8 vulnerabilities discovered in Linux Kernel **v7.0-rc1** - **v7.0-rc3**

| # | Bug Type | Location |
|---|----------|----------|
| 1 | `slab-use-after-free` Read | `sock_def_readable` |
| 2 | `NULL pointer dereference` | `netfs_unbuffered_write` |
| 3 | `slab-use-after-free` Read | `rds_conn_path_drop` |
| 4 | `use-after-free` Write | `fuse_copy_do` |
| 5 | `slab-use-after-free` Read | `bpf_trace_run9` |
| 6 | `slab-use-after-free` Read | `bpf_trace_run3` |
| 7 | `slab-out-of-bounds` Write | `do_con_write` |
| 8 | `slab-use-after-free` Read | `futex_unqueue` |

>  **Vulnerability Notes:** All findings require further analysis.

---

## Vulnerability Details

### 1. slab-use-after-free Read in `sock_def_readable`

**Subsystem:** `net/core/sock.c`  
**Type:** KASAN slab-use-after-free (Read, size 8)  
**Triggered by:** `kworker/0:4` via MLD multicast workqueue

**Call Chain:**
```
mld_ifc_work → mld_send_cr → mld_sendpack → ip6_output
  → __dev_queue_xmit → dev_hard_start_xmit
  → lec_start_xmit → send_to_lecd
  → sock_def_readable  ← BUG HERE
```

**KASAN Report:**
```
BUG: KASAN: slab-use-after-free in sock_def_readable+0x1cb/0x580 net/core/sock.c:3610
Read of size 8 at addr ffff888047cb0c00 by task kworker/0:4/5308
CPU: 0 UID: 0 PID: 5308
```

<details>
<summary>Full Stack Trace</summary>

```
Call Trace:
 <TASK>
 dump_stack_lvl+0xe8/0x150 lib/dump_stack.c:120
 kasan_report+0x117/0x150 mm/kasan/report.c:595
 list_empty include/linux/list.h:381 [inline]
 waitqueue_active include/linux/wait.h:127 [inline]
 wq_has_sleeper include/linux/wait.h:161 [inline]
 skwq_has_sleeper include/net/sock.h:2404 [inline]
 sock_def_readable+0x1cb/0x580 net/core/sock.c:3610
 send_to_lecd+0x322/0x600 net/atm/lec.c:538
 lec_arp_resolve net/atm/lec.c:1787 [inline]
 lec_start_xmit+0xec0/0x2660 net/atm/lec.c:285
 mld_ifc_work+0x835/0xe70 net/ipv6/mcast.c:2693
 process_one_work kernel/workqueue.c:3275 [inline]
 worker_thread+0xa50/0xfc0 kernel/workqueue.c:3439
 </TASK>
```
</details>

---

### 2. NULL Pointer Dereference in `netfs_unbuffered_write`

**Subsystem:** `fs/netfs/direct_write.c`  
**Type:** Kernel NULL pointer dereference (instruction fetch)  
**Triggered by:** `syz.0.17` via `write()` syscall on 9p filesystem

**Call Chain:**
```
ksys_write → vfs_write → v9fs_file_write_iter
  → netfs_unbuffered_write_iter → netfs_unbuffered_write_iter_locked
  → netfs_unbuffered_write  ← BUG HERE (RIP: 0x0)
```

**KASAN Report:**
```
BUG: kernel NULL pointer dereference, address: 0000000000000000
#PF: supervisor instruction fetch in kernel mode
#PF: error_code(0x0010) - not-present page
RIP: 0010:0x0
```

> **Note:** Preceded by `netfs: Couldn't get user pages (rc=-14)` — indicates failed user page pin leading to NULL function pointer call.

<details>
<summary>Full Stack Trace</summary>

```
Call Trace:
 <TASK>
 netfs_unbuffered_write+0xae5/0x2080 fs/netfs/direct_write.c:189
 netfs_unbuffered_write_iter_locked+0x801/0xab0 fs/netfs/direct_write.c:287
 netfs_unbuffered_write_iter+0x40c/0x710 fs/netfs/direct_write.c:377
 v9fs_file_write_iter+0xbf/0x100 fs/9p/vfs_file.c:409
 vfs_write+0x6ac/0x1070 fs/read_write.c:688
 ksys_write+0x12a/0x250 fs/read_write.c:740
 </TASK>
```
</details>

---

### 3. slab-use-after-free Read in `rds_conn_path_drop`

**Subsystem:** `net/rds/connection.c`  
**Type:** KASAN slab-use-after-free (Read, size 4)  
**Triggered by:** `kworker/u32:0` via InfiniBand MAD timeout

**Call Chain:**
```
timeout_sends → cm_send_handler → cma_ib_handler → cma_cm_event_handler
  → rds_rdma_cm_event_handler_cmn → rds_conn_path_drop  ← BUG HERE
```

**Root Cause:** `net_namespace` object freed while still referenced via RDS connection path. The freed `net_namespace` cache object (size 9536) is accessed 384 bytes into the freed region.

**KASAN Report:**
```
BUG: KASAN: slab-use-after-free in rds_conn_path_drop+0x11d/0x3c0 net/rds/connection.c:914
Read of size 4 at addr ffff88804ae88180 by task kworker/u32:0/23206
```

<details>
<summary>Full Stack Trace + Alloc/Free Info</summary>

```
Allocated by task 26019:
 copy_net_ns+0xe8/0x7c0 net/core/net_namespace.c:565
 create_new_namespaces+0x3ea/0xac0 kernel/nsproxy.c:130
 ksys_unshare+0x473/0xad0 kernel/fork.c:3174

Freed by task 14441:
 cleanup_net+0x51a/0x920 net/core/net_namespace.c:713
 process_one_work+0x9d7/0x1920 kernel/workqueue.c:3275
```
</details>

---

### 4. use-after-free Write in `fuse_copy_do`

**Subsystem:** `fs/fuse/dev.c`  
**Type:** KASAN use-after-free (Write, size 2)  
**Triggered by:** `syz.0.17` via `write()` syscall to FUSE device  


**Call Chain:**
```
ksys_write → vfs_write → fuse_dev_write → fuse_dev_do_write
  → fuse_notify → fuse_notify_store → fuse_copy_folio
  → fuse_copy_do  ← BUG HERE (__asan_memcpy)
```

**KASAN Report:**
```
BUG: KASAN: use-after-free in fuse_copy_do+0x193/0x380 fs/fuse/dev.c
Write of size 2 at addr ffff888070528fff by task syz.0.17/6005
```

> **Note:** Write crosses a page boundary (`0x...fff`) into freed memory. The page was freed via `exit_mmap` → `tlb_flush_mmu` → `free_pages_and_swap_cache`.

<details>
<summary>Full Stack Trace</summary>

```
Call Trace:
 <TASK>
 __asan_memcpy+0x40/0x70 mm/kasan/shadow.c:106
 fuse_copy_do+0x193/0x380 fs/fuse/dev.c
 fuse_copy_folio+0xefc/0x1b00 fs/fuse/dev.c:1166
 fuse_notify_store fs/fuse/dev.c:1821 [inline]
 fuse_dev_do_write+0x2b9d/0x4060 fs/fuse/dev.c:2205
 fuse_dev_write+0x177/0x220 fs/fuse/dev.c:2289
 vfs_write+0x61d/0xb90 fs/read_write.c:688
 </TASK>
```
</details>

---

### 5. slab-use-after-free Read in `bpf_trace_run9`

**Subsystem:** `kernel/trace/bpf_trace.c`  
**Type:** KASAN slab-use-after-free (Read, size 8)  
**Triggered by:** `syz.5.56` via `connect()` syscall on vsock

**Call Chain:**
```
__sys_connect → vsock_connect → virtio_transport_connect
  → virtio_transport_send_pkt_info → virtio_transport_alloc_skb
  → trace_virtio_transport_alloc_pkt → __traceiter_virtio_transport_alloc_pkt
  → bpf_trace_run9  ← BUG HERE
```

**Root Cause:** BPF raw tracepoint link (`bpf_raw_tp_link`) freed via RCU (`kfree` in `rcu_do_batch`) while still being accessed in BPF trace run. Object is from `kmalloc-192` cache, accessed 24 bytes into the freed 192-byte region.

**KASAN Report:**
```
BUG: KASAN: slab-use-after-free in bpf_trace_run9+0x13b/0x8c0 kernel/trace/bpf_trace.c:2136
Read of size 8 at addr ffff888039269618 by task syz.5.56/5665
```

<details>
<summary>Full Stack Trace + Alloc/Free Info</summary>

```
Allocated by task 5664:
 bpf_raw_tp_link_attach+0x278/0x700 kernel/bpf/syscall.c:4264
 bpf_raw_tracepoint_open+0x1b2/0x220 kernel/bpf/syscall.c:4312
 __sys_bpf+0x846/0x950 kernel/bpf/syscall.c:6270

Freed by task 5576:
 kfree+0x1c1/0x630 mm/slub.c:6442
 rcu_do_batch kernel/rcu/tree.c:2617 [inline]
 rcu_core+0x7cd/0x1070 kernel/rcu/tree.c:2869
```
</details>

---

### 6. slab-use-after-free Read in `bpf_trace_run3`

**Subsystem:** `kernel/trace/bpf_trace.c`  
**Type:** KASAN slab-use-after-free (Read, size 8)  
**Triggered by:** `dhcpcd-run-hook` via `execve()` syscall

**Call Chain:**
```
__x64_sys_execve → load_elf_binary → begin_new_exec → exec_mmap
  → exit_mmap → free_pgtables → unlink_anon_vmas
  → kmem_cache_free → trace_kmem_cache_free
  → __traceiter_kmem_cache_free → bpf_trace_run3  ← BUG HERE
```

**Root Cause:** Same class of bug as #5 — BPF raw tracepoint link freed via RCU while still in use. `kmalloc-192` cache object accessed 24 bytes into a freed 192-byte region.

**KASAN Report:**
```
BUG: KASAN: slab-use-after-free in bpf_trace_run3+0xdd/0x850 kernel/trace/bpf_trace.c:2130
Read of size 8 at addr ffff88803828ab18 by task dhcpcd-run-hook/5487
```

<details>
<summary>Full Stack Trace + Alloc/Free Info</summary>

```
Allocated by task 5486:
 bpf_raw_tp_link_attach+0x278/0x700 kernel/bpf/syscall.c:4264
 bpf_raw_tracepoint_open+0x1b2/0x220 kernel/bpf/syscall.c:4312

Freed by task 15:
 kfree+0x1c1/0x630 mm/slub.c:6461
 rcu_do_batch kernel/rcu/tree.c:2617 [inline]
 rcu_core+0x7cd/0x1070 kernel/rcu/tree.c:2869
```
</details>

---

### 7. slab-out-of-bounds Write in `do_con_write`

**Subsystem:** `drivers/tty/vt/vt.c`  
**Type:** KASAN slab-out-of-bounds (Write, size 2)  
**Triggered by:** `syz.2.556` via `write()` to TTY  


**Call Chain:**
```
ksys_write → vfs_write → redirected_tty_write → tty_write
  → file_tty_write → n_tty_write → process_output_block
  → con_write → do_con_write → vc_con_write_normal  ← BUG HERE
```

**Root Cause:** Write of 2 bytes at `ffff888037925fb0` — **4016 bytes past the end** of an allocated 4096-byte `kmalloc-4k` region. The buffer allocated by `kobject_uevent_env` was freed before the virtual console write completed.

**KASAN Report:**
```
BUG: KASAN: slab-out-of-bounds in do_con_write+0x386f/0x8540 drivers/tty/vt/vt.c:3226
Write of size 2 at addr ffff888037925fb0 by task syz.2.556/8668
```

<details>
<summary>Full Stack Trace + Alloc/Free Info</summary>

```
Allocated by task 8646:
 kobject_uevent_env+0x263/0x18b0 lib/kobject_uevent.c:540
 netdev_register_kobject+0x290/0x3d0 net/core/net-sysfs.c:2362
 register_netdevice+0x12e0/0x2210 net/core/dev.c:11411

Freed by task 8646:
 kobject_uevent_env+0x2e2/0x18b0 lib/kobject_uevent.c:640
 (same allocation path — freed within same uevent function)
```
</details>

---

### 8. slab-use-after-free Read in `futex_unqueue`

**Subsystem:** `kernel/futex/core.c`  
**Type:** KASAN slab-use-after-free (Read, size 1)  
**Triggered by:** `syz.0.19` via `futex()` syscall  


**Call Chain:**
```
__x64_sys_futex → futex_wait → __futex_wait
  → futex_unqueue → spin_lock → _raw_spin_lock  ← BUG HERE
```

**Root Cause:** `futex_hash` table freed by `futex_hash_free` during `do_exit` while another thread still holds a reference and attempts to acquire a spinlock within `futex_unqueue`. The freed region belongs to `kmalloc-cg-4k` (size 4096), accessed 992 bytes in.

**KASAN Report:**
```
BUG: KASAN: slab-use-after-free in _raw_spin_lock+0x2e/0x40 kernel/locking/spinlock.c:154
Read of size 1 at addr ffff888033ce23e0 by task syz.0.19/6039
```

<details>
<summary>Full Stack Trace + Alloc/Free Info</summary>

```
Allocated by task 6038:
 futex_hash_allocate+0x40b/0x1090 kernel/futex/core.c:1812
 futex_hash_allocate_default+0x2ca/0x5b0 kernel/futex/core.c:1921
 copy_process+0x4eb5/0x79b0 kernel/fork.c:2344
 kernel_clone+0xfc/0x930 kernel/fork.c:2654
 __do_sys_clone3+0x214/0x290 kernel/fork.c:2956

Freed by task 6038:
 futex_hash_free+0x98/0xc0 kernel/futex/core.c:1739
 __mmput+0x30c/0x410 kernel/fork.c:1185
 do_exit+0x78a/0x2a30 kernel/exit.c:959
```
</details>


##  Bug Classification

| # | Subsystem | Bug Class | Access Type | Size |
|---|-----------|-----------|-------------|------|
| 1 | `net/core` (ATM/MLD) | use-after-free | Read | 8 bytes |
| 2 | `fs/netfs` (9p) | NULL ptr deref | Exec | — |
| 3 | `net/rds` (RDMA) | use-after-free | Read | 4 bytes |
| 4 | `fs/fuse` | use-after-free | Write | 2 bytes |
| 5 | `kernel/bpf` (vsock trace) | use-after-free | Read | 8 bytes |
| 6 | `kernel/bpf` (kmem trace) | use-after-free | Read | 8 bytes |
| 7 | `drivers/tty/vt` | out-of-bounds | Write | 2 bytes |
| 8 | `kernel/futex` | use-after-free | Read | 1 byte |
