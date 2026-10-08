# bpf_alignchecker.c

## 用途

**不是**真正跑在内核里的 BPF 程序。它是 Cilium 用来做 **Go 侧与 BPF 侧结构体内存布局一致性校验** 的一个"伪 BPF"编译单元：把 `lib/*.h` 里所有被 Go 侧 (`pkg/alignchecker/testdata/`) 对照的 C 结构体都"实例化"一遍，再由 `pkg/alignchecker` 读取编译出来的 `bpf_alignchecker.o` 的 DWARF/BTF，和 Go 结构体 (`gopkg/sys/btrfs/...` 或 datapath 里的对应类型) 一一比较大小 / 字段偏移。

Build 入口在 `bpf/Makefile:146-149` 的 `testdata` 目标，用 `--target=bpf -c` 编译 `bpf_alignchecker.c` 得到 `bpf_foo.o` / `bpf_alignchecker.o`，之后 Go 单元测试 `pkg/alignchecker` 加载 BTF 读 symbol。

## 实现技巧：`add_type` 宏

```c
#define __add_type(TYPE, N) TYPE _ ## N
#define __expand(TYPE, N) __add_type(TYPE, N)
#define add_type(TYPE) __expand(TYPE, __COUNTER__)
```

- `__COUNTER__` 每次展开会 +1，`__expand` 保证先展开成数字再和 `_` 拼接，否则会得到 `_ __COUNTER__` 这种字符串。
- 所以文件里每个 `add_type(struct X);` 都展开为 `struct X _<N>;` —— 文件作用域的一个全局变量声明。
- 这样编译器就被迫把该结构体真正放到可执行文件里（否则作为未使用类型可能被 BTF 省略），后续工具就能通过 DWARF/BTF 看到字段偏移。

## 被声明的结构体清单（按 include 顺序）

| include | 结构体 |
|---------|--------|
| `lib/common.h` | `ipv4_ct_tuple`, `ipv6_ct_tuple` |
| `lib/conntrack.h` | `ct_entry` |
| `lib/eps.h` | `endpoint_key`, `endpoint_info`, `ipcache_key`, `remote_endpoint_info` |
| `lib/lb.h` | `lb4_key`, `lb4_service`, `lb4_backend`, `lb6_key`, `lb6_service`, `lb6_backend`, `lb4_affinity_key`, `lb6_affinity_key`, `lb_affinity_val`, `lb_affinity_match`, `lb4_src_range_key`, `lb6_src_range_key` |
| `lib/metrics.h` | `metrics_key`, `metrics_value` |
| `lib/policy.h` | `policy_key`, `policy_entry` |
| `lib/nat.h` | `ipv4_nat_entry`, `ipv6_nat_entry` |
| `lib/trace.h` | `trace_notify` |
| `lib/drop.h` | `drop_notify` |
| `lib/policy_log.h` | `policy_verdict_notify` |
| `lib/dbg.h` | `debug_msg`, `debug_capture_msg` |
| `lib/sock.h` | `ipv4_revnat_tuple/entry`, `ipv6_revnat_tuple/entry` |
| `lib/ipv4.h` / `ipv6.h` | `ipv4/ipv6_frag_id`, `ipv4/ipv6_frag_l4ports` |
| `lib/eth.h` | `union macaddr` |
| `lib/edt.h` | `edt_id`, `edt_info` |
| `lib/egress_gateway.h` | `egress_gw_policy_key/entry_v2`, `_key6/entry6` |
| `lib/vtep.h` | `vtep_key`, `vtep_value` |
| `lib/srv6_maps.h` | `srv6_vrf_key4/6`, `srv6_policy_key4/6` |
| `lib/trace_sock.h` | `trace_sock_notify` |
| `lib/ipsec.h` | `encrypt_config` |
| `lib/mcast.h` | `mcast_subscriber_v4` |
| `lib/node.h` | `node_key`, `node_value` |
| `lib/lrp.h` | `skip_lb4_key`, `skip_lb6_key` |
| `lib/network_device.h` | `device_state` |
| `lib/lpm.h` | `lpm_v4_key`, `lpm_v6_key` |

## 新增结构体时需要做什么

1. 定义结构体后，把 `add_type(struct X);` 添加到对应 include 下。
2. 在 Go 侧 `pkg/alignchecker` 里加入对应映射。
3. 运行 `make -C bpf testdata` 并跑 `go test ./pkg/alignchecker/...`。

## 关键点

- 这是 **compile-only 工件**，不会被 `tc` 或 `cgroup/*` 加载；因此没有 `__section_entry`，也没有 `BPF_LICENSE`。
- 它读 `bpf/config/global.h` 和 `bpf/config/node.h`，这样条件编译分支（例如 IPv4-only vs dualstack）下结构体大小差异也会被覆盖。
- 它和真正的 bpf_lxc / bpf_host 等公用 `lib/*.h`，所以一旦底层结构体字段漂移，alignchecker 单测会立刻失败，这是 Cilium 保证 "Go 侧 map 读写字节与 BPF 侧视图一致" 的核心防线。
