# bpf_probes.c

## 用途

一个纯"探测"用 BPF 程序，用于在 Cilium agent 启动阶段 **判断当前内核是否支持某些 `bpf_fib_lookup` 的 flag**。它不会真正跑业务流量：Cilium 加载它、尝试把三段短程序分别 attach / 执行一次（通常用 `BPF_PROG_RUN`），只看是否得到 `-EINVAL`。

和 `pkg/datapath/bpf/gen.go:7` 的 `go generate` 配合，`cilium/ebpf` 的 `bpf2go` 会生成 `pkg/datapath/bpf/*_bpfel.go`，Agent 侧用 `Probes` 对象去跑这些 program。

## 核心封装

```c
static __always_inline int probe_fib_lookup_with_flag(struct __ctx_buff *ctx, int flag)
{
    struct bpf_fib_lookup fib_params = {
        .family   = AF_INET,
        .ifindex  = ctx_get_ifindex(ctx),
        .ipv4_src = 0,
        .ipv4_dst = 0,
    };
    return fib_lookup(ctx, &fib_params, sizeof(fib_params), flag) == -EINVAL;
}
```

逻辑：传入一个 FIB flag。如果内核不认识这个 flag，`bpf_fib_lookup` 会直接返回 `-EINVAL`，于是函数返回 `1`（"不支持"）。如果内核认识它，返回值可能是其它 code（例如查不到路由 `BPF_FIB_LKUP_RET_NO_NEIGH`），函数返回 `0`。

Agent 侧根据返回值记录能力位。构造的 `fib_params` 字段其实没意义（源/目的全 0），因为探测只在意 flag 校验，不在意 lookup 结果。

## 三个 entry program

| 函数 | section | flag | 含义 |
|------|---------|------|------|
| `probe_fib_lookup_skip_neigh` | `__section_entry` | `BPF_FIB_LOOKUP_SKIP_NEIGH` | 探测跳过 neighbor 解析的能力（Linux 5.19+） |
| `probe_fib_lookup_tbid` | `__section_entry` | `BPF_FIB_LOOKUP_TBID` | 探测按 routing-table-id 做 FIB 查找（Linux 6.6+） |
| `probe_fib_lookup_src` | `__section_entry` | `BPF_FIB_LOOKUP_SRC` | 探测让内核回填 source IP 的能力（Linux 6.7+） |

## 关键点

- `#include <bpf/ctx/unspec.h>`：用的是"未指定类型" ctx（既不是 skb 也不是 xdp）。因为这是用来 `BPF_PROG_RUN` 跑一次就扔，没必要指定具体 hook。
- 没有 `BPF_MAP` 声明，不读写任何 map，所以 BTF 很小，agent 加载开销可忽略。
- 若将来内核又加了新的 FIB flag，Cilium 只需复制粘贴一个新的 `probe_fib_lookup_<flag>` entry 即可。
- `BPF_LICENSE("Dual BSD/GPL");` 使所有 Linux helper（包括 `bpf_fib_lookup`）可用，否则 verifier 会拒绝。
