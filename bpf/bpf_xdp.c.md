# bpf_xdp.c

## 用途

Cilium 的 **XDP 入口程序**，挂到物理网卡（eth0 等）的 XDP native/driver 层，在 skb 分配之前就处理报文，用来做：

1. **XDP prefilter**：按 CIDR 黑名单直接 drop（DDoS 场景的"洗流量"）。
2. **NodePort/LoadBalancer 加速**：对已知 service 的目的 IP，直接在 XDP 层完成 DNAT + redirect，省掉 skb 分配、conntrack、iptables。
3. **DSR/IPIP/Geneve** 支持。
4. **NAT46x64** 支持。

挂载约定：

```c
#include <bpf/ctx/xdp.h>
#define IS_BPF_XDP 1
```

ctx 是 `struct xdp_md`。`#define NODEPORT_USE_NAT_46x64 1` 让 `lib/nodeport.h` 以 XDP 模式启用 NAT46x64。几个 `SKIP_*` 宏缩小 object：XDP 里不需要 ICMPv6 NS 响应、ICMPv6 Time Exceeded、SRv6 代码。

## 自带的 CIDR 过滤 map

两类，每类 v4/v6 各一份：

| map | 类型 | 用途 |
|-----|------|------|
| `cilium_cidr_v4_fix` / `cilium_cidr_v6_fix` | HASH | 单一地址（prefix=32/128）精确匹配，命中则 drop |
| `cilium_cidr_v4_dyn` / `cilium_cidr_v6_dyn` | LPM_TRIE | 可配置前缀的黑名单，命中则 drop |

flags：
- `BPF_F_NO_PREALLOC`：按需分配。
- `BPF_F_RDONLY_PROG_COND`：datapath 只读、user space 可写，让 verifier 可以更激进地做 const-prop。
- `pinning = LIBBPF_PIN_BY_NAME`：pin 到 `/sys/fs/bpf/tc/globals`，Agent 侧用。

Agent 侧可以把攻击者 IP/CIDR 实时写进 `_dyn` 表。

## 顶层 entry：`cil_xdp_entry`

```c
__section_entry
int cil_xdp_entry(struct __ctx_buff *ctx)
{
    bpf_clear_meta(ctx);
    check_and_store_ip_trace_id(ctx);
    return check_filters(ctx);
}
```

剩余逻辑都在 `check_filters`。

## `check_filters` 主干

1. `validate_ethertype(ctx, &proto)`：不是 IPv4/IPv6 直接 `CTX_ACT_OK` 让内核栈处理。
2. `ctx_store_meta(ctx, XFER_MARKER, 0)` + `ctx_skip_nodeport_clear(ctx)`：清状态。
3. `xdp_early_hook(ctx, proto)`：允许用户自定义早期 hook（默认 `#define xdp_early_hook ... CTX_ACT_OK`）。
4. 根据 ethertype 分流：
   - IPv4 → `prefilter_v4` → `check_v4_lb`。
   - IPv6 → `prefilter_v6` → `check_v6_lb`。
5. 最后 `bpf_xdp_exit(ctx, ret)`：若 verdict 是 `CTX_ACT_OK`（通过），`ctx_move_xfer(ctx)` 把 `xdp_md->data_meta` 里暂存的 `XFER_MARKER` 等信息传给 TC 层——TC 的 `from-netdev` 会读这个 meta。

## `prefilter_v{4,6}`

```c
if (ctx_no_room(ipv4_hdr + 1, data_end))
    return CTX_ACT_DROP;

#ifdef CIDR4_FILTER
    pfx.addr = ipv4_hdr->saddr;
    pfx.lpm.prefixlen = 32;
    if (map_lookup_elem(&cilium_cidr_v4_dyn, &pfx)) return CTX_ACT_DROP;
    if (map_lookup_elem(&cilium_cidr_v4_fix, &pfx)) return CTX_ACT_DROP;
#endif
```

- 入口健壮性：先确认 L3 头在 `data_end` 之内。
- 源 IP 命中任一 CIDR 表就 `CTX_ACT_DROP`。
- `CIDR4_FILTER` / `CIDR4_LPM_PREFILTER` 两个宏控制是否编译进对应检查，节省指令数。

IPv6 版本等价，使用 128bit 对齐的 `ipv6_addr_copy_unaligned`。

## `check_v{4,6}_lb` & `tail_lb_ipv{4,6}`

当 `ENABLE_NODEPORT_ACCELERATION` 开启时：

```c
static __always_inline int check_v4_lb(struct __ctx_buff *ctx)
{
    __s8 ext_err = 0;
    int ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_NETDEV, &ext_err);
    return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err, METRIC_INGRESS);
}
```

tail-call 的目标 `tail_lb_ipv4`：

1. `revalidate_data(ctx, &data, &data_end, &ip4)`。
2. `nodeport_lb4(ctx, ip4, UNKNOWN_ID, &punt_to_stack, &ext_err, &is_dsr)`：
   - 查 service / backend / DSR 决策。
   - 命中 → DNAT + `bpf_redirect` 到目标网卡/隧道（真正的"XDP LB 加速"）。
   - 不命中（例如目的是本机 pod）→ 返回让栈处理。
3. 如果 `IS_ERR(ret)`，调用 `xdp_frag_not_found_world_v4`：
   ```c
   if (ret != DROP_FRAG_NOT_FOUND) return ret;
   info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
   return frag_not_found_world(ret, info ? info->sec_identity : WORLD_IPV4_ID);
   ```
   XDP 没有解析过 identity，所以在最终 drop notify 之前再做一次 ipcache lookup 回填源 identity，便于 hubble 告警。

关闭 acceleration 时 `check_v4_lb` 直接 `CTX_ACT_OK`，XDP 层等效 pass-through。

## `bpf_xdp_exit`

```c
static __always_inline int bpf_xdp_exit(struct __ctx_buff *ctx, const int verdict)
{
    if (verdict == CTX_ACT_OK)
        ctx_move_xfer(ctx);
    return verdict;
}
```

关键是 `ctx_move_xfer`：把 XDP 层写入 `data_meta` 的辅助信息（`XFER_FLAGS`、`XFER_PKT_SNAT_DONE`、`XFER_PKT_NO_SVC` 等）保留下来，TC 层 `cil_from_netdev` 会用 `ctx_get_xfer(ctx, XFER_FLAGS)` 读回。

## 关键点

- XDP 比 TC 更早、更快、但限制更多：没有 skb、没有 conntrack、没有 push/pop_header 等富 helper，只有 `bpf_xdp_adjust_head/tail/meta`。
- Prefilter 是实际在生产中最常用的功能：L3/L4 DDoS 时在 XDP 层 drop 掉打到 K8s node 的攻击流量。
- NodePort acceleration 要求 CIlium 跑在 driver XDP 上（或 generic XDP fallback），内核需支持 `bpf_redirect` 到 veth / tunnel。
- 这个 program 没有 `BPF_LICENSE` 之外的 kfunc 依赖，所以在旧内核上也能运行，但 `nodeport_lb4` 内部可能用到的 helper（例如 `bpf_fib_lookup` 的新 flag）会在 agent 启动时由 `bpf_probes.c` 探测。
- 对 fragment 的处理：XDP 本身没有 fragment reassembly，所以靠 nodeport_lb4 返回 `DROP_FRAG_NOT_FOUND` + `xdp_frag_not_found_world` 的组合，正确回退到让栈处理。
