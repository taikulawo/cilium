# bpf_host.c

## 用途

Cilium 的 **host datapath**，挂到物理网卡（eth0 等）和 `cilium_host` / `cilium_net` 虚拟设备上。每个节点上网络进出 / 跨 pod / 跨节点流量基本都要经过这个 object 的某个 hook，是整个 Cilium datapath 中 **最复杂**（~2000 行）、**最热点**的程序。

包含的 hook：

| section | 函数 | 挂载点 | 作用 |
|---------|------|-------|------|
| `__section_entry` | `cil_from_netdev` | tc ingress @ eth0 | 外部进入节点，是最早的 "cilium 可见入口" |
| `__section_entry` | `cil_from_host` | tc egress @ cilium_host | 本机 host netns 发出的流量 |
| `__section_entry` | `cil_to_netdev` | tc egress @ eth0 | 节点出口，做最后的 NAT/encrypt/BW |
| `__section_entry` | `cil_to_host` | tc ingress @ cilium_host, cilium_net | 流量注入 host 栈前的最后一步 |
| `__section_entry` | `cil_host_policy` | tail-call slot | 使能 host firewall + per-ep routes 时的策略子程序 |

另有一系列 tail-call 程序：`CILIUM_CALL_IPV{4,6}_{FROM,CONT_FROM}_{HOST,NETDEV}`、`CILIUM_CALL_IPV{4,6}_TO_HOST_POLICY_ONLY`。

## 配置约定

```c
#define IS_BPF_HOST 1
#define EFFECTIVE_EP_ID CONFIG(host_ep_id)
#define EVENT_SOURCE    CONFIG(host_ep_id)
#define ACTION_UNKNOWN_ICMP6_NS CTX_ACT_OK
#define NODEPORT_USE_NAT_46x64  1
```

- `host_ep_id` 是 Cilium 给 host 分配的虚拟 endpoint id，所有观察点、policy map 都用它。
- 以太网头完整存在，`ETH_HLEN == 14`。

`FROM_HOST_FLAG_NEED_HOSTFW` / `FROM_HOST_FLAG_HOST_ID` 两个比特位编码到 `CB_FROM_HOST`，用于把 "是否需要跑 host firewall" / "src 是否 HOST_ID" 的信息从前半段 `handle_ipv4/6` 传给后半段 `tail_handle_ipv4/6_cont`。

## 两个 per-CPU buffer

```c
BPF_MAP(cilium_tail_call_buffer4, PERCPU_ARRAY, 1)   // struct ct_buffer4
BPF_MAP(cilium_tail_call_buffer6, PERCPU_ARRAY, 1)   // struct ct_buffer6
```

因为 host datapath 的 CT lookup 分散在多个 tail call 中（为了规避 verifier 复杂度上限），每个 CPU 用一个 slot 存 `{tuple, l4_off, ret, monitor, ct_state, fraginfo}`，前半段写、后半段读。这是和 bpf_lxc 共享的技巧。

## 入口 1：`cil_from_netdev`（物理网卡 ingress）

1. VLAN 过滤：允许白名单内 VLAN 的包回栈再处理，其他 drop。
2. **XDP transfer**：读 `ctx_get_xfer(ctx, XFER_FLAGS)`，承接 bpf_xdp.c 写进 `data_meta` 的 `XFER_PKT_NO_SVC` / `XFER_PKT_SNAT_DONE` 等 hint。
3. `validate_ethertype`：非 IP 直接放行或 drop（看 host firewall 是否开）。
4. **IPsec**：`do_decrypt(ctx, proto)`。要解密的包直接返回 `CTX_ACT_OK` 让 XFRM 走，不再进入下面所有逻辑；避免 encrypted 还没解就跑 LB。
5. `tcx_early_hook(ctx, proto)`：预留给外部注入 hook。
6. 核心：`do_netdev(ctx, proto, UNKNOWN_ID, TRACE_FROM_NETWORK, false)`（见下文）。

## 入口 2：`cil_from_host`（cilium_host egress）

host netns 的 socket 发出去的包会先命中这个 program（因为 route 把它们导向 cilium_host）：

1. `edt_set_aggregate(ctx, 0)`：host 流量不参加 EDT 限速（host 一般无 edt policy）。
2. 若是 L7 LB 的 `MARK_MAGIC_PROXY_EGRESS_EPID`：解出 lxc_id，直接 `tail_call_egress_policy` 到对应 endpoint 的 egress policy prog。
3. `inherit_identity_from_host(ctx, &identity)`：把 skb mark 里的 identity 读到局部变量。
4. 调 `do_netdev(ctx, proto, identity, TRACE_FROM_HOST, true)`。

## `do_netdev`（dispatcher）

公共调度器，`from_host` 布尔决定具体 tail-call 目标：

- IPv6 分支：
  - L2 announcement（ARP 代答）；
  - **IPv6-in-IPv6 IPIP termination**：若 outer dst 命中本机 endpoint，剥 outer 头、把真实 backend 塞进 CB，后面 `nodeport_lb6` 要用。
  - `resolve_srcid_ipv6`：如果包是 reserved identity（例如 WORLD_ID、HOST_ID）→ 用 ipcache 查更具体身份；但永远不覆盖 `HOST_ID`（SNAT 场景下 world 包会伪装成 HOST，必须保持 HOST）。
  - WireGuard：`ctx_is_wireguard()` 识别已经加密的包，用于 trace reason。
  - tail-call `CILIUM_CALL_IPV6_FROM_HOST` 或 `_FROM_NETDEV`。
- IPv4 分支：
  - **IPv4-in-IPv4 IPIP termination**：同上，剥 outer，把 backend 存 `CB_FORCED_BACKEND_V4`，清 skip-nodeport（因为 XDP 不认识 inner service，要重跑 nodeport_lb4）。
  - 其余逻辑同 IPv6。
- ARP：L2 announcement（如启用）。
- 未知 L3：drop。

tail-call 失败时用 `send_drop_notify_error_with_exitcode_ext(..., CTX_ACT_OK, ...)`：**map 异常也不阻塞流量**。

## `tail_handle_ipv{4,6}_from_{host,netdev}` → `handle_ipv{4,6}`

两步切分：

**第一段 `handle_ipv{4,6}`**（文件内 ~160 行 ipv4 / ~230 行 ipv6）：
1. `revalidate_data` + fragment check。
2. **Strict ingress encryption**（wg）：如果 secctx 是 cluster 身份且不是 remote-node，且目的是本机 pod，则 `DROP_UNENCRYPTED_TRAFFIC`。
3. `nodeport_lb{4,6}`：仅在 `!from_host` 时跑，返回 `TC_ACT_REDIRECT`/`punt_to_stack` 都要尽早回。
4. **Host firewall CT 预 lookup**：
   - `from_host` → `ipv4_host_policy_egress_lookup` 查 CT 决定是否需要跑 egress 策略，结果写进 per-CPU `ct_buffer4`。
   - `!from_host` → `ipv4_host_policy_ingress_lookup`，决定是否跑 ingress 策略。
   - 把 `(need_hostfw, is_host_id)` 编码到 `CB_FROM_HOST`。
5. 返回 `CTX_ACT_OK`，第二段接管。

**第二段 `handle_ipv{4,6}_cont`** 和 `tail_handle_ipv{4,6}_cont_from_{host,netdev}`：
1. 若 `from_host` + `tc_index_from_{in,e}gress_proxy(ctx)` → 来自本机 L7 proxy，magic 调整为 `MARK_MAGIC_PROXY_{INGRESS,EGRESS}`。
2. 若 `FROM_HOST_FLAG_NEED_HOSTFW` → 用之前存的 `ct_buffer` 继续执行 `__ipv4_host_policy_{egress,ingress}` 真正的策略判决（CT create/update + policy map lookup）；返回 `CTX_ACT_REDIRECT` 时表示 redirect 到 proxy。
3. 查 `lookup_ip4_endpoint`：
   - 命中本地 pod/host → 可能走 `ipv4_local_delivery` 直送（`enable_bpf_host_routing`）。
   - 未命中 → 决定是否发到 tunnel (`encap_and_redirect_with_nodeid`)、egress gateway、still-encrypted-passthrough、或 fallthrough 到 stack。
4. `from_host && CTX_ACT_OK` → `rewrite_dmac_to_host(ctx)` 把目的 MAC 改成 cilium_net MAC，确保 kernel 认为是 PACKET_HOST。

拆成两段的核心原因是：verifier 单程序复杂度上限，加上一次性做 LB + policy + encap 太大。

## 入口 3：`cil_to_netdev`（物理网卡 egress，节点出口）

挂到 eth0 egress，是节点出外最后一环。流程：

1. 读 skb mark 推 src_sec_identity（`MARK_MAGIC_HOST/OVERLAY/ENCRYPT/PROXY_EGRESS/IDENTITY/EGW_DONE`）。
2. VLAN 过滤。
3. L7 LB `MARK_MAGIC_PROXY_EGRESS_EPID` → `tail_call_egress_policy`。
4. **Host firewall**（`ENABLE_HOST_FIREWALL`）：
   - `ctx_snat_done(ctx)` 已 SNAT 跳过。
   - `handle_to_netdev_ipv{4,6}`：解析源身份后调 `ipv{4,6}_host_policy_egress`。
5. `host_egress_policy_hook`：预留 hook。
6. **Egress Gateway**（`ENABLE_EGRESS_GATEWAY_COMMON` 且非 overlay 复用）：`egress_gw_handle_request`，判断是否 SNAT 到 egressIP 并经过指定 ifindex 出去。
7. **Bandwidth Manager**：`edt_sched_departure(ctx, proto)` 按 EDT (BBR-like) 调度；超限直接 drop 并打 metric（不发 drop notify，因为是 rate limit）。
8. **IPsec**：未加密 → `ipsec_maybe_redirect_to_encrypt` 走 XFRM。
9. **WireGuard**：`host_wg_encrypt_hook` → 若需要加密 → `TC_ACT_REDIRECT` 到 `cilium_wg0`。有防循环检查（`MARK_MAGIC_ENCRYPT`）。
10. `strict_egress_encryption` 严格模式：未加密的包直接 `DROP_UNENCRYPTED_TRAFFIC`。
11. **Health check**：`lb_handle_health`。
12. **NAT fwd**（NodePort SNAT）：`handle_nat_fwd(ctx, 0, src_sec_identity, proto, false, ...)`，通常会 tail-call，很多场景从这里就不回来了。
13. 最后发 `TRACE_TO_NETWORK` 并返回。

## 入口 4：`cil_to_host`（cilium_host/cilium_net ingress）

把流量交回 host 协议栈之前的"最后一刀"：

1. 读 `CB_PROXY_MAGIC` 判断是不是要 redirect 到 L7 proxy：
   ```c
   if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
       __be16 port = magic >> 16;
       return ctx_redirect_to_proxy_first(ctx, port);
   }
   ```
   上 16 位编码 proxy port，直接 `ctx_redirect_to_proxy_first`。
2. IPsec：`MARK_MAGIC_ENCRYPT` 还原 identity meta。
3. 处理 TPROXY 相关 mark hack（见代码中注释的 iptables.Manager.inboundProxyRedirectRule 兼容逻辑：mark=0 + 在 cilium_net 上 → `MARK_MAGIC_SKIP_TPROXY`，防止 iptables rule 把它重定向到 proxy）。
4. **IPsec+NodePort rev DNAT**：encrypt 包要在这里跑 `handle_nat_fwd(..., true, ...)` 做反向 NodePort NAT，否则回包识别不出来。
5. **Host firewall ingress**：`host_ingress_policy`。

## 入口 5：`cil_host_policy`（per-endpoint routes 下的 tail-call 入口）

当 `ENABLE_HOST_FIREWALL && !ENABLE_ROUTING`（即 per-endpoint routes 开启）时，bpf_lxc 需要在 "从 pod 发出" / "从 pod 收入" 两个方向跳进 host firewall。但 host firewall 不是普通 tail call，是手动插入全局 tail call map 的 fixed slot，于是这个 program 以 `__section_entry` 身份存在：

- `from_host` 分支：pod 发出的包，`src = HOST_ID`，先跑 `from_host_to_lxc`（即 egress 策略），然后 `tail_call_policy(ctx, lxc_id)` 跳回目标 pod 的 policy。
- `!from_host` 分支：pod 收入的包，跑 `host_ingress_policy`。

## 关键点

- **ct_buffer 技巧**：跨 tail-call 保留 CT lookup 结果，避免重复查表 + 规避 verifier 复杂度上限。
- **身份穿透的几个 mark/CB 字段**：`CB_SRC_LABEL`、`CB_PROXY_MAGIC`、`CB_IPCACHE_SRC_LABEL`、`CB_FROM_HOST`、`MARK_MAGIC_*`。要改动 identity 流动一定要全部检查。
- **CVE 相关硬约束**：
  - overlay/wg 远端送来的 `HOST_ID` 要 drop（bpf_overlay 做了）；bpf_host 这里反过来要在 SNAT 场景下**不**用 ipcache 把 HOST_ID 改成 world，否则 host policy 会被绕过。
  - IPIP termination 后要重跑 nodeport_lb，否则 LB backend 对应的 DNAT 会错位。
- **failing open** 的几个地方：do_netdev 的 tail-call 失败返回 `CTX_ACT_OK`、ipsec 解密失败只打 drop notify、bandwidth manager drop 不发 drop notify。
- 两阶段 tail-call（`FROM_*` → `CONT_FROM_*`）要配套，缺一个会出现包"卡在中间"：改动时要同时改 `use_tailcall` 条件。
- 一个常见误解：`cil_from_netdev` 的"下一跳" tail-call `CILIUM_CALL_IPV4_FROM_NETDEV` 和 bpf_xdp.c 里的同名符号指向的是 **不同** program —— XDP 和 TC 各有一份 tail-call map。
