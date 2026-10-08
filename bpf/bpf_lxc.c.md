# bpf_lxc.c

## 用途

Cilium 的 **容器/endpoint datapath**，是整个 cilium 中最大的 BPF 文件 (~2650 行)。每个 pod 对应一张 veth，`bpf_lxc.o` 被加载到 pod 侧 veth 的 tc **ingress（容器发出）** 和（启用 per-endpoint routes 时）**egress（容器接收）** 上。核心职责：

- 从容器发出的流量：策略 (CiliumNetworkPolicy)、per-packet LB、conntrack、L7 proxy redirect、egress encapsulation / tunnel、local delivery。
- 发到容器的流量：策略、L7 proxy redirect、local delivery。
- ARP 代答、ICMP policy deny reply。

## 关键宏

```c
#define IS_BPF_LXC 1
#define EFFECTIVE_EP_ID LXC_ID
#define EVENT_SOURCE    LXC_ID
#define USE_LOOPBACK_LB 1
```

`LXC_ID` 是该 endpoint 在本节点的内部 id，由 Agent 构建时替换到 node_config.h。`USE_LOOPBACK_LB` 让 LB 代码启用 hairpin loopback 处理（pod → clusterIP 回到自己）。

### `FROM_HOST_FLAG_*` / `FROM_HOST_L7_LB`

`CB_FROM_HOST` 字段在不同 program 之间穿透：
- `0` 常态；
- `FROM_HOST_L7_LB`：标记这是来自 L7 LB (Envoy) 的 egress 包，`policy_can_egress4` 跳过某些检查，CT 处理也要特殊。

## 两个 per-CPU scratch map

```c
BPF_MAP(cilium_tail_call_buffer4, PERCPU_ARRAY, 1)   // struct ct_buffer4
BPF_MAP(cilium_tail_call_buffer6, PERCPU_ARRAY, 1)   // struct ct_buffer6
```

和 bpf_host.c 一样，用于在"CT lookup tail-call" 和 "policy/encap tail-call" 之间传递 `(tuple, l4_off, ret, monitor, ct_state, fraginfo)`，规避 verifier 复杂度上限。

## 入口 1：`cil_from_container`（容器 → ???）

挂到 pod veth 的 tc ingress。流程：

1. `ctx->queue_mapping = 0`：绕过 veth 驱动在旧内核的 queue mapping bug（workaround GH-18311）。
2. `edt_set_aggregate(ctx, LXC_ID)`：bandwidth manager 按 pod id 聚合。
3. `send_trace_notify(TRACE_FROM_LXC, ...)`。
4. 按 ethertype 分流：
   - IPv6 → `tail_call_internal(CILIUM_CALL_IPV6_FROM_LXC)`。
   - IPv4 → `tail_call_internal(CILIUM_CALL_IPV4_FROM_LXC)`。
   - ARP → `tail_call_internal(CILIUM_CALL_ARP)`（如果 `enable_arp_responder`）。
   - 其它 → `DROP_UNKNOWN_L3`。
5. tail-call 的目标就是下面的 `tail_handle_ipv4` / `tail_handle_ipv6`。

## egress 主干流水线（IPv4 为例）

**三步 tail-call 链**：

```
cil_from_container
  → CILIUM_CALL_IPV4_FROM_LXC         (= tail_handle_ipv4)
    → CILIUM_CALL_IPV4_CT_EGRESS       (= TAIL_CT_LOOKUP4 生成的 tail_ipv4_ct_egress)
      → CILIUM_CALL_IPV4_FROM_LXC_CONT  (= tail_handle_ipv4_cont → handle_ipv4_from_lxc)
```

**step 1：`__tail_handle_ipv4` (tail_handle_ipv4)**
- `revalidate_data` + fragment check。
- `is_valid_lxc_src_ipv4`：源 IP 必须属于本 lxc（排除 spoof），L7 LB 发出的除外。
- **Multicast**：IGMP 由 pod 发出 → `mcast_ipv4_handle_igmp` 处理订阅；多播目的地 → tail-call 到 EP_DELIVERY 分发。
- 根据 `ENABLE_PER_PACKET_LB`：
  - 开 → `__per_packet_lb_svc_xlate_4(ctx, ip4, ext_err)`：对每包做 service DNAT（socket LB 不覆盖的 UDP/ICMP 或者 socket LB 关闭时）。该函数内部可能 tail-call 到 LB 子程序，返回后 **继续** tail-call 到 CT_EGRESS。
  - 关 → 直接调 `tail_ipv4_ct_egress(ctx)`。

**step 2：`TAIL_CT_LOOKUP4(CILIUM_CALL_IPV4_CT_EGRESS, tail_ipv4_ct_egress, CT_EGRESS, ENABLE_PER_PACKET_LB, FROM_LXC_CONT, tail_handle_ipv4_cont)`**

这是用宏生成的 CT 查询 program。关键步骤（见 `TAIL_CT_LOOKUP4` 宏，bpf_lxc.c:492-558）：

1. 拉 `ct_buffer = AUX(cilium_tail_call_buffer4)`。
2. 解析 ipv4 tuple：`daddr/saddr/nexthdr`，`l4_off = ETH_HLEN + ipv4_hdrlen`。
3. `select_ct_map4(ctx, DIR, tuple)` 选 CT map（支持 ClusterMesh 多集群分 map）。
4. 如果 `ENABLE_PER_PACKET_LB` 且方向 EGRESS：
   - 用 `lb4_ctx_restore_state` 把前一步 LB 挑出的 backend 从 CB 恢复到局部 ct_state_new。
   - 如果 rev_nat_index / proxy_port / L7 LB 任一命中 → `scope = SCOPE_FORWARD`（只匹配正向，避免错配）。
5. `ct_lookup4()`：写回 ct_buffer 的 `tuple/ct_state/monitor/ret`。
6. 根据 `CONDITION`（ENABLE_PER_PACKET_LB）决定走 tail-call（`FROM_LXC_CONT`）还是直接 inline 调 `tail_handle_ipv4_cont(ctx)`。

**step 3：`tail_handle_ipv4_cont` → `handle_ipv4_from_lxc`**

这是egress大头，依次做：

1. 从 ct_buffer 读出 tuple/ct_state/ret（上一步的结果）。
2. 从 `AUX_REUSE(nodeport_nat_info)` 恢复 nodeport 的 NAT 结果（如果 per-packet LB 做了 nodeport）。
3. **dst 身份决议**：`lookup_ip4_remote_endpoint(ip4->daddr, cluster_id)`，拿不到用 `WORLD_IPV4_ID` 兜底。记录 `skip_tunnel` / `hybrid_routing` 位。
4. **Policy enforcement**（按 `ct_status`）：
   - `CT_NEW/CT_ESTABLISHED`：
     - L7 LB 来源 (`from_l7lb`) 时跳过 policy。
     - `hairpin_flow` 跳过 policy（pod 访问自己 clusterIP）。
     - 否则 `policy_can_egress4(ctx, tuple, l4_off, SECLABEL_IPV4, dst_sec_identity, ...)`：返回 verdict、`policy_match_type`、`audited`、`proxy_port`、`cookie`。
     - `send_policy_verdict_notify` 打事件（命中 drop/新连接都要打）。
     - `verdict != CTX_ACT_OK`：若配置 `policy_deny_response_enabled` 且是 DROP_POLICY，tail-call 到 `CILIUM_CALL_IPV4_POLICY_DENIED`（生成 ICMP admin prohibited）；否则直接返回 verdict。
   - `CT_RELATED/CT_REPLY`：跳过策略；如果 `ct_state->proxy_redirect`，send `TRACE_TO_PROXY` 并 `ctx_redirect_to_proxy4(..., proxy_port=0, false)`（ingress proxy 回包）。
   - 其它 → `DROP_UNKNOWN_CT`。
5. **CT 建表 / 更新 flags**：
   - `CT_NEW` → `ct_create4` 到对应 cluster 的 CT map。
   - `CT_ESTABLISHED` 若 `rev_nat_index` 或 `proxy_redirect` 过期 → `ct_recreate4`（重建）。
   - `CT_REPLY/RELATED` 且 `node_port && lb_is_svc_proto` → tail-call 到 `CILIUM_CALL_IPV4_NODEPORT_REVNAT`，做 nodeport 回程 revDNAT。
6. 调 `ipv4_forward_to_destination(...)` 进行真正投递（SRv6、L7 proxy redirect、tunnel encap、local delivery、host delivery、egress gateway hints）。

IPv6 egress 结构一模一样（`handle_ipv6_from_lxc`、`tail_handle_ipv6_cont`、`TAIL_CT_LOOKUP6`、`ipv6_forward_to_destination`），差别只在 fragment / SRv6 / `ipv6_addr_copy`。

## 入口 2：`cil_lxc_policy`（ingress 策略，tail-call 入口）

当包要进入这个 pod 时（来自其他 pod、tunnel、host），调用方做 `local_delivery_fill_meta` + tail-call policy map 到本 ep。本 program 不绑定 tc hook，是全局 policy tail-call map 中的一格。

1. `validate_ethertype` + `pull_l3_hdr`。
2. 两种工作模式（取决于 compile 时是否 dualstack）：
   - 独立 v4+v6：tail-call 到 `CILIUM_CALL_IPV{4,6}_CT_INGRESS_POLICY_ONLY`。
   - 单协议：直接 inline 调 `tail_ipv{4,6}_ct_ingress_policy_only(ctx)`。
3. CT_LOOKUP 的下游是 `tail_ipv{4,6}_policy`（见下文），走纯 policy，不做 ingress CT create（上游已经做）。

## 入口 3：`cil_lxc_policy_egress`（L7 LB egress policy）

挂点同样是 tail-call 入口。只在 `ENABLE_L7_LB` 下有逻辑：
- 标记 `CB_FROM_HOST = FROM_HOST_L7_LB`。
- `edt_set_aggregate(ctx, 0)` 不重复计费。
- tail-call 回 `CILIUM_CALL_IPV{4,6}_FROM_LXC`，走标准 egress pipeline，但 `from_l7lb = true` 会跳过某些检查。

## 入口 4：`cil_to_container`（容器 ← ???）

当 per-endpoint routes 开启时，这个 program 挂在 pod veth 的 tc egress（内核视角是朝 pod 发），处理 "进入 pod 之前的最后一步"：

1. **L7 egress proxy EPID**：`MARK_MAGIC_PROXY_EGRESS_EPID` → `tail_call_egress_policy(ctx, lxc_id)`。
2. `inherit_identity_from_host` 从 mark 解出 src identity。
3. **Host firewall 回跳**（`ENABLE_HOST_FIREWALL && !ENABLE_ROUTING`）：如果 src 是 HOST_ID，先 tail-call 到 `host_ep_id` 执行 host egress policy（相当于回到 bpf_host.c 的 `cil_host_policy`），完毕之后再回 bpf_lxc 继续。`CB_FROM_HOST=1` + `CB_DST_ENDPOINT_ID=LXC_ID` 做状态传递。
4. 按 ethertype tail-call 到 `CILIUM_CALL_IPV{4,6}_CT_INGRESS`（下游继续到 `tail_ipv{4,6}_to_endpoint`）。

## `tail_ipv{4,6}_policy` / `tail_ipv{4,6}_to_endpoint`

两个 tail-call 都调用公共的 `ipv{4,6}_policy(ctx, ip, src_label, tuple_out, ext_err, &proxy_port, from_tunnel)`：

- 查 CT (`ct_lookup{4,6}`)。
- 对 CT_NEW/ESTABLISHED 做 `policy_can_ingress{4,6}`。
- 对 CT_REPLY/RELATED 跳过策略，可能触发 egress proxy redirect（当 CT 建立时记录了 proxy）。
- 返回 `POLICY_ACT_PROXY_REDIRECT`（上层去 `ctx_redirect_to_proxy{4,6}` + `CB_PROXY_MAGIC`），`CTX_ACT_OK`（继续投递），或错误码。

两者区别：
- `tail_ipv{4,6}_policy`：标准路径，由其他 program 发起（bpf_host / bpf_overlay / 其他 pod），要根据 `CB_DELIVERY_FLAGS` 决定是否 `redirect_ep` 继续送包、tunnel 场景是否 `ctx_change_type(ctx, PACKET_HOST)`。
- `tail_ipv{4,6}_to_endpoint`：进入本 pod 的最后一步，可能触发 "hairpin to proxy"（`ctx_redirect_to_proxy_hairpin_ipv4`），处理 L7 ingress proxy。

## `tail_handle_arp`

ARP 代答：pod 问 gateway（通常是 cilium router IP）→ 用 `interface_mac` 回复。对所有 ARP 请求 IP 都回答，除了 lxc 自己的 IP（避免 duplicate-address detection 冲突）。

## `tail_policy_denied_ipv{4,6}` (`CILIUM_CALL_IPV{4,6}_POLICY_DENIED`)

当 `policy_deny_response_enabled` 时，被 denied 的 egress 包不只是丢弃，而是：
1. 生成 ICMP(v4) Destination Unreachable: PKT_FILTERED 或 ICMPv6 Admin Prohibited。
2. `redirect_self(ctx)` 把 ICMP reply 送回发包 pod。
3. 更新 metrics。IPv6 版有 100 pps/突发 1000 的限流（`ratelimit_check_and_take`）避免 ICMP flood。

## 关键点

- bpf_lxc 的 CT 处理和 bpf_host 一样是 **分两段 tail-call**（LOOKUP + POLICY），放一起 verifier 会炸。
- `TAIL_CT_LOOKUP4/6` 是宏，接受 `CONDITION/TARGET_ID/TARGET_NAME`：开 PER_PACKET_LB 时必须 tail-call（因为前面 LB 做了很多工作），否则 inline 走子函数即可省一次 tail-call。
- `AUX` / `AUX_REUSE` 是 Cilium 封装的 per-CPU scratch，`AUX_REUSE(cilium_tail_call_buffer4)` 返回已存在 slot 的指针。`tuple.saddr == 0` 是哨兵，发生这个说明前一步 LOOKUP 没走到 → `DROP_INVALID_TC_BUFFER`。
- L7 proxy redirect 是整个文件最绕的地方：egress 时如果策略判定要 redirect proxy，CT entry 里会写 `proxy_redirect`，之后同一方向的新包继续 redirect，回包方向看到 `proxy_redirect` 则不走策略直接 ctx_redirect_to_proxy。
- Hairpin / loopback（pod 访问自己 clusterIP）通过 `USE_LOOPBACK_LB + ct_state->loopback` 处理，策略整个跳过。
- `is_valid_lxc_src_ipv4` 是防止 pod 伪造源 IP 的核心检查：源必须是本 pod 的 IP（通过 config 注入）；L7 LB 场景例外是因为 Envoy 要用自己的 socket 代理。
- 新连接必定要 `policy_can_egress4/6`，CT_ESTABLISHED 的 proxy_redirect 变化要重建 CT（否则会出现"曾被允许的连接突然需要跑 proxy"）。
- `policy_deny_response_enabled` 是选项：没它就是普通 drop，开启后能让应用层明确收到 ICMP 拒绝，便于调试和合规。
- `cil_lxc_policy_egress` + L7 LB 的 `FROM_HOST_L7_LB` 位是 Cilium Envoy integration 的核心粘合，决定了 egress 包是否"从 L7 proxy 发出，应跳过某些重复检查"。
