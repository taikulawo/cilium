# bpf_overlay.c

## 用途

Cilium 的 **tunnel overlay (VXLAN/Geneve) datapath**。挂到 `cilium_vxlan` 或 `cilium_geneve` 隧道设备的 tc ingress/egress：

- `cil_from_overlay`（ingress，`__section_entry`）：解封装后的 inner 包从隧道设备进入本节点，决定投递给本机 pod 还是本机 host。
- `cil_to_overlay`（egress，`__section_entry`）：准备从本节点通过隧道设备送出的包，做 bandwidth manager、SNAT 等 egress 处理。

两个入口都遵循 "按 ethertype dispatch → tail-call 到 `tail_handle_ipv{4,6}` → 调用 `handle_ipv{4,6}`" 的模式。

## 身份标签默认值

```c
#define SECLABEL      WORLD_ID
#define SECLABEL_IPV4 WORLD_IPV4_ID
#define SECLABEL_IPV6 WORLD_IPV6_ID
```

从隧道进来的包默认视为 "world"，真正的身份要从 **tunnel_id**（VNI 的高位，由对端 encap 时写入）解码，见下文 `get_id_from_tunnel_id`。

和 bpf_host 不同，这里没有以太网头：`CILIUM_IFINDEX` 隧道 iface 发给 BPF 的 skb 已经是 L2，但剥离 encap 后 L3 偏移还是 `ETH_HLEN`。几个 `SKIP_ICMPV6_NS_HANDLING` / `SKIP_SRV6_HANDLING` 删剪代码。

## `cil_from_overlay`（ingress）主干

1. `bpf_clear_meta(ctx)` + `ctx_skip_nodeport_clear(ctx)`。
2. `validate_ethertype(ctx, &proto)` 失败 → `CTX_ACT_OK` 放行。
3. `pull_l3_hdr(ctx, proto)`。
4. 若 `ENABLE_WIREGUARD` 且 `encryption_strict_ingress`：
   ```c
   if (!ctx_is_decrypt(ctx))
       return DROP_UNENCRYPTED_TRAFFIC;
   ```
   严格模式下隧道流量必须先经过 wg 解密。随后清掉 decrypt bit。
5. **解 tunnel key**（只对 IPv4/IPv6 分支）：
   ```c
   get_tunnel_key(ctx, &key);
   src_sec_identity = get_id_from_tunnel_id(key.tunnel_id, proto);
   if (src_sec_identity == HOST_ID) return DROP_INVALID_IDENTITY;
   ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
   ```
   - `tunnel_id` 是 encap 侧写入的 VNI/Geneve option，承载对端的 security identity。
   - 远端绝对不该用 `HOST_ID`（否则在 overlay 一侧伪装成本机 host 可以绕过 host firewall），直接 drop。
6. `send_trace_notify(ctx, TRACE_FROM_OVERLAY, ...)`。
7. 根据 ethertype 再次 switch：
   - IPv4/IPv6：`tail_call_internal(CILIUM_CALL_IPV{4,6}_FROM_OVERLAY)`。
   - ARP（且启用 VTEP）：`CILIUM_CALL_ARP` tail-call 到 `tail_handle_arp`。
   - 其它：`CTX_ACT_OK`。

## tail call `tail_handle_ipv{4,6}` → `handle_ipv{4,6}`

以 IPv4 为例 (`handle_ipv4`)：

1. `revalidate_data` 拿 ip4 指针。
2. **fragment check**：若关闭 ipv4 fragment 且是分片 → `DROP_FRAG_NOSUPPORT`。
3. **Multicast**：
   ```c
   if (IN_MULTICAST(bpf_ntohl(ip4->daddr))) {
       if (mcast_lookup_subscriber_map(&ip4->daddr))
           return tail_call_internal(ctx, CILIUM_CALL_MULTICAST_EP_DELIVERY, ext_err);
   }
   ```
   命中订阅表就 tail-call 到 multicast 分发程序。
4. **NodePort LB**：`nodeport_lb4(ctx, ip4, identity, ...)`。
   - 返回 `TC_ACT_REDIRECT`（L7 LB）或 `punt_to_stack=true` 直接返回。
   - 否则重新 `revalidate_data`。
5. **VTEP**：如果开启 `enable_vtep`，查 `cilium_vtep_map` 保证来源 VTEP 身份是 world（否则 `DROP_INVALID_VNI`）。
6. **Inter-cluster SNAT**（`ENABLE_CLUSTER_AWARE_ADDRESSING && ENABLE_INTER_CLUSTER_SNAT`）：
   - 若来源 cluster id ≠ 本集群，且 dst IP 等于 inter-cluster SNAT IP，tail-call 到 `CILIUM_CALL_IPV4_INTER_CLUSTER_REVSNAT`（见下文）。
7. **身份修正**：
   ```c
   if (identity_is_remote_node(identity) || (is_dsr && identity_is_world_ipv4(identity))) {
       info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
       if (info) identity = info->sec_identity;
   }
   ```
   兜底：对于 remote-node 或 world 身份的 DSR 流量，用 ipcache 的 saddr 查更具体的身份（支持 KUBE_APISERVER_NODE_ID、CIDR CNP 等场景）。
8. **Egress Gateway**（`ENABLE_EGRESS_GATEWAY_COMMON`）：
   ```c
   if (egress_gw_snat_needed_hook(ctx, saddr, daddr, &snat_addr, &egress_ifindex, false)) {
       if (snat_addr == EGRESS_GATEWAY_NO_EGRESS_IP) return DROP_NO_EGRESS_IP;
       ipv4_l3(ctx, ETH_HLEN, NULL, NULL, ip4);  // decrement TTL
       set_identity_mark(ctx, identity, MARK_MAGIC_EGW_DONE);
       return egress_gw_fib_lookup_and_redirect(ctx, snat_addr, daddr, egress_ifindex, EGRESS_GATEWAY_RT_TBID, ext_err);
   }
   ```
   SNAT 由 `to-netdev@bpf_host` 完成，这里只负责 FIB + redirect。
9. **DSR Geneve 回程**：当 DSR + Geneve encap，不走 bpf_host_routing 时，`ctx_change_type(ctx, PACKET_HOST)` 让 netfilter 走 conntrack 建立回程表项。
10. **投递**：
    - `lookup_ip4_endpoint(ip4)` 找本地 pod → `ipv4_local_delivery(..., from_tunnel=true, ...)`。
    - 否则（必须是本机 host）：`set_identity_mark + ipv4_host_delivery`。

IPv6 版本结构镜像一致，没有 inter-cluster snat / vtep / multicast 分支。

## `tail_handle_inter_cluster_revsnat`

ClusterMesh 场景：隧道里的回包，目的是把 SNAT 过的地址翻回原 pod IP。

1. `snat_v4_rev_nat(ctx, &target, &trace)`：用对端 cluster id 作为 nat target 的一部分查反向映射。
2. 成功后用 `cluster_id` 继续投递；在 `ipv4_local_delivery` 时传入 cluster_id 让目标 pod 感知跨集群身份。

## `tail_handle_arp`（VXLAN VTEP ARP 代答）

VXLAN VTEP 与 Cilium 对接时，远端会往隧道里 ARP 问本机 pod IP。此 tail-call 做"代答"：

1. `ctx_get_tunnel_key`（没有 src ip 的版本）。
2. `arp_validate`：解析 ARP 请求，拿到 sip/tip、smac。
3. 检查 tip 是本机 endpoint（`__lookup_ip4_endpoint`）；
4. 从 `cilium_vtep_map` 查 saddr 所在 VTEP 的信息；
5. `arp_prepare_response(ctx, &mac, tip, &smac, sip)` 原地改成 ARP reply（源 MAC 用 `interface_mac`）；
6. 用 `__encap_and_redirect_with_nodeid` 把这个 ARP reply 以 VXLAN encap 回去（目的是 VTEP 的 tunnel_endpoint IP）。
7. 走不通的分支（ARP 不是本机、不是 VTEP、encap 失败）走 drop_err 或 pass_to_stack。

## `cil_to_overlay`（egress）主干

```c
__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;
```

1. `bpf_clear_meta(ctx)`。
2. 读 ethertype（只是为了下面 trace 和 bandwidth manager，不严格校验）。
3. **Bandwidth Manager**：
   ```c
   #ifdef ENABLE_BANDWIDTH_MANAGER
       ret = edt_sched_departure(ctx, proto);
       if (ret < 0) { update_metrics(...); return CTX_ACT_DROP; }
   #endif
   ```
   在 tunnel 层做 EDT (earliest departure time) 调度，因为 phys dev 的 queue_mapping 在 tunnel xmit 时会被覆盖，必须在这里打时间戳。
4. **ClusterMesh cluster-id**：从 mark 里读。
5. 读 tunnel_key，推 src_sec_identity。
6. `set_identity_mark(ctx, src_sec_identity, MARK_MAGIC_OVERLAY)`：下游 TC 层能识别"这个包已经被 overlay 加过身份"。
7. **NAT forward**（`ENABLE_NODEPORT`）：
   - 若 `ctx_snat_done(ctx)`（已经被 bpf_host 做过 SNAT）→ 跳过。
   - 否则 `handle_nat_fwd(ctx, cluster_id, src_sec_identity, proto, false, &trace, &ext_err)` 做最后一跳 nat。
8. 失败走 drop_notify。

## 关键点

- 这里是 overlay 模式下，从 pod/host → remote pod 的"最后一次 Cilium 可见机会"：bandwidth、snat、trace 全集中。
- VXLAN **tunnel_id → security identity** 的映射是 Cilium overlay 身份传递的核心：encap 侧写、decap 侧读，保证跨节点的 L4/L7 policy 不会丢标签。禁止 `HOST_ID` 从远端进来是硬性安全约束。
- 对 DSR + Geneve，没开启 bpf_host_routing 时需要 `ctx_change_type(ctx, PACKET_HOST)` 让 netfilter 介入——否则回程 conntrack 建不起来。
- 对 Egress Gateway，这里只负责"决定 SNAT IP 和出口 ifindex 并 FIB redirect"，真正改源 IP 在 bpf_host 的 to-netdev 做；避免每条路径都重复 SNAT 逻辑。
- VTEP ARP 代答让旧式物理 VTEP 和 Cilium 实现 L2 透传，这是 BGP/VTEP 场景下的兼容桥梁。
