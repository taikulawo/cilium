# bpf_wireguard.c

## 用途

Cilium 的 **WireGuard tunnel 两端 datapath 粘合层**。挂到 `cilium_wg0` 虚拟网卡的 tc ingress/egress hook：

- `cil_from_wireguard`（tc ingress，`__section_entry`）：报文刚从 WireGuard 解密出来，决定它应该交给本地 pod、本地 host 栈还是继续转发。
- `cil_to_wireguard`（tc egress，`__section_entry`）：报文已经被路由到 `cilium_wg0`，准备被加密发往对端节点，这里做 NodePort 的 revSNAT 等 "最后一公里" 处理。

本文件只关心 overlay-ETH 之后的 inner header，因此在最前面定义：

```c
#define ETH_HLEN 0
#define IS_BPF_WIREGUARD 1
```

因为 WireGuard 接口是 L3 的，skb 到达时没有以太网头。`SKIP_ICMPV6_NS_HANDLING` / `SKIP_SRV6_HANDLING` 把本不属于加密路径的 helper 代码剪掉，缩小 object。

## 身份标签约定

```c
#define SECLABEL      WORLD_ID
#define SECLABEL_IPV4 WORLD_IPV4_ID
#define SECLABEL_IPV6 WORLD_IPV6_ID
```

发给远端 node 的流量在到达 wg 前已经打过标签，这里的 "world" 只是默认兜底身份；真正的 src identity 从 ipcache 里按 inner src IP 再查一次。

## `cil_from_wireguard`（ingress）

主流程：

1. `ctx_skip_nodeport_clear(ctx)` + `bpf_clear_meta(ctx)`：清掉旧 cb/meta。
2. `set_decrypt_mark(ctx, 0)`：把 skb 标记为 "已解密"，供上游 fw/ingress-strict 判断。
3. **提前短路**：
   ```c
   #if defined(TUNNEL_MODE) && !(defined(ENABLE_NODEPORT) && defined(ENABLE_NODE_ENCRYPTION))
       return CTX_ACT_OK;
   #endif
   ```
   如果同时开 vxlan/geneve overlay 且 node-encryption 没有依赖 wg，这里直接把包交回内核栈——因为后续 bpf_overlay 会处理。
4. 按 inner ethertype 分流（IPv4 / IPv6）：
   - 从 ipcache 查 `src identity`，写到 CB_SRC_LABEL。
   - 发 `TRACE_FROM_CRYPTO` 观察点，供 hubble 使用。
   - tail-call 到 `CILIUM_CALL_IPV{4,6}_FROM_WIREGUARD`。
   - 不管 tail-call 成功失败都返回 `CTX_ACT_OK`（通过 `send_drop_notify_error_with_exitcode_ext`），这是刻意为之：**maps 异常时也让包进栈，避免整条 wg 隧道崩溃**。

## tail call: `tail_handle_ipv{4,6}` → `handle_ipv{4,6}`

两个方向结构基本一致，以 IPv4 为例 (`handle_ipv4`)：

1. `revalidate_data_pull(ctx, &data, &data_end, &ip4)`，拉够 L3 头。
2. 若 `!CONFIG(enable_ipv4_fragments)` 且 `ipfrag_is_fragment` → `DROP_FRAG_NOSUPPORT`。
3. **NodePort LB**（`ENABLE_NODEPORT` 且 skb 没被要求 skip）：
   ```c
   ret = nodeport_lb4(ctx, ip4, identity, &punt_to_stack, ext_err, &is_dsr);
   ```
   拦截发给本节点 NodePort 的 Decrypted 流量，继续走 NAT 流程。`TC_ACT_REDIRECT`（L7 LB）或 `punt_to_stack=true` 直接返回。
4. 从 ipcache 根据 dst IP 查本地 endpoint：
   - **本地 pod**（`ep && !host-delivery`）：
     - `CONFIG(enable_bpf_host_routing)` 开启时，视情况 `maybe_add_l2_hdr`，然后 `ipv4_local_delivery(...)` 直送到容器。
     - 否则返回 `CTX_ACT_OK`，让内核栈路由。
   - **非 pod（本机 host）**：`add_l2_hdr(ctx)` 给包补一层以太网头（下游是普通 L2 设备），然后：
     ```c
     if (CONFIG(enable_identity_mark))
         set_identity_mark(ctx, identity, MARK_MAGIC_DECRYPT);
     return ipv4_host_delivery(ctx, __ETH_HLEN, ip4);
     ```
     `MARK_MAGIC_DECRYPT`（而不是 `MARK_MAGIC_IDENTITY`）是为了配合 **Ingress Strict Mode**（PR #39239）：下游 cilium_host 看到这个 mark 才知道包确实解密过。

IPv6 版本结构镜像一致，差别在 fragment 检测走 `ipv6_get_fraginfo`。

## `cil_to_wireguard`（egress）

挂在 `cilium_wg0` 的 egress，处理即将被 WireGuard 加密发出去的包。

```c
__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;
if (magic == MARK_MAGIC_IDENTITY)
    src_sec_identity = get_identity(ctx);
```

读 mark 推断源 identity。接下来：

1. `bpf_clear_meta(ctx)`。
2. **overlay 直通**：
   ```c
   if (magic == MARK_MAGIC_OVERLAY)
       goto out;
   ```
   如果包是从 bpf_overlay 发来的（已经做过所有加工），这里就只打一下 TRACE，不再 nat。
3. `handle_nat_fwd(ctx, 0, src_sec_identity, proto, true, &trace, &ext_err)`。
   `true` 是 `is_wg`：告诉 nat 层这是 wg egress，让它执行最后一跳 revSNAT（例如 NodePort 回包要把源 IP 从 node IP 换回原 pod IP）。
4. 发 `TRACE_TO_CRYPTO` 观察点。

即便 nat_fwd 失败，整体返回 `CTX_ACT_OK` 或 `send_drop_notify_error_ext`，不会阻塞加密。

## 关键点

- 本文件没有自己的 map 声明，全靠公共 lib。
- WireGuard 支持 **IngressStrictMode**：解密后的包必须带 `MARK_MAGIC_DECRYPT`，否则上游会丢。这里的 `set_decrypt_mark` + host delivery 用 `MARK_MAGIC_DECRYPT` 都是在为这个模式服务。
- `ENABLE_NODE_ENCRYPTION` 开关决定了 wg 是否参与 NodePort 的 encryption：开着时 wg 必须在 ingress 跑 `nodeport_lb{4,6}`，否则 wg 侧收到的 NodePort 流量 revSNAT 会丢。
- 这是少数几个必须 "fail-open" 的 datapath 组件：如果本程序 drop 了包，整条跨节点 pod → pod 流量就断掉；代码里到处用 `send_drop_notify_error_with_exitcode_ext(..., CTX_ACT_OK, ...)` 保证即使发送 drop notify 失败也让包通过。
