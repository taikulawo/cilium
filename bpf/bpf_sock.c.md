# bpf_sock.c

## 用途

Cilium 的 **socket-level load balancer**。挂到 cgroup v2 的多个 BPF 钩子上，在应用调用 `connect()/bind()/sendmsg()/recvmsg()/getpeername()/sock_release` 等 syscall **进入内核但尚未发包** 时就把 "service VIP:port" 翻译成 "backend IP:port"。相比在 TC/XDP 层做 LB，这里省掉了一次 DNAT/revDNAT，并避免每个数据报都要查 conntrack。

典型效果：pod 里 `curl 10.96.1.1:80`（ClusterIP）在 `connect()` 阶段就被改写为真实 pod IP，之后内核协议栈建立的 socket 直接朝 backend 发包；数据面连 LB 这一跳都不需要。

## cgroup hook 对照表

| section | 函数 | 触发时机 |
|---------|------|--------|
| `cgroup/connect4` | `cil_sock4_connect` | TCP/UDP `connect()`，IPv4 |
| `cgroup/connect6` | `cil_sock6_connect` | 同上，IPv6（含 v4-in-v6） |
| `cgroup/sendmsg4` | `cil_sock4_sendmsg` | UDP `sendmsg()`（未连接型 UDP），IPv4 |
| `cgroup/sendmsg6` | `cil_sock6_sendmsg` | 同上，IPv6 |
| `cgroup/recvmsg4` | `cil_sock4_recvmsg` | UDP `recvmsg()`，做反向翻译，IPv4 |
| `cgroup/recvmsg6` | `cil_sock6_recvmsg` | 同上，IPv6 |
| `cgroup/getpeername4` | `cil_sock4_getpeername` | 让应用拿到 "VIP:port" 而不是 backend，v4 |
| `cgroup/getpeername6` | `cil_sock6_getpeername` | 同上，v6 |
| `cgroup/bind4` | `cil_sock4_pre_bind` | health-check 场景下为 socket 预 bind 一个 slot（v4） |
| `cgroup/bind6` | `cil_sock6_pre_bind` | 同上，v6 |
| `cgroup/post_bind4` | `cil_sock4_post_bind` | 拦截会和已有 NodePort/LB VIP 冲突的 bind()，v4 |
| `cgroup/post_bind6` | `cil_sock6_post_bind` | 同上，v6 |
| `cgroup/sock_release` | `cil_sock_release` | socket 关闭：清掉 revNAT 条目 |

返回值使用 `SYS_PROCEED(1)` / `SYS_REJECT(0)` 两个宏，`try_set_retval` 将具体 errno 透出给用户空间 syscall。

## 关键配置项与运行时结构

- `CONFIG(socket_lb).hostns_only` —— 只对 host netns 的 socket 做 LB，pod 内 socket 走 TC 路径。
- `CONFIG(nodeport_port_min/max)` —— NodePort 端口范围，决定 wildcard lookup 是否生效。
- `CONFIG(enable_lrp)` —— Local Redirect Policy。
- `CONFIG(enable_health_check)` —— cilium health 使用的特殊 socket 标记（`SO_MARK = MARK_MAGIC_HEALTH`）要特判。
- `CONFIG(host_netns_cookie)` —— 用来识别 host netns，否则调 `get_netns_cookie(NULL)` 兜底。
- `DECLARE_CONFIG(bool, disable_external_ip_mitigation, ...)` —— 关联 CVE-2020-8554 的开关：是否允许 pod 对非 host external-IP 做 service 翻译。

socket LB 用到的核心 map：
- `cilium_lb4_services_v2 / cilium_lb6_services_v2`（通过 `lb4_lookup_service`）
- `cilium_lb4_backends_v3 / cilium_lb6_backends_v3`
- `cilium_lb4_reverse_sk / cilium_lb6_reverse_sk`（socket-cookie → 原始 VIP）
- `cilium_lb{4,6}_health`（健康检查）

## 转发翻译：`__sock4_xlate_fwd`（v4 为例）

函数签名：
```c
static __always_inline int __sock4_xlate_fwd(struct bpf_sock_addr *ctx,
                                             struct bpf_sock_addr *ctx_full,
                                             const bool udp_only,
                                             const bool is_connect);
```

主干步骤：

1. **hostns 判定**。`CONFIG(socket_lb).hostns_only && !in_hostns` → 返回 `-ENXIO` 跳过。
2. **协议过滤**。TCP / UDP / UDPLite，其它返回 `-ENOTSUP`。
3. **service lookup**。
   - 先直查 `lb4_lookup_service(key)`。
   - 查不到就 `sock4_wildcard_lookup_full()` 处理 NodePort / HostPort 的 wildcard（dst IP 换成 0）。
   - 都查不到：`-ENXIO`，连接继续，让它走原路径。
4. **endpoint 为 0 处理**。`svc->count == 0 && !L7LB` 时按 `enable_no_service_endpoints_routable` 决定是否 `-EHOSTUNREACH`。
5. **mitigation**。
   - L7 punt proxy → `SYS_PROCEED` 直通，由 TC 层接管。
   - `sock4_skip_xlate()` CVE-2020-8554：ExternalIP / HostPort 不是 host 自身 → `-EPERM`。
   - LRP（Local Redirect）跳过规则。
6. **L7 LB**。节点内（`in_hostns`）直接拿 `svc->l7_lb_proxy_port` + `127.0.0.1` 当 backend；非 hostns 返回 0 让 TC 继续处理。
7. **affinity**。`lb4_svc_is_affinity(svc)` 时按 `(svc, client_cookie)` 从 `cilium_lb4_affinity` 查 backend_id，拿不到就随机 + 更新 affinity。
8. **随机 backend_slot 选择**。`sock_select_slot(ctx) % svc->count + 1`，TCP 用 `get_prandom_u32()`，UDP 用 socket cookie 保证同 socket 的多次 `sendmsg` 走同一后端。
9. **revNAT 写入**。调 `sock4_update_revnat`，把 `(socket cookie, backend addr+port) → (原 VIP+port, rev_nat_id)` 存到 `cilium_lb4_reverse_sk`。
10. **改写 ctx**。`ctx->user_ip4 = backend->address; ctx_set_port(ctx, backend->port);`。应用随后发包就直接发到 backend。

trace 侧用 `send_trace_sock_notify4(ctx_full, XLATE_PRE_DIRECTION_FWD/XLATE_POST_DIRECTION_FWD, ...)` 把前后地址都打点。

### 反向翻译 `__sock4_xlate_rev`

`recvmsg`/`getpeername` 场景：
1. 以 socket cookie + 当前 dst (backend) 为 key 查 `cilium_lb4_reverse_sk`。
2. 用返回的 `rev_nat_index` 反查 service；若 service 不存在或 `rev_nat_index` 对不上，删 revNAT 条目并回 `-ENOENT`。
3. 否则把 `ctx->user_ip4` / port 改回原来的 VIP:port，应用层感知到的 peer 就是 service VIP。

`sock_release` 时清理：`sock4_delete_revnat` / `sock6_delete_revnat`。

## wildcard lookup

两个辅助：

- `sock4_wildcard_lookup`（只在 `__sock4_post_bind` 用）：仅在 nodeport 端口范围内且 dst 是 host 身份或 loopback 时，用 IP=0 查 service。
- `sock4_wildcard_lookup_full`：区分 NodePort / HostPort：
  - NodePort 要求 service 是 `lb4_svc_is_nodeport` 且 remote endpoint 是 HOST_ID 或 remote-node（本集群）。
  - HostPort 要求 `lb4_svc_is_hostport`；带 `SVC_FLAG_LOOPBACK` 时限制必须是 loopback 发起。

## bind 相关

- `cil_sock4_pre_bind`：只给 cilium 自己 health-check socket（`SO_MARK == MARK_MAGIC_HEALTH`）使用：往 `cilium_lb4_health` 塞一条 `(socket cookie) → health peer`，然后 `sock4_auto_bind()` 把 `user_ip4/port` 清 0，让内核分配 random port。
- `cil_sock4_post_bind`（仅 ENABLE_NODEPORT）：如果用户态进程想 bind 到的 (ip, port) 碰巧是 NodePort/LoadBalancer/ExternalIP 的 service → `-EADDRINUSE` 拒绝，防止意外劫持 service 流量。L7 Envoy 场景允许，因为它必须在 hostns 上同一 VIP:port 监听。

## v4-in-v6

应用用 IPv6 socket 连到 `::ffff:1.2.3.4` 时：
- `sock6_xlate_v4_in_v6` 构造一个假 `bpf_sock_addr`（协议/地址/端口都从 v6 ctx 挤出来），复用 `__sock4_xlate_fwd`。翻译结果再 `build_v4_in_v6` 转回 v6 格式写回 ctx。
- 反向、pre_bind、post_bind 都有相似的 "v4 in v6 fallback" 对偶实现。

## 实用技巧

- `ctx_protocol`, `ctx_dst_port`, `ctx_src_port`, `ctx_set_port` 等宏：封装内核对 `struct bpf_sock_addr` 的"窄字段访问"限制（内核验证器以前不允许从 `__u32` 字段抽取窄位，这里用 `volatile` 和显式强转绕过）。
- `ctx_get_v6_address` / `ctx_set_v6_address` 读写 `user_ip6[4]`，每个赋值间插 `barrier()`，强制编译器按顺序写，避免 verifier 不认可"随机顺序写满 16 字节"。

## 关键点

- 这是 Cilium 性能收益最大的组件之一：pod → ClusterIP 的流量几乎没有额外 datapath 开销。
- CVE-2020-8554 的默认防护依赖 `sock4_skip_xlate()`：对非 host 的 ExternalIP / HostPort 拒绝 socket LB，强制回到 TC 路径，由那边的 policy 决定是否放行。管理员可以用 `disable_external_ip_mitigation=true` 关掉这层防护（例如集群要用公共 externalIP 做 service 时）。
- L7 LB 场景（Envoy）通过 "返回 0 让 TC 接手" 或 "改成 127.0.0.1:proxy_port" 两种策略切换：node-local 走后者，远端走前者。
- UDP 的 `sendmsg` 没有 socket 连接概念，所以每条消息都走 `__sock4_xlate_fwd(udp_only=true, is_connect=false)`，revNAT 条目靠 socket cookie 保持跨多条消息一致。
