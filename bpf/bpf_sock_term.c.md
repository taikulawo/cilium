# bpf_sock_term.c

## 用途

用来 **强制断开（socket destroy）那些已经通过 Cilium LB 建立连接、但现在后端已经消失或被从 service 移除的本地 socket**。它不是 datapath 上的 fast-path 程序，而是通过 `bpf_iter`（socket iterator）在 user space 触发时跑一遍整个 netns 的 TCP/UDP socket 列表，匹配到的调用 `bpf_sock_destroy()`。

典型使用场景：某个 LB backend 被删除后，已经和它建立的 TCP 长连接不会自然断开；Agent 需要主动终结，让客户端重连并被 LB 重新调度到新 backend。

## 全局 filter 配置

```c
struct sock_term_filter cilium_sock_term_filter;
```

一个 **单实例全局变量**（不是 map），由 Agent 侧通过 `.rodata`/`.bss` 更新。保存要销毁的 service VIP (`address`, `port`)。每次要清理某个 service 时，Agent 更新这个 filter，然后触发 `bpf_iter`。

## BTF 兼容声明

```c
struct sock_common {
    __be32 skc_daddr;
    __be16 skc_dport;
    struct in6_addr skc_v6_daddr;
} __sock_btf;

struct sock {
    struct sock_common __sk_common;
} __sock_btf;
```

- 内核真实 `struct sock` 字段位置随版本漂移，用 `__attribute__((preserve_access_index))` 让 clang 发出 CO-RE 重定位记录，加载时由 libbpf/kernel 用当前 vmlinux BTF 修正字段偏移。
- 单元测试模式 (`#ifdef BPF_TEST`) 下 `__sock_btf` 置空，因为测试里是自己构造 `struct sock`，布局就是声明本身。
- `bpf_sock_destroy` 用 kfunc 形式声明 (`__section(".ksyms")`)，由内核 ksyms 解析。

## 匹配逻辑

```c
static __always_inline bool matches_v4(void *sk, __sock_cookie cookie)
{
    struct sock *s = sk;

    if (s->__sk_common.skc_daddr != filter.address.addr4 ||
        s->__sk_common.skc_dport != bpf_htons(filter.port))
        return false;

    struct ipv4_revnat_tuple key = {
        .address = filter.address.addr4,
        .port    = bpf_htons(filter.port),
        .cookie  = cookie,
    };
    return map_lookup_elem(&cilium_lb4_reverse_sk, &key);
}
```

两道闸：
1. **socket 当前目的地址/端口** 要和 filter 对上（可能是 service 后端 IP:port，也可能是 VIP:port 看 sock LB 场景）。
2. 该 socket 必须在 **`cilium_lb4_reverse_sk`**（socket-level LB 的 revNAT 表）里有 entry —— 证明它是经过 cilium socket LB 转换的，不是普通连接。IPv6 走 `cilium_lb6_reverse_sk`。

两道都过，才真正 `bpf_sock_destroy(sk)`，并把被终结 socket 的 cookie 写到 iter 的 seq 文件返回给用户态，便于日志/审计。

## 四个 entry

| section | 入口 | 作用 |
|---------|------|------|
| `iter/udp` | `cil_sock_udp_destroy_v4` | 遍历 UDP sock，匹配 v4 规则就 destroy |
| `iter/tcp` | `cil_sock_tcp_destroy_v4` | 遍历 TCP sock，匹配 v4 规则就 destroy |
| `iter/udp` | `cil_sock_udp_destroy_v6` | 同上，v6 规则 |
| `iter/tcp` | `cil_sock_tcp_destroy_v6` | 同上，v6 规则 |

四个 program 都走一个薄薄的 wrapper，调用对应 `sock_udp_destroy_v4` / `sock_tcp_destroy_v4` 等 `__always_inline` 静态函数。两套（UDP/TCP）结构完全同构：
1. 从 iter ctx 取 socket；
2. `get_socket_cookie()`；
3. `matches_v4` / `matches_v6`；
4. `bpf_sock_destroy()` 成功 → `seq_write` cookie。

## 关键点

- 本程序不走 tc/xdp 路径，没有 drop notify、policy 等机制，纯粹是一个"离线"清理器。
- 与 `bpf_sock.c` 的 socket LB 配合：`bpf_sock.c` 在 `connect/sendmsg` 时写入 `cilium_lb4_reverse_sk`；此文件通过该表识别"曾经被 LB 翻译过的" socket。
- 失败时（例如内核不支持 `bpf_sock_destroy`，老内核）函数返回非 0，agent 侧只能回退到 "等客户端自己超时"。
- 可用 `BPF_TEST` 宏构造单元测试，`struct sock` 字段偏移退化为编译器计算，而不是 CO-RE 修正。
