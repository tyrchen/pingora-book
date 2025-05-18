# 上游服务器选择与负载均衡

在本章中，我们将探讨如何在 Pingora 中选择上游服务器以及实现负载均衡。具体来说，我们将深入了解 `upstream_peer()` 方法的使用方式，以及如何结合 `pingora-load-balancing` crate 实现高级负载均衡功能。

## upstream_peer 方法概述

`upstream_peer()` 方法是 `ProxyHttp` trait 中最核心的方法之一，它决定了客户端请求将被转发到哪个上游服务器。无论是简单的反向代理还是复杂的负载均衡系统，都需要实现这个方法来指定请求的目标服务器。

方法签名如下：

```rust
async fn upstream_peer(
    &self,
    session: &mut Session,
    ctx: &mut Self::CTX,
) -> Result<Box<HttpPeer>>;
```

该方法接收：

- `session`: 包含当前请求相关信息的会话对象
- `ctx`: 在 `new_ctx()` 方法中创建的请求上下文对象

它返回一个装箱的 `HttpPeer` 实例，该实例定义了上游服务器的连接信息，包括地址、端口、TLS 设置等。

## 返回 HttpPeer 结构

`HttpPeer` 是 Pingora 定义的代表上游服务器的结构体，它实现了 `Peer` trait。使用 `HttpPeer` 可以指定：

1. 服务器地址和端口
2. 是否使用 TLS (HTTPS)
3. TLS 使用的 SNI (Server Name Indication)
4. 代理设置（如果需要通过另一个代理连接到上游）
5. 客户端证书（用于 mTLS）
6. 其他连接选项（超时、绑定地址等）

创建 `HttpPeer` 的最简单方式：

```rust
let peer = HttpPeer::new("example.com:443", true, "example.com".to_string());
```

其中：

- 第一个参数是服务器地址和端口
- 第二个参数指定是否使用 TLS（true 表示 HTTPS）
- 第三个参数是 TLS 的 SNI 值

完整的 `HttpPeer` 结构及其选项：

| 属性            | 含义                             |
| --------------- | -------------------------------- |
| address         | 连接的 IP:端口                   |
| scheme          | HTTP 或 HTTPS                    |
| sni             | TLS SNI 值（仅 HTTPS）           |
| proxy           | 代理设置（如果需要通过代理连接） |
| client_cert_key | 客户端证书（用于 mTLS）          |
| options         | 连接选项（见下表）               |

`PeerOptions` 可配置的连接选项：

| 属性                     | 含义                                         |
| ------------------------ | -------------------------------------------- |
| bind_to                  | 客户端绑定的本地地址                         |
| connection_timeout       | TCP 连接建立超时时间                         |
| total_connection_timeout | 包含 TLS 握手在内的连接建立总超时时间        |
| read_timeout             | 从上游读取的超时时间                         |
| idle_timeout             | 空闲连接保持时间                             |
| write_timeout            | 写入上游的超时时间                           |
| verify_cert              | 是否验证上游服务器证书                       |
| verify_hostname          | 是否验证证书 CN 与 SNI 匹配                  |
| alternative_cn           | 接受的备选证书 CN                            |
| alpn                     | HTTP 协议 ALPN 设置（HTTP/1.1 和/或 HTTP/2） |
| ca                       | 用于验证服务器证书的根 CA                    |

## 根据请求特性动态选择上游服务器

在实际应用中，通常需要根据请求的特性（如路径、Host 头部、查询参数等）动态选择不同的上游服务器。Pingora 的 `upstream_peer()` 方法能够访问完整的请求信息，使这种动态路由变得非常简单。

### 根据路径选择上游服务器

最常见的路由方式是基于请求路径的路由。例如，将 `/api/` 开头的请求路由到 API 服务器，将 `/static/` 开头的请求路由到静态资源服务器。

```rust
async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // 获取请求路径
    let path = session.req_header().uri().path();

    // 基于路径选择上游服务器
    let (host, port, use_tls, sni) = if path.starts_with("/api/") {
        // API 服务器
        ("api.example.com", 443, true, "api.example.com")
    } else if path.starts_with("/static/") {
        // 静态资源服务器
        ("static.example.com", 80, false, "")
    } else {
        // 默认服务器
        ("www.example.com", 443, true, "www.example.com")
    };

    // 记录选择的上游服务器到上下文（用于日志或监控）
    ctx.selected_upstream = Some(host.to_string());

    // 创建并返回 HttpPeer
    let peer = HttpPeer::new(format!("{}:{}", host, port), use_tls, sni.to_string());
    Ok(Box::new(peer))
}
```

### 根据 Host 头部选择上游服务器

另一种常见的路由方式是基于 Host 头部的路由，这对于托管多个域名的代理服务器特别有用。

```rust
async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // 获取 Host 头部
    let host_header = match session.req_header().headers().get("host") {
        Some(h) => h.to_str().unwrap_or(""),
        None => "",
    };

    // 基于 Host 头部选择上游服务器
    let (upstream_host, port, use_tls) = match host_header {
        "api.example.com" => ("10.0.1.10", 8080, false),
        "blog.example.com" => ("10.0.1.20", 8080, false),
        "secure.example.com" => ("10.0.1.30", 443, true),
        _ => ("10.0.1.1", 80, false), // 默认服务器
    };

    // 记录到上下文
    ctx.selected_host = Some(host_header.to_string());

    // 创建并返回 HttpPeer
    let peer = HttpPeer::new(
        format!("{}:{}", upstream_host, port),
        use_tls,
        host_header.to_string(),  // 使用原始 Host 作为 SNI
    );
    Ok(Box::new(peer))
}
```

### 组合多种条件选择上游服务器

在更复杂的场景中，可能需要组合多种条件来选择上游服务器。例如，同时考虑路径、Host 头部和其他请求头：

```rust
async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    let req = session.req_header();
    let path = req.uri().path();

    // 获取 Host 头部
    let host = match req.headers().get("host") {
        Some(h) => h.to_str().unwrap_or(""),
        None => "",
    };

    // 获取用户 Agent
    let is_mobile = match req.headers().get("user-agent") {
        Some(ua) => {
            let ua_str = ua.to_str().unwrap_or("");
            ua_str.contains("Mobile") || ua_str.contains("Android")
        },
        None => false,
    };

    // 基于多种条件选择上游服务器
    let (upstream, use_tls, sni) = if host == "api.example.com" {
        if path.starts_with("/v2/") {
            // API v2
            ("api-v2.internal:8080", false, "")
        } else {
            // API v1
            ("api-v1.internal:8080", false, "")
        }
    } else if host == "www.example.com" {
        if path.starts_with("/shop/") {
            // 商店
            ("shop.internal:8080", false, "")
        } else if is_mobile {
            // 移动版网站
            ("mobile.internal:8080", false, "")
        } else {
            // 桌面版网站
            ("desktop.internal:8080", false, "")
        }
    } else {
        // 默认
        ("default.internal:8080", false, "")
    };

    // 记录选择信息到上下文
    ctx.selected_upstream = Some(upstream.to_string());
    ctx.is_mobile_client = is_mobile;

    // 创建并返回 HttpPeer
    Ok(Box::new(HttpPeer::new(upstream, use_tls, sni.to_string())))
}
```

### 根据查询参数或 Cookie 选择上游服务器

有时可能需要根据查询参数或 Cookie 进行路由，例如实现 A/B 测试或金丝雀发布：

```rust
async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    let req = session.req_header();

    // 检查是否有特定的查询参数
    let uri = req.uri();
    let query = uri.query().unwrap_or("");

    // 解析查询参数（简化版）
    let is_beta_tester = query.contains("beta=true");

    // 或者检查 Cookie
    let has_beta_cookie = if let Some(cookie) = req.headers().get("cookie") {
        cookie.to_str().unwrap_or("").contains("beta=true")
    } else {
        false
    };

    // 选择上游服务器
    let upstream = if is_beta_tester || has_beta_cookie {
        // 导向测试环境
        "beta.example.com:443"
    } else {
        // 导向生产环境
        "www.example.com:443"
    };

    // 记录到上下文
    ctx.is_beta_user = is_beta_tester || has_beta_cookie;

    // 创建并返回 HttpPeer
    Ok(Box::new(HttpPeer::new(upstream, true, upstream.split(':').next().unwrap_or("").to_string())))
}
```

## 使用 pingora-load-balancing 实现负载均衡

当需要将请求分发到多个同质的上游服务器时，可以使用 Pingora 的负载均衡功能。`pingora-load-balancing` crate 提供了一组用于服务发现和负载均衡的工具。

### LoadBalancer 基础

`LoadBalancer` 结构是 `pingora-load-balancing` crate 的核心，它管理一组上游服务器，并使用特定的算法在这些服务器之间分配请求。

#### 创建 LoadBalancer

以下是创建 `LoadBalancer` 的基本步骤：

```rust
use pingora_load_balancing::{LoadBalancer, selection::RoundRobin};
use std::sync::Arc;

// 创建一个使用轮询算法的负载均衡器
let mut lb = LoadBalancer::try_from_iter([
    "server1.example.com:443",
    "server2.example.com:443",
    "server3.example.com:443",
]).unwrap();

// 将负载均衡器包装在 Arc 中以便在多个线程间共享
let lb = Arc::new(lb);
```

#### 使用 LoadBalancer 选择上游服务器

在 `upstream_peer()` 方法中使用负载均衡器：

```rust
struct MyProxy {
    load_balancer: Arc<LoadBalancer<RoundRobin>>,
}

#[async_trait]
impl ProxyHttp for MyProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 使用负载均衡器选择一个上游服务器
        // 第一个参数是用于一致性哈希的键（如果使用哈希算法）
        // 第二个参数是最大迭代次数（防止陷入无限循环）
        let upstream = self.load_balancer.select(b"", 256).unwrap();

        // 创建 HttpPeer
        let peer = HttpPeer::new(upstream, true, "example.com".to_string());
        Ok(Box::new(peer))
    }
}
```

### 负载均衡算法

`pingora-load-balancing` 提供了几种常用的负载均衡算法：

1. **轮询 (Round Robin)** - 按顺序依次选择每个上游服务器
2. **随机 (Random)** - 随机选择一个上游服务器
3. **一致性哈希 (Consistent Hashing)** - 使用一致性哈希算法，确保相同的请求总是被路由到相同的上游服务器

选择算法的示例：

```rust
// 轮询算法
let lb_round_robin = LoadBalancer::<RoundRobin>::try_from_iter(upstreams).unwrap();

// 随机算法
let lb_random = LoadBalancer::<Random>::try_from_iter(upstreams).unwrap();

// 一致性哈希算法
let lb_consistent = LoadBalancer::<Consistent>::try_from_iter(upstreams).unwrap();
```

### 基于请求特征的一致性哈希

一致性哈希特别适合需要会话亲和性的场景，例如维护用户会话或缓存一致性。通过使用请求的特定部分（如用户 ID 或会话 ID）作为哈希键，可以确保相同的客户端总是被路由到相同的上游服务器：

```rust
async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // 获取用户会话 ID（从 Cookie 或其他地方）
    let session_id = get_session_id(session).unwrap_or_else(|| "default".to_string());

    // 使用会话 ID 作为哈希键，确保会话亲和性
    let upstream = self.load_balancer.select(session_id.as_bytes(), 256).unwrap();

    // 创建 HttpPeer
    let peer = HttpPeer::new(upstream, true, "example.com".to_string());
    Ok(Box::new(peer))
}

fn get_session_id(session: &Session) -> Option<String> {
    // 从 Cookie 中提取会话 ID
    if let Some(cookie) = session.req_header().headers().get("cookie") {
        let cookie_str = cookie.to_str().ok()?;

        // 简单解析 Cookie（生产环境应使用专门的 Cookie 解析库）
        for part in cookie_str.split(';') {
            let part = part.trim();
            if let Some(id) = part.strip_prefix("session_id=") {
                return Some(id.to_string());
            }
        }
    }
    None
}
```

### 健康检查

负载均衡的一个关键方面是识别并避开不健康的上游服务器。`pingora-load-balancing` 提供了内置的健康检查机制：

```rust
use pingora_load_balancing::{health_check, LoadBalancer, selection::RoundRobin};
use pingora_core::services::background::{background_service, GenBackgroundService};
use std::{sync::Arc, time::Duration};

// 创建负载均衡器
let mut lb = LoadBalancer::<RoundRobin>::try_from_iter([
    "server1.example.com:443",
    "server2.example.com:443",
    "server3.example.com:443",
]).unwrap();

// 配置 TCP 健康检查
let hc = health_check::TcpHealthCheck::new();
lb.set_health_check(hc);
lb.health_check_frequency = Some(Duration::from_secs(5));  // 每 5 秒检查一次

// 创建运行健康检查的后台服务
let background = background_service("health check", lb);
let lb = background.task();  // 获取对负载均衡器的引用

// 将后台服务添加到 Pingora 服务器
my_server.add_service(background);
```

健康检查的工作原理：

1. 后台服务定期对每个上游服务器执行健康检查
2. 如果服务器响应失败，它将被标记为不健康
3. 负载均衡器会自动跳过不健康的服务器
4. 当服务器恢复健康时，负载均衡器会自动将其重新加入到可用池中

### 加权负载均衡

在某些情况下，不同的上游服务器可能具有不同的处理能力。通过设置权重，可以控制服务器接收请求的比例：

```rust
use pingora_load_balancing::{Backend, LoadBalancer, selection::RoundRobin};
use std::collections::BTreeSet;

// 创建带有权重的后端
let mut backends = BTreeSet::new();
backends.insert(Backend::new("server1.example.com:443", 10));  // 服务器1权重为10
backends.insert(Backend::new("server2.example.com:443", 5));   // 服务器2权重为5
backends.insert(Backend::new("server3.example.com:443", 1));   // 服务器3权重为1

// 创建负载均衡器
let lb = LoadBalancer::<RoundRobin>::new(backends);
```

在这个例子中，server1 将处理约 10/16 (62.5%) 的请求，server2 将处理约 5/16 (31.25%) 的请求，server3 仅处理约 1/16 (6.25%) 的请求。

### 多集群路由

在更复杂的场景中，可能需要将请求路由到不同的后端服务器集群。这可以通过组合集群选择和负载均衡来实现：

```rust
struct MultiClusterRouter {
    api_cluster: Arc<LoadBalancer<RoundRobin>>,
    web_cluster: Arc<LoadBalancer<RoundRobin>>,
    static_cluster: Arc<LoadBalancer<RoundRobin>>,
}

#[async_trait]
impl ProxyHttp for MultiClusterRouter {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let path = session.req_header().uri().path();

        // 根据路径选择集群
        let (cluster, use_tls, sni) = if path.starts_with("/api/") {
            (&self.api_cluster, false, "")
        } else if path.starts_with("/static/") {
            (&self.static_cluster, false, "")
        } else {
            (&self.web_cluster, true, "www.example.com")
        };

        // 从选定的集群中选择上游服务器
        let upstream = cluster.select(b"", 256).unwrap();

        // 创建 HttpPeer
        let peer = HttpPeer::new(upstream, use_tls, sni.to_string());
        Ok(Box::new(peer))
    }
}

// 创建并配置路由器
fn create_router() -> MultiClusterRouter {
    // 创建 API 集群
    let api_cluster = build_cluster(["api1:8080", "api2:8080", "api3:8080"]);

    // 创建 Web 集群
    let web_cluster = build_cluster(["web1:443", "web2:443"]);

    // 创建静态资源集群
    let static_cluster = build_cluster(["static1:80", "static2:80", "static3:80"]);

    MultiClusterRouter {
        api_cluster,
        web_cluster,
        static_cluster,
    }
}

// 辅助函数：创建并配置集群
fn build_cluster<S: AsRef<str>>(upstreams: impl IntoIterator<Item = S>) -> Arc<LoadBalancer<RoundRobin>> {
    let upstreams = upstreams.into_iter().map(|s| s.as_ref()).collect::<Vec<_>>();
    let mut lb = LoadBalancer::<RoundRobin>::try_from_iter(upstreams).unwrap();

    // 配置健康检查
    lb.set_health_check(health_check::TcpHealthCheck::new());

    Arc::new(lb)
}
```

## 小结

在本章中，我们探讨了 Pingora 中两个关于上游服务器选择的关键方面：

1. **动态选择上游服务器**：通过 `upstream_peer()` 方法，可以根据请求的各种特征（路径、头部、查询参数等）选择适当的上游服务器。

2. **负载均衡**：使用 `pingora-load-balancing` crate，可以实现高级负载均衡功能，包括不同的均衡算法、健康检查、权重分配等。

通过结合这两个方面，可以构建一个既能根据请求内容进行智能路由，又能在多个同类上游服务器之间实现高效负载分配的强大代理系统。
