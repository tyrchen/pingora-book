# 负载均衡与健康检查

前面的章节中，我们已经学习了 Pingora 的基本代理功能、HTTP 请求和响应处理以及 HTTP 缓存。本章将深入探讨另一个关键特性：负载均衡和健康检查机制，这对于构建高可用、高性能的代理服务至关重要。

## 负载均衡基础

负载均衡是一种将网络流量分发到多个服务器的技术，旨在提高应用程序的可用性、可靠性和性能。在 Pingora 中，`pingora-load-balancing` crate 提供了丰富的负载均衡功能。

### LoadBalancer 概述

`LoadBalancer` 是 Pingora 负载均衡系统的核心组件，它包含三个主要部分：

1. **服务发现（Service Discovery）**：识别可用的上游服务器
2. **健康检查（Health Check）**：监控上游服务器的健康状态
3. **选择算法（Selection Algorithm）**：决定将请求发送到哪个上游服务器

创建和使用 `LoadBalancer` 的基本流程如下：

```rust
use pingora_load_balancing::{selection::RoundRobin, LoadBalancer};
use std::sync::Arc;

// 创建一个使用轮询算法的负载均衡器
let lb = LoadBalancer::try_from_iter([
    "server1.example.com:443",
    "server2.example.com:443",
    "server3.example.com:443",
]).unwrap();

// 将负载均衡器包装在 Arc 中以便在多个线程间共享
let lb = Arc::new(lb);
```

## 负载均衡选择算法

Pingora 提供了几种内置的负载均衡算法，每种算法适用于不同的场景。

### 轮询（Round Robin）

轮询算法按顺序依次选择每个上游服务器，是最简单的负载均衡算法。它适用于所有上游服务器性能相近的情况：

```rust
use pingora_load_balancing::{selection::RoundRobin, LoadBalancer};

let lb = LoadBalancer::<RoundRobin>::try_from_iter(upstreams).unwrap();
```

### 随机（Random）

随机算法随机选择一个上游服务器，适用于短连接且上游服务器性能相近的情况：

```rust
use pingora_load_balancing::{selection::algorithms::Random, LoadBalancer};

let lb = LoadBalancer::<Random>::try_from_iter(upstreams).unwrap();
```

### 一致性哈希（Consistent Hashing）

一致性哈希算法确保相同的请求总是被路由到相同的上游服务器（只要该服务器仍然可用）。这对于维护会话亲和性或缓存一致性非常有用：

```rust
use pingora_load_balancing::{selection::consistent::Consistent, LoadBalancer};

let lb = LoadBalancer::<Consistent>::try_from_iter(upstreams).unwrap();
```

### 在 ProxyHttp 中使用负载均衡器

要在 `ProxyHttp` 实现中使用负载均衡器，可以在 `upstream_peer` 方法中调用负载均衡器的 `select` 方法：

```rust
use pingora::prelude::*;
use pingora_load_balancing::{selection::RoundRobin, LoadBalancer};
use std::sync::Arc;

struct BalancedProxy {
    load_balancer: Arc<LoadBalancer<RoundRobin>>,
}

#[async_trait]
impl ProxyHttp for BalancedProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 使用请求路径作为哈希键（对于一致性哈希算法有意义）
        let path = session.req_header().uri.path().as_bytes();

        // 选择一个上游服务器（最多尝试 256 次）
        let upstream = self.load_balancer.select(path, 256)
            .ok_or_else(|| Error::msg("No healthy upstream available"))?;

        // 创建 HTTP 对等点
        let peer = Box::new(HttpPeer::new(
            upstream,
            true, // 使用 TLS
            "example.com".to_string(), // SNI 主机名
        ));

        Ok(peer)
    }
}
```

## 健康检查

健康检查是负载均衡系统的关键组成部分，它确保请求只被发送到健康的上游服务器。Pingora 提供了多种健康检查机制。

### TCP 健康检查

TCP 健康检查通过尝试建立 TCP 连接来验证上游服务器的可用性。这是最基本的健康检查方式：

```rust
use pingora_load_balancing::{health_check::TcpHealthCheck, LoadBalancer, selection::RoundRobin};
use std::time::Duration;

// 创建负载均衡器
let mut lb = LoadBalancer::<RoundRobin>::try_from_iter(upstreams).unwrap();

// 配置 TCP 健康检查
let mut hc = TcpHealthCheck::new();
hc.consecutive_success = 2; // 需要 2 次连续成功才会将服务器标记为健康
hc.consecutive_failure = 3; // 需要 3 次连续失败才会将服务器标记为不健康

// 为负载均衡器设置健康检查
lb.set_health_check(hc);

// 设置健康检查频率（每 5 秒检查一次）
lb.health_check_frequency = Some(Duration::from_secs(5));
```

对于 HTTPS 上游服务器，可以使用 TLS 健康检查：

```rust
// 创建 TLS 健康检查（会尝试建立 TLS 握手）
let hc = TcpHealthCheck::new_tls("example.com");
lb.set_health_check(hc);
```

### HTTP 健康检查

HTTP 健康检查实际发送 HTTP 请求并验证响应，这提供了更准确的健康状态检测：

```rust
use pingora_load_balancing::{health_check::HttpHealthCheck, LoadBalancer, selection::RoundRobin};

// 创建负载均衡器
let mut lb = LoadBalancer::<RoundRobin>::try_from_iter(upstreams).unwrap();

// 创建 HTTP 健康检查
// 参数: 主机名, 是否使用 TLS
let mut hc = HttpHealthCheck::new("example.com", true);

// 默认情况下，检查会发送 GET 请求到 "/"，并期望 200 响应
// 但你可以自定义请求和验证逻辑

// 自定义健康检查端点
let mut req = RequestHeader::build("GET", b"/health", None).unwrap();
req.append_header("Host", "example.com").unwrap();
hc.req = req;

// 自定义响应验证逻辑
hc.validator = Some(Box::new(|resp| {
    // 检查状态码是否为 200
    if resp.status != 200 {
        return Err(Error::msg("Non-200 status code"));
    }

    // 检查响应体中是否包含特定内容（通过头部检查）
    if let Some(content_type) = resp.headers.get("content-type") {
        if content_type.as_bytes() != b"application/json" {
            return Err(Error::msg("Wrong content type"));
        }
    } else {
        return Err(Error::msg("Missing content-type header"));
    }

    Ok(())
}));

// 配置健康检查参数
hc.consecutive_success = 2;
hc.consecutive_failure = 2;
hc.reuse_connection = true; // 重用连接以提高效率

// 为负载均衡器设置健康检查
lb.set_health_check(Box::new(hc));
```

### 自定义健康检查

Pingora 允许通过实现 `HealthCheck` trait 来创建自定义健康检查逻辑：

```rust
use async_trait::async_trait;
use pingora_load_balancing::{health_check::HealthCheck, Backend};
use pingora_error::Result;

struct CustomHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
}

#[async_trait]
impl HealthCheck for CustomHealthCheck {
    async fn check(&self, target: &Backend) -> Result<()> {
        // 实现自定义的健康检查逻辑
        // 例如，可以检查数据库连接、运行复杂的验证等

        // 如果检查通过，返回 Ok(())
        // 如果检查失败，返回 Err(...)

        // 示例：简单的 DNS 解析检查
        if let Ok(_) = tokio::net::lookup_host(target.to_string()).await {
            Ok(())
        } else {
            Err(Error::msg("DNS resolution failed"))
        }
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    // 可选：实现状态变化回调
    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        println!("Backend {} is now {}", target, if healthy { "healthy" } else { "unhealthy" });
    }
}
```

## 作为后台服务运行健康检查

为了定期执行健康检查，需要将负载均衡器作为后台服务运行：

```rust
use pingora_core::services::background::background_service;
use std::{sync::Arc, time::Duration};

// 创建负载均衡器并配置健康检查（如前所示）
let mut lb = LoadBalancer::<RoundRobin>::try_from_iter(upstreams).unwrap();
let hc = TcpHealthCheck::new();
lb.set_health_check(hc);
lb.health_check_frequency = Some(Duration::from_secs(5));

// 创建并运行后台服务
let background = background_service("health_check", lb);
let lb = background.task();  // 获取对负载均衡器的引用

// 将后台服务添加到 Pingora 服务器
server.add_service(background);

// 创建使用此负载均衡器的代理服务
let proxy = BalancedProxy {
    load_balancer: lb,
};
let proxy_service = http_proxy_service(&server.configuration, proxy);
server.add_service(proxy_service);
```

## 完整的负载均衡与健康检查示例

下面是一个完整的示例，展示了如何在 Pingora 中实现负载均衡和健康检查：

```rust
use async_trait::async_trait;
use pingora::prelude::*;
use pingora_core::services::background::background_service;
use pingora_load_balancing::{
    health_check::HttpHealthCheck,
    selection::RoundRobin,
    LoadBalancer,
};
use std::{sync::Arc, time::Duration};

struct BalancedProxy {
    load_balancer: Arc<LoadBalancer<RoundRobin>>,
}

#[async_trait]
impl ProxyHttp for BalancedProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 从请求中获取路径作为哈希键
        let path = session.req_header().uri.path().as_bytes();

        // 使用负载均衡器选择上游服务器
        let upstream = self.load_balancer.select(path, 256)
            .ok_or_else(|| Error::msg("No healthy upstream available"))?;

        // 记录选择的上游服务器（生产环境中可能使用正式日志系统）
        println!("Selected upstream: {}", upstream);

        // 创建 HTTP 对等点
        let peer = Box::new(HttpPeer::new(
            upstream,
            true, // 使用 TLS
            "api.example.com".to_string(), // SNI 主机名
        ));

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 确保设置正确的 Host 头
        upstream_request.insert_header("Host", "api.example.com")?;
        Ok(())
    }
}

fn main() -> Result<()> {
    // 初始化日志
    env_logger::init();

    // 创建服务器
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建负载均衡器
    let mut lb = LoadBalancer::<RoundRobin>::try_from_iter([
        "api1.example.com:443",
        "api2.example.com:443",
        "api3.example.com:443",
    ])?;

    // 配置 HTTP 健康检查
    let mut hc = HttpHealthCheck::new("api.example.com", true);

    // 自定义健康检查请求
    let mut req = RequestHeader::build("GET", b"/health", None)?;
    req.append_header("Host", "api.example.com")?;
    hc.req = req;

    // 配置健康检查参数
    hc.consecutive_success = 2;
    hc.consecutive_failure = 3;
    hc.reuse_connection = true;

    // 设置健康检查
    lb.set_health_check(Box::new(hc));
    lb.health_check_frequency = Some(Duration::from_secs(10)); // 每 10 秒检查一次

    // 创建后台健康检查服务
    let background = background_service("health_check", lb);
    let lb_ref = background.task(); // 获取对负载均衡器的引用

    // 将后台服务添加到服务器
    server.add_service(background);

    // 创建代理服务
    let proxy = BalancedProxy {
        load_balancer: lb_ref,
    };

    // 配置代理服务
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp("0.0.0.0:8080"); // 监听 8080 端口

    // 添加代理服务到服务器
    server.add_service(proxy_service);

    // 启动服务器
    println!("Load balancer running on 0.0.0.0:8080");
    server.run_forever();

    Ok(())
}
```

## 基于权重的负载均衡

在某些情况下，你可能希望某些上游服务器接收更多的流量。Pingora 支持基于权重的负载均衡：

```rust
use pingora_load_balancing::{Backend, selection::weighted::Weighted, LoadBalancer};

// 创建带有权重的后端
let mut backends = [
    Backend::new("server1.example.com:443", 3), // 权重为 3
    Backend::new("server2.example.com:443", 2), // 权重为 2
    Backend::new("server3.example.com:443", 1), // 权重为 1
];

// 使用加权轮询算法
let lb = LoadBalancer::<Weighted<RoundRobin>>::try_from_iter(backends.iter().cloned())?;
```

在这个例子中，`server1` 将接收约 50% 的流量（3/6），`server2` 将接收约 33% 的流量（2/6），`server3` 将接收约 17% 的流量（1/6）。

## 自定义选择算法

如果内置的选择算法不满足需求，你可以实现自己的算法。这需要实现 `SelectionAlgorithm` trait 和 `BackendSelection` trait：

```rust
use pingora_load_balancing::selection::{SelectionAlgorithm, BackendSelection, BackendIter};
use std::collections::BTreeSet;
use std::sync::Arc;

// 自定义选择算法
struct MyCustomAlgorithm;

impl SelectionAlgorithm for MyCustomAlgorithm {
    fn new() -> Self {
        Self
    }

    fn next(&self, key: &[u8]) -> u64 {
        // 实现自定义选择逻辑
        // 这里只是一个简化的示例，返回键的第一个字节作为选择依据
        if key.is_empty() {
            0
        } else {
            key[0] as u64
        }
    }
}

// 自定义迭代器实现
struct MyCustomIter<'a> {
    backends: Vec<&'a Backend>,
    index: usize,
}

impl<'a> BackendIter for MyCustomIter<'a> {
    fn next(&mut self) -> Option<&Backend> {
        if self.index < self.backends.len() {
            let backend = self.backends[self.index];
            self.index += 1;
            Some(backend)
        } else {
            None
        }
    }
}

// 自定义选择器实现
struct MyCustomSelector {
    backends: Vec<Backend>,
}

impl BackendSelection for MyCustomSelector {
    type Iter = MyCustomIter<'static>; // 注意：这里使用 'static 是简化示例，实际应用中需要更复杂的生命周期处理

    fn build(backends: &BTreeSet<Backend>) -> Self {
        let backends = backends.iter().cloned().collect();
        Self { backends }
    }

    fn iter(self: &Arc<Self>, key: &[u8]) -> Self::Iter {
        // 基于某种逻辑对后端排序
        // 这里只是简单地按照默认顺序返回
        let backends = self.backends.iter().collect();
        MyCustomIter { backends, index: 0 }
    }
}

// 使用自定义选择器
let lb = LoadBalancer::<MyCustomSelector>::try_from_iter(upstreams)?;
```

创建自定义选择算法是一个高级用例，通常只有在内置算法无法满足特定需求时才需要。

## 总结

Pingora 的负载均衡和健康检查功能提供了构建高可用、高性能代理服务的强大工具：

1. **负载均衡算法**：Pingora 提供了轮询、随机和一致性哈希等内置算法，也支持基于权重的分配和自定义算法。

2. **健康检查**：支持 TCP 和 HTTP 健康检查，可以配置检查频率、成功/失败阈值等，确保请求只被发送到健康的上游服务器。

3. **后台服务**：健康检查作为后台服务定期执行，不会阻塞主请求处理流程。

4. **灵活的扩展性**：通过实现相关 trait，你可以创建自定义的健康检查逻辑和负载均衡算法。

通过合理配置负载均衡和健康检查，可以显著提高代理服务的可用性、性能和稳定性，为终端用户提供更好的体验。
