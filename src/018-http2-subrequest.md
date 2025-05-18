# HTTP/2 与子请求

前面的章节已经涵盖了 Pingora 的多种核心功能，包括基本代理、缓存、负载均衡、连接池管理和速率限制。本章将深入探讨 Pingora 中的两个高级功能：HTTP/2 支持和子请求（Subrequests）。

## HTTP/2 支持

HTTP/2 是一个主要的 HTTP 协议升级，它引入了多路复用、头部压缩、服务器推送等特性，可以显著提高 Web 性能。Pingora 提供了对 HTTP/2 的全面支持，包括作为客户端（对上游）和作为服务器（对下游）的场景。

### HTTP/2 概述

在深入了解 Pingora 的 HTTP/2 实现之前，让我们简要回顾一下 HTTP/2 的主要特性：

1. **二进制协议**：HTTP/2 使用二进制格式传输数据，而不是 HTTP/1.x 的文本格式
2. **多路复用**：单个 TCP 连接可以并行处理多个请求和响应
3. **头部压缩**：使用 HPACK 压缩格式减少请求头的大小
4. **服务器推送**：服务器可以主动推送资源到客户端
5. **流量控制**：精细控制数据传输
6. **优先级和依赖**：为请求设置优先级

### 在 Pingora 中启用 HTTP/2

Pingora 支持以下 HTTP/2 配置：

1. **对下游启用 HTTP/2**：允许客户端使用 HTTP/2 连接到 Pingora
2. **对上游启用 HTTP/2**：允许 Pingora 使用 HTTP/2 连接到上游服务器
3. **HTTP/2 明文（h2c）**：非加密的 HTTP/2 连接

#### 对下游启用 HTTPS 和 HTTP/2

要同时支持 HTTPS 和 HTTP/2 连接，需要配置 TLS 并启用 HTTP/2：

```rust
use pingora::prelude::*;
use pingora::tls::TlsSettings;
use std::sync::Arc;

fn main() -> Result<()> {
    // 创建服务器
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务
    let proxy = MyProxy::new();
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // 配置 TLS 和 HTTP/2
    let cert_path = "/path/to/cert.pem";
    let key_path = "/path/to/key.pem";

    // 创建 TLS 设置
    let mut tls_settings = TlsSettings::intermediate(cert_path, key_path)?;

    // 启用 HTTP/2 支持
    tls_settings.enable_h2();

    // 添加 TLS 监听器，支持 HTTP/2
    proxy_service.add_tls_with_settings("0.0.0.0:443", tls_settings)?;

    // 同时添加普通 HTTP 监听器
    proxy_service.add_tcp("0.0.0.0:80");

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 启动服务器
    server.run_forever();

    Ok(())
}
```

#### 启用 HTTP/2 明文（h2c）支持

Pingora 也支持 HTTP/2 明文连接（h2c），这在内部网络或测试环境中很有用：

```rust
use pingora::prelude::*;
use pingora::apps::http_app::HttpServerOptions;
use std::sync::Arc;

fn main() -> Result<()> {
    // 创建服务器
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务
    let proxy = MyProxy::new();
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // 获取 HTTP 应用程序逻辑
    if let Some(http_logic) = proxy_service.app_logic_mut() {
        // 创建 HTTP 服务器选项
        let mut http_server_options = HttpServerOptions::default();

        // 启用 h2c（明文 HTTP/2）
        http_server_options.h2c = true;

        // 设置选项
        http_logic.server_options = Some(http_server_options);
    }

    // 添加 TCP 监听器（将支持 h2c）
    proxy_service.add_tcp("0.0.0.0:8080");

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 启动服务器
    server.run_forever();

    Ok(())
}
```

#### 对上游连接使用 HTTP/2

Pingora 会自动根据 ALPN（应用层协议协商）结果选择使用 HTTP/1.1 还是 HTTP/2 连接到上游服务器。要确保使用 HTTP/2，你需要确保上游服务器支持 HTTP/2 并正确配置了 ALPN。

以下是自定义 `connectors_builder` 方法的示例，用于配置对上游的 HTTP/2 支持：

```rust
use pingora::connectors::http::HttpConnector;
use pingora::connectors::http::HttpConnectorsBuilder;
use pingora::prelude::*;
use std::sync::Arc;

#[async_trait]
impl ProxyHttp for MyProxy {
    // ... 其他实现

    fn connectors_builder(&self) -> Box<HttpConnectorsBuilder> {
        let mut builder = Box::new(HttpConnectorsBuilder::new());

        // 启用 HTTP/2，设置最大并发流
        builder.h2_max_streams = 100;

        // 设置 HTTP/2 ping 间隔，保持连接活跃
        builder.h2_ping_interval = Some(std::time::Duration::from_secs(30));

        // 其他可选配置...

        builder
    }
}
```

### HTTP/2 特有配置选项

Pingora 提供了多个配置选项来优化 HTTP/2 性能：

1. **h2_max_streams**：每个连接上允许的最大并发流数（默认为 100）
2. **h2_ping_interval**：保持连接活跃的 ping 间隔
3. **窗口大小**：控制数据流量的窗口大小
4. **帧大小**：调整 HTTP/2 帧的最大大小

示例配置：

```rust
// 在 server.rs 配置文件中
fn create_h2_settings() -> h2::server::Builder {
    let mut h2_opts = h2::server::Builder::new();

    // 设置单一连接最大帧大小为 16 KB
    h2_opts.max_frame_size(16 * 1024);

    // 设置初始窗口大小为 2 MB
    h2_opts.initial_window_size(2 * 1024 * 1024);

    // 设置最大并发流
    h2_opts.max_concurrent_streams(200);

    h2_opts
}

// 使用自定义 H2 设置
let h2_options = Some(create_h2_settings());
```

### HTTP/2 的性能考虑

在 Pingora 中使用 HTTP/2 时，应该考虑以下性能因素：

1. **并发流数量**：根据你的工作负载调整 `h2_max_streams`，过高会增加内存使用
2. **标头压缩**：HTTP/2 的 HPACK 压缩可以减少带宽使用，但增加一些 CPU 开销
3. **连接重用**：确保正确配置连接池以充分利用 HTTP/2 的多路复用特性
4. **窗口大小**：对于大型响应，增加窗口大小可提高吞吐量

## 子请求（Subrequests）

子请求是 Pingora 的一个强大功能，允许在处理主请求的过程中发起额外的 HTTP 请求。这在需要聚合多个后端服务数据、实现 API 网关功能或执行分布式事务时特别有用。

### 子请求的使用场景

以下是子请求的常见使用场景：

1. **数据聚合**：从多个微服务获取数据并组合到单个响应中
2. **API 网关**：丰富 API 响应或实现 BFF（Backend For Frontend）模式
3. **缓存填充**：当缓存未命中时，异步填充缓存
4. **验证和授权**：在处理主请求之前调用授权服务

### 创建和处理子请求

Pingora 提供了一个专门的 API 来创建和处理子请求。以下是一个基本示例：

```rust
use pingora::prelude::*;
use pingora_proxy::{HttpSession, SubReqCtx};
use std::sync::Arc;

#[async_trait]
impl ProxyHttp for MyProxy {
    type CTX = MyContext;

    // ... 其他方法的实现

    async fn response_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 从上游获取基本响应后，发起一个子请求获取额外数据
        if let Some(data) = self.fetch_additional_data(session).await? {
            // 修改响应，加入额外数据
            let resp_header = session.resp_header_mut();

            // 在这里处理响应...

            // 例如，将结果作为自定义标头添加
            resp_header.insert_header("X-Additional-Data", data)?;
        }

        Ok(())
    }

    // 创建一个子请求获取额外数据
    async fn fetch_additional_data(&self, session: &Session) -> Result<Option<String>> {
        // 创建子请求
        let mut request = Box::new(pingora_http::RequestHeader::build(
            "GET",
            "https://api.example.com/additional-data",
            None,
        )?);

        // 设置请求头
        request.insert_header("Host", "api.example.com")?;

        // 创建子请求上下文
        let ctx = Box::new(SubReqCtx::new());

        // 发送子请求并获取结果
        let response = self.send_subrequest(request, ctx).await?;

        // 处理响应...

        Ok(Some("processed_data".to_string()))
    }
}
```

### 子请求上下文和数据共享

子请求可以通过上下文对象与主请求共享数据：

```rust
// 定义自定义上下文类型
struct MySubReqCtx {
    original_request_id: String,
    timestamp: std::time::Instant,
    additional_data: Option<String>,
}

impl SubReqCtx for MySubReqCtx {
    // 实现必要的方法...
}

// 在主请求中创建上下文
let mut sub_ctx = Box::new(MySubReqCtx {
    original_request_id: ctx.request_id.clone(),
    timestamp: std::time::Instant::now(),
    additional_data: None,
});

// 发送子请求
let response = self.send_subrequest(request, sub_ctx).await?;

// 子请求完成后，可以从上下文中获取信息
if let Some(sub_ctx) = session.subrequest_ctx.as_ref() {
    if let Some(my_ctx) = sub_ctx.downcast_ref::<MySubReqCtx>() {
        let duration = my_ctx.timestamp.elapsed();
        // 使用子请求信息...
    }
}
```

### 并行处理多个子请求

在某些情况下，你可能需要并行发送多个子请求以提高性能：

```rust
use futures::future::join_all;
use pingora::prelude::*;

async fn fetch_multiple_resources(&self, session: &Session) -> Result<Vec<String>> {
    let endpoints = vec![
        "https://api1.example.com/data",
        "https://api2.example.com/data",
        "https://api3.example.com/data",
    ];

    let mut futures = Vec::new();

    // 为每个端点创建一个子请求
    for endpoint in endpoints {
        let request = Box::new(pingora_http::RequestHeader::build(
            "GET",
            endpoint,
            None,
        )?);

        let ctx = Box::new(SubReqCtx::new());

        // 将子请求添加到 futures 列表
        futures.push(self.send_subrequest(request, ctx));
    }

    // 并行等待所有子请求完成
    let results = join_all(futures).await;

    // 处理结果...
    let mut responses = Vec::new();
    for result in results {
        match result {
            Ok(response) => {
                // 处理响应
                responses.push("processed_data".to_string());
            }
            Err(e) => {
                // 处理错误
                log::warn!("Subrequest failed: {}", e);
            }
        }
    }

    Ok(responses)
}
```

### 子请求的最佳实践

使用子请求时，请考虑以下最佳实践：

1. **设置超时**：为子请求设置合理的超时时间，以防止主请求被长时间阻塞
2. **错误处理**：优雅地处理子请求失败，确保主请求仍能返回有用的响应
3. **限制并发**：控制并发子请求的数量，以避免过载上游服务
4. **缓存结果**：考虑缓存频繁请求的子请求结果
5. **监控性能**：监控子请求的延迟和成功率

## 总结

本章介绍了 Pingora 中的两个高级功能：HTTP/2 支持和子请求。HTTP/2 能够显著提高性能，特别是在高延迟环境或需要并行处理多个请求时。子请求功能允许在处理主请求的过程中发起额外的 HTTP 请求，为构建复杂的代理应用（如 API 网关和数据聚合服务）提供了强大的工具。

通过正确配置 HTTP/2 和有效利用子请求功能，你可以构建高性能、功能丰富的 Pingora 应用，满足现代 Web 服务的各种需求。
