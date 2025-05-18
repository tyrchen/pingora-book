# 构建最简单的反向代理

在前面的章节中，我们已经详细介绍了 Pingora 的各种核心功能和高级特性。现在，我们将把这些知识应用到实际开发中，构建一个最简单的反向代理。这个示例将帮助你了解 Pingora 应用的基本结构和工作流程。

## 反向代理的基本概念

反向代理是一种服务器，它接收客户端的请求，然后将这些请求转发到一个或多个后端服务器，再将后端服务器的响应返回给客户端。反向代理通常用于以下场景：

1. **负载均衡**：将请求分发到多个后端服务器
2. **缓存**：缓存静态内容以减轻后端服务器的负担
3. **安全防护**：隐藏后端服务器的真实地址，提供额外的安全层
4. **SSL 终结**：处理 HTTPS 连接，减轻后端服务器的计算负担

在本章中，我们将构建一个最简单的反向代理，它将所有请求转发到单个上游服务器。

## 项目设置

首先，创建一个新的 Rust 项目：

```bash
cargo new simple_proxy
cd simple_proxy
```

然后在 `Cargo.toml` 文件中添加必要的依赖：

```toml
[package]
name = "simple_proxy"
version = "0.1.0"
edition = "2021"

[dependencies]
pingora = "0.3"
tokio = { version = "1", features = ["full"] }
env_logger = "0.10"
```

## 实现最简单的反向代理

下面是一个最简单的反向代理实现，它将所有请求转发到 `example.org`：

```rust
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;

// 定义一个简单的代理服务结构体
struct SimpleProxy;

// 实现 ProxyHttp trait
#[async_trait]
impl ProxyHttp for SimpleProxy {
    // 定义请求上下文类型，这里使用空单元类型，因为我们不需要在请求处理过程中共享任何状态
    type CTX = ();

    // 创建新的上下文实例
    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    // 选择上游服务器
    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 创建一个指向 example.org 的 HTTP 对等点
        // 参数：(域名或IP, 端口, 使用HTTPS?, SNI主机名)
        let peer = Box::new(HttpPeer::new(
            ("example.org", 443),
            true,
            "example.org".to_string(),
        ));

        Ok(peer)
    }
}

fn main() -> Result<()> {
    // 初始化日志系统
    env_logger::init();

    // 创建服务器实例
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务实例
    let proxy = SimpleProxy;
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // 配置服务监听地址和端口
    proxy_service.add_tcp("0.0.0.0:8080");

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 启动服务器
    println!("Simple reverse proxy running on 0.0.0.0:8080");
    server.run_forever();

    Ok(())
}
```

将这段代码保存到 `src/main.rs` 中，然后运行：

```bash
RUST_LOG=info cargo run
```

现在，你可以通过访问 `http://localhost:8080` 来测试你的代理。所有请求都将被转发到 `https://example.org`。

## 代码解析

让我们详细解析这段代码：

### 1. 结构体定义

```rust
struct SimpleProxy;
```

这是一个空结构体，用于实现 `ProxyHttp` trait。在这个简单的例子中，我们不需要任何状态，所以使用空结构体就足够了。

### 2. 实现 ProxyHttp trait

```rust
#[async_trait]
impl ProxyHttp for SimpleProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            ("example.org", 443),
            true,
            "example.org".to_string(),
        ));

        Ok(peer)
    }
}
```

`ProxyHttp` trait 是 Pingora 中用于定义代理行为的核心 trait。在这个最小实现中，我们只覆盖了两个必须实现的方法：

- **`type CTX`**：指定请求上下文的类型。上下文在整个请求处理过程中共享，用于在不同阶段之间传递数据。在这个简单的例子中，我们使用空单元类型 `()`，因为我们不需要共享任何状态。

- **`new_ctx()`**：为每个新请求创建一个上下文实例。

- **`upstream_peer()`**：这是最关键的方法，它决定将请求转发到哪个上游服务器。在这个例子中，我们创建了一个指向 `example.org` 的 HTTPS 对等点。

  `HttpPeer::new` 方法接收三个参数：
  - 服务器地址和端口：`("example.org", 443)`
  - 是否使用 HTTPS：`true`（因为 example.org 支持 HTTPS）
  - SNI（Server Name Indication）主机名：用于 TLS 握手，通常与目标域名相同

### 3. 主函数设置

```rust
fn main() -> Result<()> {
    // 初始化日志系统
    env_logger::init();

    // 创建服务器实例
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务实例
    let proxy = SimpleProxy;
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // 配置服务监听地址和端口
    proxy_service.add_tcp("0.0.0.0:8080");

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 启动服务器
    println!("Simple reverse proxy running on 0.0.0.0:8080");
    server.run_forever();

    Ok(())
}
```

主函数完成以下步骤：

1. **初始化日志**：使用 `env_logger` 初始化日志系统。你可以通过 `RUST_LOG` 环境变量控制日志级别，例如 `RUST_LOG=info`。

2. **创建服务器**：使用 `Server::new(None)` 创建一个新的服务器实例，`None` 表示不使用配置文件，而是采用默认配置。

3. **引导服务器**：`server.bootstrap()` 初始化服务器，包括设置信号处理和线程池。

4. **创建代理服务**：使用 `http_proxy_service` 函数创建一个代理服务，传入服务器配置和我们的 `SimpleProxy` 实现。

5. **配置监听地址**：`proxy_service.add_tcp("0.0.0.0:8080")` 设置代理服务监听所有网络接口的 8080 端口。

6. **添加服务**：将代理服务添加到服务器。

7. **启动服务器**：`server.run_forever()` 启动服务器，并永久运行直到收到终止信号。

## 运行和测试

编译并运行程序：

```bash
RUST_LOG=info cargo run
```

你应该会看到类似以下的输出：

```log
[2023-xx-xx xx:xx:xx INFO  pingora_core::server] Process 12345 started
[2023-xx-xx xx:xx:xx INFO  simple_proxy] Simple reverse proxy running on 0.0.0.0:8080
```

现在，你可以使用浏览器或 curl 测试你的代理：

```bash
curl -v http://localhost:8080
```

所有发往 `localhost:8080` 的请求都将被代理到 `https://example.org`，你应该能看到 example.org 的页面内容。

## 扩展：代理到不同的上游服务器

上面的例子将所有请求都代理到 `example.org`。在实际应用中，你可能需要根据请求的特性（如 Host 头部、路径等）来选择不同的上游服务器。

这里是一个扩展示例，它根据请求的 Host 头部选择不同的上游服务器：

```rust
async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // 获取请求的 Host 头部
    let host = session.req_header().headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default");

    // 根据 Host 头部选择不同的上游服务器
    let (server, port, use_https) = match host {
        "api.example.com" => ("api.backend.com", 443, true),
        "static.example.com" => ("static.backend.com", 443, true),
        _ => ("default.backend.com", 443, true),
    };

    // 创建并返回 HttpPeer
    let peer = Box::new(HttpPeer::new(
        (server, port),
        use_https,
        server.to_string(),
    ));

    Ok(peer)
}
```

## 优化和下一步

这个最简单的反向代理示例只是一个起点。在实际应用中，你可能需要更多功能，例如：

1. **请求修改**：在转发请求前修改请求头部或主体
2. **响应修改**：在返回响应前修改响应头部或主体
3. **负载均衡**：在多个后端服务器之间分发请求
4. **缓存**：缓存响应以提高性能
5. **错误处理**：优雅地处理上游服务器错误
6. **监控和指标**：收集性能和使用指标

这些功能可以通过实现 `ProxyHttp` trait 的其他方法来添加，例如 `request_filter`、`response_filter`、`fail_to_connect` 等。

在后续章节中，我们将探讨如何添加这些高级功能，构建更强大、更灵活的代理服务。

## 总结

在本章中，我们构建了一个最简单的反向代理，它将所有请求转发到单个上游服务器。这个示例展示了 Pingora 应用的基本结构和工作流程，包括：

1. 定义代理服务结构体并实现 `ProxyHttp` trait
2. 配置和初始化服务器
3. 创建和配置代理服务
4. 启动和运行服务

这个简单的示例是理解 Pingora 如何工作的良好起点，也是构建更复杂代理服务的基础。通过扩展这个示例，你可以添加更多功能，满足特定的需求。
