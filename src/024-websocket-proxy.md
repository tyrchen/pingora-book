# 构建 WebSocket 代理

WebSocket 是一种在单个 TCP 连接上进行全双工通信的协议，它允许在客户端和服务器之间建立持久连接，并支持实时数据传输。WebSocket 在网页聊天、实时游戏、金融交易和监控应用等场景中非常有用。

本章将探讨如何使用 Pingora 实现一个 WebSocket 代理，将客户端的 WebSocket 连接转发到后端服务器。

## WebSocket 协议基础

在深入实现之前，让我们先简要了解 WebSocket 协议的基础知识：

1. **连接建立**：WebSocket 连接始于一个 HTTP 请求，使用特殊的头部进行升级（Upgrade: websocket）。
2. **帧格式**：建立连接后，数据以二进制帧形式传输，这些帧可以包含文本或二进制数据。
3. **控制帧**：协议定义了一些控制帧用于连接管理（如 Ping、Pong 和关闭帧）。
4. **全双工通信**：建立连接后，客户端和服务器可以随时发送消息，不需要等待响应。

## Pingora 中的 WebSocket 支持

Pingora 内置了 WebSocket 协议支持，允许我们轻松地构建 WebSocket 代理。主要功能包括：

1. 自动处理 WebSocket 握手和协议升级
2. 在代理层面透明地转发 WebSocket 帧
3. 支持 WebSocket 子协议和扩展协议

## 实现 WebSocket 代理

### 基本结构

让我们首先创建一个 WebSocket 代理的基本结构：

```rust
use async_trait::async_trait;
use pingora::prelude::*;
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;

pub struct WebSocketProxy;

#[async_trait]
impl ProxyHttp for WebSocketProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 选择上游 WebSocket 服务器
        let peer = Box::new(HttpPeer::new(
            ("ws-backend.example.com", 443),
            true,
            "ws-backend.example.com".to_string()
        ));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 设置转发到上游的请求头
        upstream_request.insert_header("Host", "ws-backend.example.com").unwrap();
        Ok(())
    }
}

fn main() {
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, WebSocketProxy);

    // 配置 HTTP 和 HTTPS 监听端口
    proxy_service.add_tcp("0.0.0.0:8080");

    // 假设我们有 TLS 证书和私钥
    let cert_path = "/path/to/cert.pem";
    let key_path = "/path/to/key.pem";
    proxy_service.add_tls("0.0.0.0:8443", cert_path, key_path);

    server.add_service(proxy_service);
    server.run_forever();
}
```

### WebSocket 请求检测

WebSocket 连接是通过 HTTP 升级请求发起的，所以我们可以在 `request_filter` 中检测并处理 WebSocket 请求：

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    // 获取请求头
    let req = session.req_header();

    // 判断是否为 WebSocket 升级请求
    let is_websocket = req.headers.get("upgrade")
        .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .unwrap_or(false);

    if is_websocket {
        // 可以在这里添加 WebSocket 特定的处理逻辑
        log::info!("WebSocket 升级请求: {}", req.uri);
    }

    Ok(false) // 继续常规代理流程
}
```

### 连接超时设置

WebSocket 连接通常是长期存在的，所以我们需要适当调整超时设置：

```rust
async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    let mut peer = Box::new(HttpPeer::new(
        ("ws-backend.example.com", 443),
        true,
        "ws-backend.example.com".to_string()
    ));

    // 设置更长的读写超时时间，适合 WebSocket 长连接
    peer.options.read_timeout = Some(std::time::Duration::from_secs(300)); // 5分钟
    peer.options.write_timeout = Some(std::time::Duration::from_secs(300));

    // 启用 TCP keepalive
    peer.options.keepalive_timeout = Some(std::time::Duration::from_secs(60));

    Ok(peer)
}
```

### WebSocket 子协议处理

WebSocket 可以使用子协议（subprotocol）来定义应用层协议。我们可以在代理中转发这些子协议信息：

```rust
async fn upstream_request_filter(
    &self,
    session: &mut Session,
    upstream_request: &mut pingora_http::RequestHeader,
    _ctx: &mut Self::CTX,
) -> Result<()> {
    // 设置必要的请求头
    upstream_request.insert_header("Host", "ws-backend.example.com").unwrap();

    // 确保 WebSocket 相关头部被正确转发
    if let Some(protocols) = session.req_header().headers.get("sec-websocket-protocol") {
        upstream_request.insert_header("Sec-WebSocket-Protocol", protocols).unwrap();
    }

    // 转发其他关键 WebSocket 头部
    for header_name in &["Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions"] {
        if let Some(value) = session.req_header().headers.get(*header_name) {
            upstream_request.insert_header(*header_name, value).unwrap();
        }
    }

    Ok(())
}
```

### 路径路由

如果我们需要根据路径将 WebSocket 请求路由到不同的后端，可以这样实现：

```rust
async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // 获取请求路径
    let path = session.req_header().uri.path();

    // 根据路径选择不同的上游服务器
    let (host, port) = match path {
        "/chat" => ("chat-ws.example.com", 443),
        "/game" => ("game-ws.example.com", 443),
        "/stream" => ("stream-ws.example.com", 443),
        _ => ("default-ws.example.com", 443),
    };

    let mut peer = Box::new(HttpPeer::new(
        (host, port),
        true,
        host.to_string()
    ));

    // 设置连接选项
    peer.options.read_timeout = Some(std::time::Duration::from_secs(300));
    peer.options.write_timeout = Some(std::time::Duration::from_secs(300));

    Ok(peer)
}
```

## WebSocket 连接保持与断线重连

WebSocket 连接可能由于各种原因断开，在代理中实现健壮的错误处理非常重要：

```rust
async fn fail_to_proxy(
    &self,
    session: &mut Session,
    error: &pingora_core::Error,
    _ctx: &mut Self::CTX,
) -> Result<Option<Response<Bytes>>> {
    // 记录 WebSocket 连接失败
    log::error!(
        "WebSocket 连接失败: {} - 错误类型: {}, 来源: {}",
        session.req_header().uri,
        error.etype().as_str(),
        error.esource().as_str()
    );

    // 返回适当的错误响应
    let body = Bytes::from("WebSocket 连接失败，请稍后重试");
    let resp = Response::builder()
        .status(502)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(body)
        .unwrap();

    Ok(Some(resp))
}
```

## 高级功能：WebSocket 消息处理

在某些场景下，可能需要检查或修改 WebSocket 消息内容。虽然 Pingora 的基本代理功能不直接支持这种操作，但我们可以通过一些技术来实现：

> 注意：以下示例仅用于演示，需要额外的依赖项并可能影响性能。在实际生产环境中需要谨慎使用。

```rust
// 这需要额外的处理逻辑，可能需要定制 Pingora
// 或使用专门的 WebSocket 库与 Pingora 结合

// 此类高级处理通常需要使用特定的 WebSocket 库
// 并可能需要自定义传输层逻辑
```

## 完整的 WebSocket 代理示例

下面是一个更完整的 WebSocket 代理实现，包含了我们讨论过的大部分功能：

```rust
use async_trait::async_trait;
use bytes::Bytes;
use http::Response;
use log::{info, error};
use pingora::prelude::*;
use pingora_core::Result;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use std::time::Duration;

pub struct WebSocketProxy;

#[async_trait]
impl ProxyHttp for WebSocketProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();

        // 判断是否为 WebSocket 升级请求
        let is_websocket = req.headers.get("upgrade")
            .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
            .unwrap_or(false);

        if is_websocket {
            info!("处理 WebSocket 升级请求: {}", req.uri);
        } else {
            // 如果这个代理仅用于 WebSocket，可以拒绝非 WebSocket 请求
            // 或者在这里为它们提供不同的处理逻辑
            info!("收到非 WebSocket 请求: {}", req.uri);
        }

        Ok(false) // 继续代理流程
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 获取请求路径
        let path = session.req_header().uri.path();

        // 根据路径选择不同的上游服务器
        let (host, port) = match path {
            "/chat" => ("chat.example.com", 443),
            "/stream" => ("stream.example.com", 443),
            _ => ("default.example.com", 443),
        };

        info!("WebSocket 连接路由到: {}:{}", host, port);

        let mut peer = Box::new(HttpPeer::new(
            (host, port),
            true,
            host.to_string()
        ));

        // 设置更长的超时时间，适合 WebSocket 长连接
        peer.options.read_timeout = Some(Duration::from_secs(300));
        peer.options.write_timeout = Some(Duration::from_secs(300));
        peer.options.keepalive_timeout = Some(Duration::from_secs(60));

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 获取目标主机
        let target_host = upstream_request.uri.host().unwrap_or("default.example.com");

        // 设置 Host 头部
        upstream_request.insert_header("Host", target_host).unwrap();

        // 转发 WebSocket 相关头部
        for header_name in &[
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Extensions",
            "Sec-WebSocket-Protocol"
        ] {
            if let Some(value) = session.req_header().headers.get(*header_name) {
                upstream_request.insert_header(*header_name, value).unwrap();
            }
        }

        // 确保必要的升级头部存在
        upstream_request.insert_header("Upgrade", "websocket").unwrap();
        upstream_request.insert_header("Connection", "Upgrade").unwrap();

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 验证上游服务器是否接受了 WebSocket 升级
        if upstream_response.status == 101 {
            info!("成功升级到 WebSocket 协议");
        } else {
            error!("WebSocket 升级失败，状态码: {}", upstream_response.status);
        }

        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &pingora_core::Error,
        _ctx: &mut Self::CTX,
    ) -> Result<Option<Response<Bytes>>> {
        error!(
            "WebSocket 代理失败: {} - 错误类型: {}, 来源: {}",
            session.req_header().uri,
            error.etype().as_str(),
            error.esource().as_str()
        );

        // 返回给客户端的错误响应
        let body = Bytes::from("WebSocket 连接失败，请稍后重试");
        let resp = Response::builder()
            .status(502)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(body)
            .unwrap();

        Ok(Some(resp))
    }

    async fn logging(&self, session: &mut Session, error: Option<&pingora_core::Error>, _ctx: &mut Self::CTX) {
        let req = session.req_header();
        let status = session.response_written().map_or(0, |resp| resp.status.as_u16());

        let is_websocket = req.headers.get("upgrade")
            .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
            .unwrap_or(false);

        if let Some(err) = error {
            error!(
                "WebSocket 请求: {} {} - 状态: {} - 错误: {} ({})",
                req.method, req.uri, status,
                err.etype().as_str(), err.esource().as_str()
            );
        } else if is_websocket && status == 101 {
            info!(
                "WebSocket 连接成功: {} {} - 状态: {}",
                req.method, req.uri, status
            );
        } else {
            info!(
                "请求: {} {} - 状态: {}",
                req.method, req.uri, status
            );
        }
    }
}

fn main() {
    // 初始化日志
    env_logger::init();

    // 创建服务器
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // 创建 WebSocket 代理服务
    let mut proxy_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        WebSocketProxy
    );

    // 配置监听端口
    proxy_service.add_tcp("0.0.0.0:8080");

    // 如果有 TLS 证书，也可以配置 HTTPS
    /*
    let cert_path = "/path/to/cert.pem";
    let key_path = "/path/to/key.pem";
    proxy_service.add_tls("0.0.0.0:8443", cert_path, key_path);
    */

    // 添加服务并启动
    server.add_service(proxy_service);
    server.run_forever();
}
```

## 生产环境考虑因素

在将 WebSocket 代理部署到生产环境时，需要考虑以下因素：

### 1. 连接限制

WebSocket 连接是长期存在的，需要注意系统连接数限制：

```rust
// 在 main 函数中设置系统限制
fn main() {
    // 设置文件描述符限制
    // 这应该在系统级别配置，例如在 /etc/security/limits.conf

    // Pingora 服务器配置
    let mut server = Server::new(None).unwrap();

    // 设置最大连接数
    server.configuration.listeners.max_connections = Some(50000);

    // ... 其余代码
}
```

### 2. 负载均衡

在多实例部署时，需要考虑 WebSocket 连接的粘性会话：

```
# 负载均衡器配置（如 Nginx）
upstream websocket_backend {
    # 使用 IP 哈希确保相同客户端连接到相同服务器
    ip_hash;
    server websocket1.example.com:8080;
    server websocket2.example.com:8080;
}
```

### 3. 监控与日志

WebSocket 连接的监控指标与常规 HTTP 不同，需要特别关注：

- 活跃连接数
- 连接持续时间
- WebSocket 消息吞吐量
- 异常断开次数

## 总结

通过 Pingora 实现 WebSocket 代理相对简单，主要依赖 Pingora 的 HTTP 升级机制自动处理 WebSocket 协议。在实现时需要注意：

1. 正确处理 WebSocket 的握手过程和头部转发
2. 为长连接调整适当的超时设置
3. 实现合理的错误处理和日志记录
4. 在生产环境中注意连接限制和系统资源管理

通过这种方式，我们可以构建高性能、可扩展的 WebSocket 代理，为实时应用提供可靠的服务。
