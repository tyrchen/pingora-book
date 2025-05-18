# 根据请求路径路由到不同上游服务

在上一章中，我们构建了一个简单的反向代理，它将所有请求转发到同一个上游服务器。然而，在真实世界的应用场景中，我们通常需要根据请求的特征（如路径、域名等）将请求路由到不同的后端服务。

本章将扩展前一章的例子，实现一个能够根据请求路径将流量路由到不同上游服务的反向代理。这种功能在微服务架构中尤为重要，可以让单个代理服务器作为网关，将请求分发到多个专门的后端服务。

## 路径路由的原理

路径路由的基本原理是检查请求的 URI 路径部分，然后根据预定义的规则决定将请求发送到哪个上游服务器。例如：

- `/api/*` 的请求路由到 API 服务器
- `/static/*` 的请求路由到静态资源服务器
- `/auth/*` 的请求路由到认证服务器
- 其他路径的请求路由到默认服务器

实现这种路由逻辑的关键是在 `ProxyHttp` trait 的 `upstream_peer` 方法中检查请求路径并作出决策。

## 项目设置

我们将基于上一章的代码进行扩展。首先，创建一个新的 Rust 项目：

```bash
cargo new path_routing_proxy
cd path_routing_proxy
```

然后在 `Cargo.toml` 文件中添加必要的依赖：

```toml
[package]
name = "path_routing_proxy"
version = "0.1.0"
edition = "2021"

[dependencies]
pingora = "0.3"
tokio = { version = "1", features = ["full"] }
env_logger = "0.10"
```

## 实现路径路由代理

下面是一个路径路由代理的实现，它将根据请求路径将请求路由到不同的上游服务器：

```rust
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;

// 定义一个路径路由代理服务结构体
struct PathRoutingProxy;

// 实现 ProxyHttp trait
#[async_trait]
impl ProxyHttp for PathRoutingProxy {
    // 定义请求上下文类型
    type CTX = ();

    // 创建新的上下文实例
    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    // 根据请求路径选择上游服务器
    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 获取请求路径
        let uri = session.req_header().uri();
        let path = uri.path();

        // 根据路径选择不同的上游服务器
        let (server, port, use_https, sni) = match path {
            p if p.starts_with("/api/") => {
                // API请求路由到API服务器
                ("api.example.com", 443, true, "api.example.com")
            }
            p if p.starts_with("/static/") => {
                // 静态资源请求路由到CDN
                ("static.example.com", 443, true, "static.example.com")
            }
            p if p.starts_with("/auth/") => {
                // 认证请求路由到认证服务器
                ("auth.example.com", 443, true, "auth.example.com")
            }
            _ => {
                // 默认路由到主网站
                ("www.example.com", 443, true, "www.example.com")
            }
        };

        // 创建并返回HttpPeer
        let peer = Box::new(HttpPeer::new(
            (server, port),
            use_https,
            sni.to_string(),
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
    let proxy = PathRoutingProxy;
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // 配置服务监听地址和端口
    proxy_service.add_tcp("0.0.0.0:8080");

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 启动服务器
    println!("Path routing proxy running on 0.0.0.0:8080");
    server.run_forever();

    Ok(())
}
```

## 代码详解

让我们详细解析这段代码：

### 1. 路径提取与匹配

核心功能位于 `upstream_peer` 方法中：

```rust
async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // 获取请求路径
    let uri = session.req_header().uri();
    let path = uri.path();

    // 根据路径选择不同的上游服务器
    let (server, port, use_https, sni) = match path {
        p if p.starts_with("/api/") => {
            // API请求路由到API服务器
            ("api.example.com", 443, true, "api.example.com")
        }
        // ... 其他路径匹配
    };

    // ...
}
```

这段代码通过以下步骤进行路径路由：

1. 从请求中提取 URI 并获取路径部分
2. 使用 Rust 的模式匹配（`match` 与 `if` 守卫）检查路径是否以特定前缀开始
3. 根据匹配结果选择相应的上游服务器配置，包括：
   - 服务器域名或 IP
   - 端口
   - 是否使用 HTTPS
   - SNI（Server Name Indication）主机名

### 2. 路由策略

这个例子使用了简单的前缀匹配策略，即检查路径是否以特定字符串开头。在实际应用中，你可以实现更复杂的路由策略，例如：

- **正则表达式匹配**：使用正则表达式匹配更复杂的路径模式
- **精确匹配**：要求路径完全匹配特定字符串
- **参数提取**：从路径中提取参数并用于路由决策
- **组合条件**：结合请求路径、HTTP 方法、查询参数等多种条件进行路由

## 进阶：路径重写

在路由请求到不同上游服务器时，我们可能还需要修改请求路径。例如，将 `/api/users` 转发到用户服务时，可能需要将路径改为 `/users`。

以下是一个包含路径重写功能的扩展示例：

```rust
async fn upstream_request_filter(
    &self,
    session: &mut Session,
    upstream_request: &mut RequestHeader,
    _ctx: &mut Self::CTX,
) -> Result<bool> {
    // 获取原始请求路径
    let original_path = session.req_header().uri().path();

    // 根据原始路径决定是否需要重写
    if original_path.starts_with("/api/") {
        // 移除 "/api" 前缀
        let new_path = original_path.replacen("/api", "", 1);

        // 创建带有新路径的URI
        let uri = upstream_request.uri_mut();
        let mut parts = uri.clone().into_parts();

        // 更新path_and_query部分
        if let Some(query) = uri.query() {
            parts.path_and_query = format!("{}?{}", new_path, query).parse().ok();
        } else {
            parts.path_and_query = new_path.parse().ok();
        }

        // 重新组装URI
        if let Ok(new_uri) = http::Uri::from_parts(parts) {
            *uri = new_uri;
        }
    }

    // 返回true表示继续处理请求
    Ok(true)
}
```

这个方法在请求被转发到上游之前被调用，它做了以下工作：

1. 检查原始请求路径是否以 `/api/` 开头
2. 如果是，则移除 `/api` 前缀，创建新的路径
3. 构建新的 URI，保留原始查询参数
4. 将新 URI 设置到上游请求中

这样，当客户端请求 `/api/users` 时，上游服务器将收到的请求路径为 `/users`。

## 基于域名的路由

除了基于路径的路由外，还可以基于请求的 Host 头部实现域名路由。这在需要处理多个域名指向同一代理服务器的情况下非常有用。

以下是一个结合路径和域名进行路由的示例：

```rust
async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // 获取Host头部
    let host = session.req_header().headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default");

    // 获取请求路径
    let path = session.req_header().uri().path();

    // 根据域名和路径组合路由
    let (server, port, use_https, sni) = match (host, path) {
        // api.example.com域名下的请求路由到API服务器
        ("api.example.com", _) => {
            ("api-backend.example.com", 443, true, "api-backend.example.com")
        },
        // www.example.com域名下的API路径路由到API服务器
        ("www.example.com", p) if p.starts_with("/api/") => {
            ("api-backend.example.com", 443, true, "api-backend.example.com")
        },
        // www.example.com域名下的静态资源路由到CDN
        ("www.example.com", p) if p.starts_with("/static/") => {
            ("static-cdn.example.com", 443, true, "static-cdn.example.com")
        },
        // 其他情况路由到默认服务器
        _ => {
            ("default-backend.example.com", 443, true, "default-backend.example.com")
        }
    };

    // 创建并返回HttpPeer
    let peer = Box::new(HttpPeer::new(
        (server, port),
        use_https,
        sni.to_string(),
    ));

    Ok(peer)
}
```

这个例子展示了如何结合请求的 Host 头部和路径进行更复杂的路由决策。

## 服务发现与动态路由

在本章中，我们使用了硬编码的上游服务器地址。在生产环境中，你可能需要从服务发现系统（如 Consul、Etcd 或 Kubernetes API）动态获取上游服务器地址。

实现动态路由的一般步骤是：

1. 在代理服务初始化时，从服务发现系统获取服务地址列表
2. 定期更新这些地址列表（例如，通过后台任务或订阅更新事件）
3. 在 `upstream_peer` 方法中使用最新的服务地址

下面是一个伪代码示例，展示了如何结合服务发现实现动态路由：

```rust
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// 定义上游服务的配置结构
struct UpstreamConfig {
    server: String,
    port: u16,
    use_https: bool,
}

// 定义路由代理服务结构体
struct DynamicRoutingProxy {
    // 使用RwLock包装的HashMap存储路由表
    routes: Arc<RwLock<HashMap<String, UpstreamConfig>>>,
}

impl DynamicRoutingProxy {
    // 创建新的代理实例
    fn new() -> Self {
        let routes = Arc::new(RwLock::new(HashMap::new()));

        // 初始化路由表
        Self::init_routes(Arc::clone(&routes));

        // 启动后台任务定期更新路由表
        Self::start_route_updater(Arc::clone(&routes));

        Self { routes }
    }

    // 初始化路由表
    fn init_routes(routes: Arc<RwLock<HashMap<String, UpstreamConfig>>>) {
        // 从服务发现系统获取初始路由配置
        let mut routes_map = routes.write().unwrap();

        // 添加初始路由
        routes_map.insert(
            "/api".to_string(),
            UpstreamConfig {
                server: "api.example.com".to_string(),
                port: 443,
                use_https: true,
            },
        );

        // 添加更多路由...
    }

    // 启动后台任务定期更新路由表
    fn start_route_updater(routes: Arc<RwLock<HashMap<String, UpstreamConfig>>>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

            loop {
                interval.tick().await;

                // 从服务发现系统获取最新路由配置
                // 更新routes_map...

                println!("Route table updated");
            }
        });
    }
}

#[async_trait]
impl ProxyHttp for DynamicRoutingProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 获取请求路径
        let path = session.req_header().uri().path();

        // 查找匹配的路由
        let mut matched_prefix = "";
        let mut config = None;

        // 读取路由表
        let routes = self.routes.read().unwrap();

        // 查找最长前缀匹配
        for (prefix, route_config) in routes.iter() {
            if path.starts_with(prefix) && prefix.len() > matched_prefix.len() {
                matched_prefix = prefix;
                config = Some(route_config);
            }
        }

        // 使用匹配的配置，或者默认配置
        let config = config.unwrap_or_else(|| {
            // 默认路由配置
            &UpstreamConfig {
                server: "default.example.com".to_string(),
                port: 443,
                use_https: true,
            }
        });

        // 创建HttpPeer
        let peer = Box::new(HttpPeer::new(
            (config.server.as_str(), config.port),
            config.use_https,
            config.server.clone(),
        ));

        Ok(peer)
    }
}
```

这个伪代码示例展示了如何使用共享的路由表和后台更新任务实现动态路由。在实际应用中，你需要根据具体的服务发现系统实现对应的更新逻辑。

## 日志记录和监控

在实现路由功能时，记录路由决策对于调试和监控非常重要。你可以通过实现 `logging` 方法来记录这些信息：

```rust
fn logging(&self, session: &Session, ctx: &Self::CTX) -> String {
    let uri = session.req_header().uri();
    let path = uri.path();
    let host = session.req_header().headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    // 获取已选择的上游服务器（如果有）
    let upstream = if let Some(peer) = session.upstream_info() {
        peer.addr().unwrap_or_else(|| "unknown".to_string())
    } else {
        "none".to_string()
    };

    // 返回日志字符串
    format!("host={} path={} routed_to={}", host, path, upstream)
}
```

这样，每个请求的路由决策都会被记录下来，有助于验证路由规则是否按预期工作。

## 完整示例

以下是一个更完整的路由代理示例，它结合了路径和域名路由，并包含路径重写功能：

```rust
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;

// 定义路由代理服务结构体
struct RoutingProxy;

#[async_trait]
impl ProxyHttp for RoutingProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 获取Host头部
        let host = session.req_header().headers.get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("default");

        // 获取请求路径
        let path = session.req_header().uri().path();

        // 根据域名和路径组合路由
        let (server, port, use_https, sni) = match (host, path) {
            // api子域名路由到API服务器
            (h, _) if h.starts_with("api.") => {
                ("api-backend.example.com", 443, true, "api-backend.example.com")
            },
            // 静态资源子域名路由到CDN
            (h, _) if h.starts_with("static.") => {
                ("static-cdn.example.com", 443, true, "static-cdn.example.com")
            },
            // 主域名下的API路径路由到API服务器
            (_, p) if p.starts_with("/api/") => {
                ("api-backend.example.com", 443, true, "api-backend.example.com")
            },
            // 主域名下的静态资源路径路由到CDN
            (_, p) if p.starts_with("/static/") || p.ends_with(".jpg") || p.ends_with(".png") => {
                ("static-cdn.example.com", 443, true, "static-cdn.example.com")
            },
            // 主域名下的认证路径路由到认证服务器
            (_, p) if p.starts_with("/auth/") || p.starts_with("/login") || p.starts_with("/register") => {
                ("auth.example.com", 443, true, "auth.example.com")
            },
            // 主域名下的管理路径路由到管理后台
            (_, p) if p.starts_with("/admin/") => {
                ("admin.example.com", 443, true, "admin.example.com")
            },
            // 其他情况路由到默认服务器
            _ => {
                ("www-backend.example.com", 443, true, "www-backend.example.com")
            }
        };

        // 创建HttpPeer
        let peer = Box::new(HttpPeer::new(
            (server, port),
            use_https,
            sni.to_string(),
        ));

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // 获取原始请求路径
        let original_path = session.req_header().uri().path();

        // 根据路径决定是否需要重写
        if original_path.starts_with("/api/") {
            // 移除 "/api" 前缀
            let new_path = original_path.replacen("/api", "", 1);

            // 重写URI
            let uri = upstream_request.uri_mut();
            let mut parts = uri.clone().into_parts();

            if let Some(query) = uri.query() {
                parts.path_and_query = format!("{}?{}", new_path, query).parse().ok();
            } else {
                parts.path_and_query = new_path.parse().ok();
            }

            if let Ok(new_uri) = http::Uri::from_parts(parts) {
                *uri = new_uri;
            }
        }

        // 添加X-Forwarded-Host和X-Forwarded-Proto头部
        let host = session.req_header().headers.get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");

        upstream_request.headers.insert(
            "X-Forwarded-Host",
            http::header::HeaderValue::from_str(host).unwrap_or_default(),
        );

        upstream_request.headers.insert(
            "X-Forwarded-Proto",
            http::header::HeaderValue::from_static("https"),
        );

        // 返回true表示继续处理请求
        Ok(true)
    }

    fn logging(&self, session: &Session, _ctx: &Self::CTX) -> String {
        let uri = session.req_header().uri();
        let path = uri.path();
        let host = session.req_header().headers.get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");

        // 获取已选择的上游服务器（如果有）
        let upstream = if let Some(peer) = session.upstream_info() {
            peer.addr().unwrap_or_else(|| "unknown".to_string())
        } else {
            "none".to_string()
        };

        // 返回日志字符串
        format!("host={} path={} routed_to={}", host, path, upstream)
    }
}

fn main() -> Result<()> {
    // 初始化日志系统
    env_logger::init();

    // 创建服务器实例
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务实例
    let proxy = RoutingProxy;
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // 配置服务监听地址和端口
    proxy_service.add_tcp("0.0.0.0:8080");

    // 可选：添加TLS支持
    // let cert_path = "path/to/cert.pem";
    // let key_path = "path/to/key.pem";
    // proxy_service.add_tls("0.0.0.0:8443", cert_path, key_path)?;

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 启动服务器
    println!("Advanced routing proxy running on 0.0.0.0:8080");
    server.run_forever();

    Ok(())
}
```

## 为路由规则添加测试

为了确保路由规则按预期工作，添加单元测试是一个好习惯。以下是一个简单的测试示例：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pingora::http::header::HeaderMap;
    use pingora::http::Uri;
    use pingora::protocols::http::v1::RequestHeader;

    // 辅助函数：创建测试会话
    fn create_test_session(path: &str, host: &str) -> Session {
        let mut req_header = RequestHeader::build(
            http::Method::GET,
            Uri::from_static(path),
            http::Version::HTTP_11,
        ).unwrap();

        req_header.headers.insert(
            "host",
            http::header::HeaderValue::from_str(host).unwrap()
        );

        Session::new_dummy(req_header)
    }

    #[tokio::test]
    async fn test_api_path_routing() {
        let proxy = RoutingProxy;
        let mut session = create_test_session("/api/users", "example.com");
        let mut ctx = proxy.new_ctx();

        let peer = proxy.upstream_peer(&mut session, &mut ctx).await.unwrap();
        assert_eq!(peer.host(), "api-backend.example.com");
    }

    #[tokio::test]
    async fn test_static_path_routing() {
        let proxy = RoutingProxy;
        let mut session = create_test_session("/static/styles.css", "example.com");
        let mut ctx = proxy.new_ctx();

        let peer = proxy.upstream_peer(&mut session, &mut ctx).await.unwrap();
        assert_eq!(peer.host(), "static-cdn.example.com");
    }

    #[tokio::test]
    async fn test_api_subdomain_routing() {
        let proxy = RoutingProxy;
        let mut session = create_test_session("/users", "api.example.com");
        let mut ctx = proxy.new_ctx();

        let peer = proxy.upstream_peer(&mut session, &mut ctx).await.unwrap();
        assert_eq!(peer.host(), "api-backend.example.com");
    }

    #[tokio::test]
    async fn test_default_routing() {
        let proxy = RoutingProxy;
        let mut session = create_test_session("/", "example.com");
        let mut ctx = proxy.new_ctx();

        let peer = proxy.upstream_peer(&mut session, &mut ctx).await.unwrap();
        assert_eq!(peer.host(), "www-backend.example.com");
    }
}
```

这些测试验证了不同的路由场景，确保路由规则按预期工作。

## 总结

在本章中，我们扩展了前一章的简单反向代理，实现了一个能够根据请求路径和域名将流量路由到不同上游服务的代理。我们讨论了以下关键点：

1. **基本路径路由**：根据请求的 URI 路径将请求路由到不同的上游服务器
2. **域名路由**：结合请求的 Host 头部实现基于域名的路由
3. **路径重写**：在转发请求之前修改请求路径
4. **动态路由**：使用服务发现系统实现动态更新的路由表
5. **日志记录**：记录路由决策以便调试和监控
6. **路由规则测试**：通过单元测试验证路由规则

路径路由是构建灵活的 API 网关和微服务代理的基本功能。通过本章学习的技术，你可以构建功能强大的反向代理，满足各种复杂的路由需求。

在下一章中，我们将探讨如何构建一个 API 网关，它将在路由功能的基础上添加认证、请求转换和 API 限流等高级功能。
