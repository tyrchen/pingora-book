# 构建 API 网关

在前两章中，我们实现了一个简单的反向代理，并扩展它使其能够根据请求路径路由到不同的上游服务。本章将更进一步，构建一个功能完整的 API 网关，它不仅可以路由请求，还可以实现认证、请求转换和 API 限流等高级功能。

API 网关是微服务架构中的重要组件，它作为客户端和后端服务之间的单一入口点，负责请求路由、认证授权、请求/响应转换、限流、监控等功能。使用 Pingora 构建 API 网关可以获得高性能、低延迟和可扩展性。

## API 网关的核心功能

一个完整的 API 网关通常包括以下核心功能：

1. **请求路由**：将请求转发到适当的微服务
2. **认证和授权**：验证请求者的身份和权限
3. **请求转换**：修改请求格式以适应后端服务的需求
4. **响应转换**：修改响应格式以适应客户端的需求
5. **限流和熔断**：控制请求速率，防止过载
6. **缓存**：缓存频繁请求的响应
7. **日志和监控**：记录请求信息，监控性能和错误

在本章中，我们将重点实现其中的认证、请求转换和限流功能。

## 项目设置

首先，创建一个新的 Rust 项目：

```bash
cargo new api_gateway
cd api_gateway
```

然后在 `Cargo.toml` 文件中添加必要的依赖：

```toml
[package]
name = "api_gateway"
version = "0.1.0"
edition = "2021"

[dependencies]
pingora = { version = "0.3", features = ["build-binary"] }
pingora-limits = "0.3"
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
env_logger = "0.10"
jsonwebtoken = "8.3"
async-trait = "0.1"
futures = "0.3"
http = "0.2"
chrono = "0.4"
```

## 实现 API 网关

我们将按照以下步骤构建 API 网关：

1. 实现 JWT 认证
2. 实现请求转换
3. 实现限流功能
4. 将这些功能集成到一个完整的 API 网关中

### 1. JWT 认证实现

JSON Web Token (JWT) 是一种开放标准，用于在网络应用环境间传递声明。我们将实现一个简单的 JWT 验证器，用于认证请求。

首先，创建一个 JWT 验证模块 `src/jwt.rs`：

```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, errors::Error as JwtError};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// JWT 声明结构
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,       // 主题（通常是用户ID）
    pub exp: u64,          // 过期时间
    pub iat: u64,          // 签发时间
    pub role: String,      // 用户角色
}

// JWT 验证器
pub struct JwtValidator {
    secret: String,
}

impl JwtValidator {
    // 创建新的验证器
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    // 验证 JWT
    pub fn validate(&self, token: &str) -> Result<Claims, JwtError> {
        // 设置验证参数
        let validation = Validation::new(Algorithm::HS256);

        // 解码并验证 token
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )?;

        // 检查是否过期
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        if token_data.claims.exp < now {
            return Err(JwtError::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature));
        }

        Ok(token_data.claims)
    }
}
```

### 2. 请求转换实现

请求转换的目的是修改请求格式以适应后端服务的需求。例如，添加或修改请求头、转换请求体格式等。

创建一个请求转换模块 `src/transformer.rs`：

```rust
use serde_json::{Value, json};
use std::collections::HashMap;

// 请求转换器
pub struct RequestTransformer {
    // 存储按路径的请求转换规则
    transformations: HashMap<String, Box<dyn Fn(Value) -> Value + Send + Sync>>,
}

impl RequestTransformer {
    // 创建新的转换器
    pub fn new() -> Self {
        let mut transformations = HashMap::new();

        // 注册默认转换规则
        Self::register_default_transformations(&mut transformations);

        Self { transformations }
    }

    // 注册默认转换规则
    fn register_default_transformations(
        transformations: &mut HashMap<String, Box<dyn Fn(Value) -> Value + Send + Sync>>
    ) {
        // 用户 API 转换：添加 user_type 字段
        transformations.insert(
            "/api/users".to_string(),
            Box::new(|mut value: Value| {
                if let Value::Object(obj) = &mut value {
                    obj.insert("user_type".to_string(), json!("standard"));
                }
                value
            }),
        );

        // 产品 API 转换：将价格从字符串转换为数字
        transformations.insert(
            "/api/products".to_string(),
            Box::new(|mut value: Value| {
                if let Value::Object(obj) = &mut value {
                    if let Some(Value::String(price_str)) = obj.get("price") {
                        if let Ok(price) = price_str.parse::<f64>() {
                            obj.insert("price".to_string(), json!(price));
                        }
                    }
                }
                value
            }),
        );
    }

    // 根据路径获取转换函数
    pub fn get_transformation(&self, path: &str) -> Option<&Box<dyn Fn(Value) -> Value + Send + Sync>> {
        // 查找最匹配的路径
        self.transformations.iter()
            .filter(|(k, _)| path.starts_with(k.as_str()))
            .max_by_key(|(k, _)| k.len())
            .map(|(_, transform)| transform)
    }

    // 转换请求体
    pub fn transform(&self, path: &str, body: Value) -> Value {
        if let Some(transform) = self.get_transformation(path) {
            transform(body)
        } else {
            // 如果没有匹配的转换规则，则返回原始请求体
            body
        }
    }
}
```

### 3. 限流功能实现

限流功能用于控制请求速率，防止系统过载。我们将使用 `pingora-limits` crate 实现两种限流策略：基于 IP 的限流和基于路径的限流。

创建一个限流模块 `src/rate_limiter.rs`：

```rust
use pingora_limits::{RateLimiter as PingoraRateLimiter, BucketCounter, TokenBucket};
use std::sync::Arc;
use std::time::Duration;
use std::net::IpAddr;
use std::collections::HashMap;
use tokio::sync::RwLock;

// 限流器
pub struct RateLimiter {
    // IP 基础限流器：每个 IP 的请求限制
    ip_limiter: PingoraRateLimiter<IpAddr>,

    // 路径基础限流器：特定路径的全局请求限制
    path_limiters: Arc<RwLock<HashMap<String, PingoraRateLimiter<()>>>>,
}

impl RateLimiter {
    // 创建新的限流器
    pub fn new() -> Self {
        // 创建 IP 限流器：每 IP 每秒 10 个请求
        let ip_limiter = PingoraRateLimiter::new(
            Box::new(move |_| Box::new(TokenBucket::new(10, 10, Duration::from_secs(1)))),
        );

        Self {
            ip_limiter,
            path_limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // 注册路径限流器
    pub async fn register_path_limiter(&self, path: &str, rate: u32, capacity: u32) {
        let mut path_limiters = self.path_limiters.write().await;

        // 创建特定路径的限流器
        let limiter = PingoraRateLimiter::new(
            Box::new(move |_| {
                Box::new(TokenBucket::new(
                    rate,
                    capacity,
                    Duration::from_secs(1),
                ))
            }),
        );

        path_limiters.insert(path.to_string(), limiter);
    }

    // 检查 IP 是否超过限制
    pub fn check_ip(&self, ip: IpAddr) -> bool {
        self.ip_limiter.check(&ip)
    }

    // 检查路径是否超过限制
    pub async fn check_path(&self, path: &str) -> bool {
        let path_limiters = self.path_limiters.read().await;

        // 查找最匹配的路径限流器
        for (prefix, limiter) in path_limiters.iter() {
            if path.starts_with(prefix) {
                return limiter.check(&());
            }
        }

        // 如果没有匹配的限流器，则允许请求
        true
    }
}
```

### 4. 集成到完整的 API 网关

现在，我们将上述组件集成到一个完整的 API 网关中。

首先，创建主模块 `src/main.rs`：

```rust
mod jwt;
mod transformer;
mod rate_limiter;

use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use pingora::upstreams::peer::HttpPeer;
use pingora::protocols::http::RequestHeader;
use jwt::JwtValidator;
use transformer::RequestTransformer;
use rate_limiter::RateLimiter;
use serde_json::Value;
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::sync::Mutex;
use futures::future::BoxFuture;
use http::StatusCode;

// 请求上下文
struct ApiGatewayContext {
    // 存储解析后的 JWT 声明
    claims: Option<jwt::Claims>,

    // 缓存已解析的请求体
    request_body: Arc<Mutex<Option<Value>>>,
}

// API 网关服务
struct ApiGateway {
    jwt_validator: Arc<JwtValidator>,
    request_transformer: Arc<RequestTransformer>,
    rate_limiter: Arc<RateLimiter>,
}

impl ApiGateway {
    // 创建新的 API 网关
    fn new() -> Self {
        // 创建 JWT 验证器
        let jwt_validator = Arc::new(JwtValidator::new("your_jwt_secret".to_string()));

        // 创建请求转换器
        let request_transformer = Arc::new(RequestTransformer::new());

        // 创建限流器
        let rate_limiter = Arc::new(RateLimiter::new());

        Self {
            jwt_validator,
            request_transformer,
            rate_limiter,
        }
    }

    // 初始化限流器
    async fn init_rate_limiters(&self) {
        // 为不同路径注册限流规则
        self.rate_limiter.register_path_limiter("/api/users", 20, 20).await;
        self.rate_limiter.register_path_limiter("/api/products", 30, 30).await;
        self.rate_limiter.register_path_limiter("/api/orders", 10, 10).await;
    }

    // 从请求头中提取 JWT token
    fn extract_token(&self, req_header: &RequestHeader) -> Option<String> {
        let auth_header = req_header.headers.get("authorization")?;
        let auth_str = auth_header.to_str().ok()?;

        if auth_str.starts_with("Bearer ") {
            Some(auth_str[7..].to_string())
        } else {
            None
        }
    }

    // 从请求头中提取客户端 IP
    fn extract_client_ip(&self, req_header: &RequestHeader) -> Option<IpAddr> {
        // 尝试从 X-Forwarded-For 头中获取
        if let Some(forwarded_for) = req_header.headers.get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded_for.to_str() {
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    if let Ok(ip) = IpAddr::from_str(first_ip.trim()) {
                        return Some(ip);
                    }
                }
            }
        }

        // 尝试从 X-Real-IP 头中获取
        if let Some(real_ip) = req_header.headers.get("x-real-ip") {
            if let Ok(ip_str) = real_ip.to_str() {
                if let Ok(ip) = IpAddr::from_str(ip_str.trim()) {
                    return Some(ip);
                }
            }
        }

        // 如果都没有，返回 None
        None
    }
}

#[async_trait]
impl ProxyHttp for ApiGateway {
    type CTX = ApiGatewayContext;

    // 创建新的上下文
    fn new_ctx(&self) -> Self::CTX {
        ApiGatewayContext {
            claims: None,
            request_body: Arc::new(Mutex::new(None)),
        }
    }

    // 请求过滤：验证 JWT 和限流
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req_header = session.req_header();
        let path = req_header.uri().path();

        // 不需要认证的公共路径
        let public_paths = ["/api/public", "/api/login", "/api/register"];
        let is_public_path = public_paths.iter().any(|p| path.starts_with(p));

        // 如果不是公共路径，验证 JWT
        if !is_public_path {
            if let Some(token) = self.extract_token(req_header) {
                match self.jwt_validator.validate(&token) {
                    Ok(claims) => {
                        // 存储解析后的声明到上下文
                        ctx.claims = Some(claims);
                    },
                    Err(_) => {
                        // JWT 验证失败，返回 401 Unauthorized
                        session.respond_error(StatusCode::UNAUTHORIZED)?;
                        return Ok(false);
                    }
                }
            } else {
                // 没有提供 token，返回 401 Unauthorized
                session.respond_error(StatusCode::UNAUTHORIZED)?;
                return Ok(false);
            }
        }

        // 执行限流检查
        if let Some(client_ip) = self.extract_client_ip(req_header) {
            // 检查 IP 限流
            if !self.rate_limiter.check_ip(client_ip) {
                // IP 超过限制，返回 429 Too Many Requests
                session.respond_error(StatusCode::TOO_MANY_REQUESTS)?;
                return Ok(false);
            }
        }

        // 检查路径限流
        if !self.rate_limiter.check_path(path).await {
            // 路径超过限制，返回 429 Too Many Requests
            session.respond_error(StatusCode::TOO_MANY_REQUESTS)?;
            return Ok(false);
        }

        // 验证和限流通过，继续处理请求
        Ok(true)
    }

    // 请求体处理：解析和转换 JSON
    async fn request_body_filter<'a>(
        &'a self,
        session: &'a mut Session,
        body: &'a [u8],
        _end_of_stream: bool,
        ctx: &'a mut Self::CTX,
    ) -> Result<(BoxFuture<'a, Result<Vec<u8>>>, bool)> {
        // 只处理 JSON 请求
        let content_type = session.req_header().headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        if !content_type.contains("application/json") {
            // 不是 JSON 请求，直接传递原始请求体
            return Ok((
                Box::pin(async move { Ok(body.to_vec()) }),
                true,
            ));
        }

        let body_vec = body.to_vec();
        let path = session.req_header().uri().path().to_string();
        let request_transformer = self.request_transformer.clone();
        let request_body = ctx.request_body.clone();

        // 返回一个异步闭包，处理请求体
        Ok((
            Box::pin(async move {
                // 尝试解析 JSON
                if let Ok(mut value) = serde_json::from_slice::<Value>(&body_vec) {
                    // 应用转换
                    value = request_transformer.transform(&path, value);

                    // 缓存转换后的请求体
                    {
                        let mut body_guard = request_body.lock().await;
                        *body_guard = Some(value.clone());
                    }

                    // 序列化回 JSON
                    Ok(serde_json::to_vec(&value)?)
                } else {
                    // 解析失败，使用原始请求体
                    Ok(body_vec)
                }
            }),
            true,
        ))
    }

    // 选择上游服务器
    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 获取请求路径
        let path = session.req_header().uri().path();

        // 根据路径选择上游服务器
        let (server, port, use_https, sni) = match path {
            p if p.starts_with("/api/users") => {
                ("user-service.example.com", 443, true, "user-service.example.com")
            }
            p if p.starts_with("/api/products") => {
                ("product-service.example.com", 443, true, "product-service.example.com")
            }
            p if p.starts_with("/api/orders") => {
                ("order-service.example.com", 443, true, "order-service.example.com")
            }
            _ => {
                ("default-service.example.com", 443, true, "default-service.example.com")
            }
        };

        // 创建并返回 HttpPeer
        let peer = Box::new(HttpPeer::new(
            (server, port),
            use_https,
            sni.to_string(),
        ));

        Ok(peer)
    }

    // 修改上游请求：添加额外的头部
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // 添加 X-User-ID 和 X-User-Role 头部（如果有 JWT 声明）
        if let Some(claims) = &ctx.claims {
            upstream_request.headers.insert(
                "X-User-ID",
                http::header::HeaderValue::from_str(&claims.sub)?,
            );

            upstream_request.headers.insert(
                "X-User-Role",
                http::header::HeaderValue::from_str(&claims.role)?,
            );
        }

        // 添加 X-Gateway-Version 头部
        upstream_request.headers.insert(
            "X-Gateway-Version",
            http::header::HeaderValue::from_static("1.0"),
        );

        Ok(true)
    }

    // 日志记录
    fn logging(&self, session: &Session, ctx: &Self::CTX) -> String {
        let uri = session.req_header().uri();
        let path = uri.path();
        let method = session.req_header().method();

        // 获取响应状态（如果有）
        let status = session.resp_header()
            .map(|h| h.status.as_u16())
            .unwrap_or(0);

        // 获取用户 ID（如果有）
        let user_id = ctx.claims.as_ref()
            .map(|c| c.sub.clone())
            .unwrap_or_else(|| "anonymous".to_string());

        // 获取已选择的上游服务器（如果有）
        let upstream = if let Some(peer) = session.upstream_info() {
            peer.addr().unwrap_or_else(|| "unknown".to_string())
        } else {
            "none".to_string()
        };

        // 返回日志字符串
        format!(
            "method={} path={} status={} user_id={} upstream={}",
            method, path, status, user_id, upstream
        )
    }

    // 处理请求失败
    async fn fail_to_proxy(&self, session: &mut Session, _ctx: &mut Self::CTX, error: pingora::Error) -> Result<()> {
        // 根据错误类型定制错误响应
        let status_code = match error {
            pingora::Error::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            pingora::Error::ConnectingUpstream(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // 创建 JSON 错误响应
        let error_message = match status_code {
            StatusCode::GATEWAY_TIMEOUT => "请求上游服务超时",
            StatusCode::BAD_GATEWAY => "无法连接到上游服务",
            _ => "处理请求时发生内部错误",
        };

        let error_json = serde_json::json!({
            "error": {
                "code": status_code.as_u16(),
                "message": error_message
            }
        });

        let error_body = serde_json::to_string(&error_json)?;

        // 设置响应
        let mut resp = http::Response::builder()
            .status(status_code)
            .header("Content-Type", "application/json")
            .header("Content-Length", error_body.len().to_string())
            .body(())?;

        // 发送响应
        session.respond(&resp, Some(error_body.as_bytes()))?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    env_logger::init();

    // 创建服务器实例
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建 API 网关实例
    let api_gateway = ApiGateway::new();

    // 初始化限流器
    api_gateway.init_rate_limiters().await;

    // 创建代理服务实例
    let mut gateway_service = http_proxy_service(&server.configuration, api_gateway);

    // 配置服务监听地址和端口
    gateway_service.add_tcp("0.0.0.0:8080");

    // 添加服务到服务器
    server.add_service(gateway_service);

    // 启动服务器
    println!("API Gateway running on 0.0.0.0:8080");
    server.run_forever();

    Ok(())
}
```

## 测试 API 网关

要测试我们实现的 API 网关，可以使用 curl 或任何 HTTP 客户端发送请求。以下是一些测试示例：

### 1. 未认证请求

```bash
curl -i http://localhost:8080/api/users
```

这应该返回 401 Unauthorized 错误，因为我们没有提供 JWT token。

### 2. 包含 JWT 的认证请求

```bash
curl -i -H "Authorization: Bearer your_jwt_token" http://localhost:8080/api/users
```

如果 JWT 有效，请求应该被正确路由到用户服务。

### 3. JSON 转换请求

```bash
curl -i -X POST -H "Content-Type: application/json" -H "Authorization: Bearer your_jwt_token" -d '{"name":"John","email":"john@example.com"}' http://localhost:8080/api/users
```

这个请求中的 JSON 应该被我们的转换器处理，添加 `user_type` 字段后再转发到上游服务。

### 4. 限流测试

通过快速发送多个请求，可以测试限流功能：

```bash
for i in {1..20}; do
  curl -i http://localhost:8080/api/public/health
  sleep 0.1
done
```

如果发送请求太快，应该在某个点开始收到 429 Too Many Requests 错误。

## 扩展与改进

我们的 API 网关实现了基本功能，但还有许多方面可以改进和扩展：

1. **缓存集成**：使用 Pingora 的缓存功能缓存特定路径的响应
2. **更灵活的路由**：实现更复杂的路由规则，支持正则表达式匹配
3. **请求合并**：将多个后端请求合并为一个客户端响应
4. **熔断器**：检测上游服务故障并快速失败，防止级联故障
5. **指标收集**：添加 Prometheus 指标收集功能，监控网关性能
6. **插件系统**：设计一个插件系统，使功能模块化和可扩展
7. **WebSocket 支持**：添加对 WebSocket 连接的支持

## 总结

在本章中，我们构建了一个功能完整的 API 网关，它结合了 Pingora 的核心功能与一些常见的 API 网关需求。我们实现了：

1. **JWT 认证**：验证请求者的身份
2. **请求转换**：根据路径转换 JSON 请求体
3. **限流**：基于 IP 和路径的请求限制
4. **路由**：根据路径将请求路由到不同的上游服务
5. **错误处理**：提供友好的错误响应
6. **日志记录**：记录请求处理详情

通过这些功能，我们的 API 网关可以作为微服务架构中的单一入口点，处理身份验证、格式转换和流量控制等关键功能。

在实际应用中，你可能需要进一步定制和扩展这个网关，以满足特定的业务需求。例如，添加细粒度的授权控制、集成特定的服务发现机制、实现特定业务逻辑的转换规则等。
