# 请求过滤与处理

在 Pingora 代理的请求处理流程中，`request_filter()` 方法是第一个能够对请求进行检查和决策的重要环节。本章将详细介绍如何在 `request_filter()` 方法中检查传入请求的头部信息并做出决策，以及如何直接响应客户端而不转发请求到上游服务器。

## request_filter 方法的作用

`request_filter()` 是 `ProxyHttp` trait 中定义的一个重要回调方法，它在请求处理的早期阶段被调用。当 Pingora 收到一个客户端请求并解析完成请求头后，将调用此方法允许你对请求进行检查和处理。

此方法的主要作用包括：

1. 检查请求的合法性和安全性
2. 根据请求特征进行分类和标记
3. 执行访问控制（如 IP 黑名单、认证验证）
4. 实现速率限制
5. 提前拒绝不合规请求，返回错误响应
6. 为特定请求提供本地响应，无需转发到上游

方法签名如下：

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
where
    Self::CTX: Send + Sync;
```

该方法返回 `Result<bool>`，其中：

- 返回 `Ok(true)` 表示已经向客户端发送了响应，Pingora 将不再继续处理此请求
- 返回 `Ok(false)` 表示继续正常代理流程
- 返回 `Err(...)` 表示发生错误，Pingora 将向客户端返回 500 错误响应

## 检查请求头部信息

### 访问请求头部

在 `request_filter()` 方法中，可以通过 `session.req_header()` 获取请求头：

```rust
fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    // 获取请求头
    let req = session.req_header();

    // 获取请求方法
    let method = req.method();

    // 获取请求路径
    let path = req.uri().path();

    // 获取特定请求头
    if let Some(user_agent) = req.headers().get("user-agent") {
        // 将头部值转换为字符串
        let ua_str = user_agent.to_str().unwrap_or_default();
        println!("User-Agent: {}", ua_str);
    }

    // 检查是否存在特定头部
    let has_auth = req.headers().contains_key("authorization");

    Ok(false) // 继续正常代理流程
}
```

### 常见的请求头检查场景

#### 检查 User-Agent

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    let req = session.req_header();

    if let Some(user_agent) = req.headers().get("user-agent") {
        let ua_str = user_agent.to_str().unwrap_or_default();

        // 阻止特定的爬虫
        if ua_str.contains("BadBot") || ua_str.contains("ScraperBot") {
            // 标记请求来源为爬虫
            ctx.client_type = Some("blocked_bot".to_string());

            // 返回 403 禁止访问
            session.respond_error(403).await?;
            return Ok(true); // 已发送响应，不再继续处理
        }

        // 记录客户端类型
        if ua_str.contains("Mozilla") {
            ctx.client_type = Some("browser".to_string());
        } else if ua_str.contains("bot") || ua_str.contains("Bot") {
            ctx.client_type = Some("allowed_bot".to_string());
        } else {
            ctx.client_type = Some("other".to_string());
        }
    }

    Ok(false) // 继续正常流程
}
```

#### 验证 Authorization 头部

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    let req = session.req_header();
    let path = req.uri().path();

    // 检查是否需要认证的路径
    if path.starts_with("/api/private") || path.starts_with("/admin") {
        // 检查是否有 Authorization 头部
        if let Some(auth) = req.headers().get("authorization") {
            let auth_str = auth.to_str().unwrap_or_default();

            // 检查 Bearer token
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..]; // 跳过 "Bearer " 前缀

                // 在实际应用中会调用更复杂的 token 验证逻辑
                if !self.validate_token(token) {
                    // Token 无效，返回 401 未授权
                    session.respond_error(401).await?;
                    return Ok(true);
                }

                // Token 有效，记录用户信息
                ctx.user_id = self.extract_user_id(token);
            } else {
                // 格式不正确，返回 401
                session.respond_error(401).await?;
                return Ok(true);
            }
        } else {
            // 没有 Authorization 头部，返回 401
            session.respond_error(401).await?;
            return Ok(true);
        }
    }

    Ok(false)
}

// 在实际应用中会实现这些方法
fn validate_token(&self, token: &str) -> bool {
    // 实际应用中的 token 验证逻辑
    token.len() > 10 // 仅示例，不应在生产中使用
}

fn extract_user_id(&self, token: &str) -> Option<String> {
    // 从 token 中提取用户 ID
    Some("user123".to_string()) // 仅示例
}
```

#### 检查 IP 地址

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    // 获取客户端 IP 地址
    if let Some(client_addr) = session.peer_addr() {
        let ip = client_addr.ip();

        // 检查 IP 是否在黑名单中
        if self.is_ip_blocked(&ip) {
            session.respond_error(403).await?;
            return Ok(true);
        }

        // 记录 IP 地址
        ctx.client_ip = Some(ip);
    }

    Ok(false)
}

fn is_ip_blocked(&self, ip: &std::net::IpAddr) -> bool {
    // 实际应用中的 IP 黑名单检查逻辑
    false // 仅示例
}
```

#### 基于路径的过滤

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    let req = session.req_header();
    let path = req.uri().path();

    // 阻止对某些路径的访问
    if path.contains("/.git/") || path.ends_with("/wp-config.php") {
        session.respond_error(404).await?;
        return Ok(true);
    }

    // 根据路径分类请求
    if path.starts_with("/api/") {
        ctx.request_type = Some("api".to_string());
    } else if path.starts_with("/static/") {
        ctx.request_type = Some("static".to_string());
    } else {
        ctx.request_type = Some("page".to_string());
    }

    Ok(false)
}
```

## 直接响应客户端

当在 `request_filter()` 中检测到特定条件，你可能想直接向客户端返回响应，而不是将请求转发给上游服务器。Pingora 提供了几种方法来实现这一点。

### 返回标准错误响应

最简单的方式是使用 `Session` 提供的 `respond_error()` 方法，它接受一个 HTTP 状态码作为参数，并向客户端发送标准错误响应：

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    // 某些条件检查...
    if request_is_invalid {
        // 返回 400 Bad Request
        session.respond_error(400).await?;
        return Ok(true); // 告诉 Pingora 已发送响应
    }

    // 检查访问权限
    if !has_permission {
        // 返回 403 Forbidden
        session.respond_error(403).await?;
        return Ok(true);
    }

    Ok(false) // 继续正常处理
}
```

### 返回自定义错误响应体

如果需要自定义错误响应体，可以使用 `respond_error_with_body()` 方法：

```rust
use bytes::Bytes;

async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    if !has_permission {
        // 创建 JSON 格式的错误响应
        let error_json = r#"{"error": "Access denied", "code": "FORBIDDEN"}"#;
        let body = Bytes::from(error_json);

        // 返回 403 Forbidden 和自定义响应体
        session.respond_error_with_body(403, body).await?;
        return Ok(true);
    }

    Ok(false)
}
```

### 返回完全自定义响应

对于更复杂的场景，可能需要完全自定义响应，包括状态码、头部和响应体：

```rust
use http::{StatusCode, header};
use pingora_http::ResponseHeader;

async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    let req = session.req_header();

    // 检查是否健康检查请求
    if req.uri().path() == "/health" {
        // 创建自定义响应头
        let mut resp = ResponseHeader::build(StatusCode::OK, None)?;

        // 添加响应头
        resp.insert_header(header::CONTENT_TYPE, "application/json")?;
        resp.insert_header(header::CACHE_CONTROL, "no-cache")?;

        // JSON 响应体
        let body = Bytes::from(r#"{"status":"healthy","version":"1.0.0"}"#);

        // 写入响应头和响应体
        session.write_response_header(Box::new(resp)).await?;
        session.write_response_body(body, true).await?;

        return Ok(true); // 告诉 Pingora 已发送响应
    }

    // 检查是否重定向请求
    if should_redirect(req) {
        let new_location = get_redirect_url(req);

        // 创建 302 重定向响应
        let mut resp = ResponseHeader::build(StatusCode::FOUND, None)?;
        resp.insert_header(header::LOCATION, new_location)?;

        // 写入响应头，无响应体
        session.write_response_header(Box::new(resp)).await?;
        session.write_response_body(Bytes::new(), true).await?;

        return Ok(true);
    }

    Ok(false)
}

fn should_redirect(req: &RequestHeader) -> bool {
    // 重定向逻辑
    false // 仅示例
}

fn get_redirect_url(req: &RequestHeader) -> &'static str {
    // 生成重定向 URL
    "https://example.com/new-location"
}
```

### 返回本地缓存的响应

你可能想要实现一个简单的本地内存缓存，用于快速响应某些请求，而不是每次都转发到上游：

```rust
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// 在代理结构中定义一个简单的缓存
struct SimpleProxy {
    local_cache: Arc<Mutex<HashMap<String, (Bytes, Instant)>>>,
    cache_ttl: Duration,
}

impl SimpleProxy {
    fn new(cache_ttl_secs: u64) -> Self {
        Self {
            local_cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
        }
    }

    fn get_cache_key(&self, req: &RequestHeader) -> String {
        // 简单地使用路径作为缓存键
        req.uri().path().to_string()
    }
}

impl ProxyHttp for SimpleProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();

        // 只对 GET 请求使用缓存
        if req.method() != http::Method::GET {
            return Ok(false);
        }

        let cache_key = self.get_cache_key(req);

        // 尝试从缓存获取响应
        if let Some((cached_body, timestamp)) = self.local_cache.lock().unwrap().get(&cache_key) {
            // 检查缓存是否过期
            if timestamp.elapsed() < self.cache_ttl {
                // 缓存未过期，直接返回
                let mut resp = ResponseHeader::build(StatusCode::OK, None)?;
                resp.insert_header(header::CONTENT_TYPE, "application/json")?;
                resp.insert_header(header::CACHE_CONTROL, "max-age=60")?;

                // 增加自定义头表明这是缓存命中
                resp.insert_header("x-cache", "HIT")?;

                // 写入响应
                session.write_response_header(Box::new(resp)).await?;
                session.write_response_body(cached_body.clone(), true).await?;

                return Ok(true);
            }
        }

        // 缓存未命中或已过期，继续正常代理逻辑
        Ok(false)
    }

    // 在其他方法中可以更新缓存...
    async fn response_filter(&self, session: &mut Session, resp: &mut ResponseHeader, _ctx: &mut Self::CTX) -> Result<()> {
        // 只缓存成功的 JSON 响应
        if resp.status == StatusCode::OK {
            if let Some(content_type) = resp.headers().get(header::CONTENT_TYPE) {
                if let Ok(content_type_str) = content_type.to_str() {
                    if content_type_str.contains("application/json") {
                        // 这里仅为示例，实际应用可能需要收集完整的响应体
                        // 并在 response_body_filter 中处理
                        let req = session.req_header();
                        let cache_key = self.get_cache_key(req);

                        // 实际应用中这里会缓存完整的响应体
                        // 这里仅是示例，实际实现会更复杂
                        let body = Bytes::from("cached response");
                        self.local_cache.lock().unwrap().insert(cache_key, (body, Instant::now()));
                    }
                }
            }
        }

        Ok(())
    }

    // 实现其他必要的方法...
}
```

## 实际使用示例

### 基于 IP 和请求率的访问控制

以下是一个综合示例，实现了基于 IP 的访问控制和简单的请求速率限制：

```rust
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

// 请求上下文
struct FilterContext {
    client_ip: Option<IpAddr>,
    start_time: Instant,
    is_throttled: bool,
}

impl FilterContext {
    fn new() -> Self {
        Self {
            client_ip: None,
            start_time: Instant::now(),
            is_throttled: false,
        }
    }
}

// 代理服务
struct SecurityProxy {
    ip_blacklist: Vec<IpAddr>,
    rate_limits: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_requests: usize,
    window_size: Duration,
}

impl SecurityProxy {
    fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            ip_blacklist: Vec::new(),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_size: Duration::from_secs(window_secs),
        }
    }

    fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.ip_blacklist.contains(ip)
    }

    fn is_rate_limited(&self, ip: &IpAddr) -> bool {
        let mut rate_limits = self.rate_limits.lock().unwrap();

        // 获取此 IP 的请求历史
        let request_times = rate_limits.entry(*ip).or_insert_with(Vec::new);

        // 清理过期的请求记录
        let now = Instant::now();
        let cutoff = now - self.window_size;
        request_times.retain(|&time| time > cutoff);

        // 检查是否超过速率限制
        if request_times.len() >= self.max_requests {
            return true;
        }

        // 记录新请求
        request_times.push(now);
        false
    }
}

impl ProxyHttp for SecurityProxy {
    type CTX = FilterContext;

    fn new_ctx(&self) -> Self::CTX {
        FilterContext::new()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // 获取客户端 IP
        if let Some(client_addr) = session.peer_addr() {
            let ip = client_addr.ip();
            ctx.client_ip = Some(ip);

            // 检查 IP 黑名单
            if self.is_ip_blocked(&ip) {
                // 返回 403 禁止访问
                session.respond_error(403).await?;
                return Ok(true);
            }

            // 检查速率限制
            if self.is_rate_limited(&ip) {
                ctx.is_throttled = true;

                // 创建 429 Too Many Requests 响应
                let mut resp = ResponseHeader::build(StatusCode::TOO_MANY_REQUESTS, None)?;
                resp.insert_header(header::RETRY_AFTER, "10")?;

                let body = Bytes::from("Rate limit exceeded. Please try again later.");

                // 发送响应
                session.write_response_header(Box::new(resp)).await?;
                session.write_response_body(body, true).await?;

                return Ok(true);
            }
        }

        // 继续正常代理流程
        Ok(false)
    }

    // 实现其他必要的方法...
}
```

### 高级访问控制和认证

下面是一个更复杂的示例，实现了 JWT 认证和基于角色的访问控制：

```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// JWT 声明结构
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // 用户 ID
    role: String, // 用户角色
    exp: usize, // 过期时间
}

// 请求上下文
struct AuthContext {
    user_id: Option<String>,
    user_role: Option<String>,
    authenticated: bool,
    auth_error: Option<String>,
}

impl AuthContext {
    fn new() -> Self {
        Self {
            user_id: None,
            user_role: None,
            authenticated: false,
            auth_error: None,
        }
    }
}

// 代理服务
struct AuthProxy {
    jwt_secret: String,
    path_permissions: HashMap<String, Vec<String>>, // 路径 -> 允许的角色列表
}

impl AuthProxy {
    fn new(jwt_secret: String) -> Self {
        let mut path_permissions = HashMap::new();

        // 设置路径权限
        path_permissions.insert("/api/admin".to_string(), vec!["admin".to_string()]);
        path_permissions.insert("/api/users".to_string(), vec!["admin".to_string(), "user".to_string()]);

        Self {
            jwt_secret,
            path_permissions,
        }
    }

    fn validate_jwt(&self, token: &str, ctx: &mut AuthContext) -> bool {
        let validation = Validation::new(Algorithm::HS256);

        // 解码和验证 JWT
        match decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        ) {
            Ok(token_data) => {
                // 设置用户信息
                ctx.user_id = Some(token_data.claims.sub);
                ctx.user_role = Some(token_data.claims.role);
                ctx.authenticated = true;
                true
            }
            Err(e) => {
                ctx.auth_error = Some(format!("Invalid token: {}", e));
                false
            }
        }
    }

    fn check_path_permission(&self, path: &str, role: &str) -> bool {
        // 检查路径是否需要特定角色
        for (protected_path, allowed_roles) in &self.path_permissions {
            if path.starts_with(protected_path) {
                return allowed_roles.contains(&role.to_string());
            }
        }

        // 默认允许访问未指定权限的路径
        true
    }
}

impl ProxyHttp for AuthProxy {
    type CTX = AuthContext;

    fn new_ctx(&self) -> Self::CTX {
        AuthContext::new()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        let path = req.uri().path();

        // 判断路径是否需要保护
        let needs_auth = self.path_permissions.keys().any(|p| path.starts_with(p));

        if needs_auth {
            // 检查 Authorization 头部
            if let Some(auth_header) = req.headers().get("authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = &auth_str[7..]; // 跳过 "Bearer " 前缀

                        // 验证 JWT
                        if self.validate_jwt(token, ctx) {
                            // JWT 有效，检查角色权限
                            if let Some(role) = &ctx.user_role {
                                if !self.check_path_permission(path, role) {
                                    // 无权访问，返回 403 Forbidden
                                    session.respond_error(403).await?;
                                    return Ok(true);
                                }

                                // 权限验证通过，继续处理
                            }
                        } else {
                            // JWT 无效，返回 401 Unauthorized
                            let mut resp = ResponseHeader::build(StatusCode::UNAUTHORIZED, None)?;
                            resp.insert_header(
                                header::WWW_AUTHENTICATE,
                                "Bearer error=\"invalid_token\"",
                            )?;

                            let body = Bytes::from(format!(
                                "{{\"error\":\"invalid_token\",\"message\":\"{}\"}}",
                                ctx.auth_error.as_deref().unwrap_or("Invalid token")
                            ));

                            session.write_response_header(Box::new(resp)).await?;
                            session.write_response_body(body, true).await?;

                            return Ok(true);
                        }
                    } else {
                        // 格式不是 Bearer token
                        session.respond_error(401).await?;
                        return Ok(true);
                    }
                } else {
                    // Authorization 头部解析失败
                    session.respond_error(401).await?;
                    return Ok(true);
                }
            } else {
                // 缺少 Authorization 头部
                session.respond_error(401).await?;
                return Ok(true);
            }
        }

        // 继续正常代理流程
        Ok(false)
    }

    // 实现其他必要的方法...
}
```

## request_filter 性能考虑

`request_filter()` 方法在每个请求的处理流程中都会被调用，因此其性能对整个代理服务的吞吐量和延迟有显著影响。以下是一些提高 `request_filter()` 性能的建议：

1. **避免过重的计算**：尽量避免在此方法中执行密集型计算，如果必须进行，考虑使用异步任务或专门的计算线程池。

2. **减少阻塞操作**：不要在这个方法中执行阻塞的 I/O 操作，比如同步读写文件或数据库。使用异步方法代替。

3. **优化数据结构**：使用高效的数据结构来存储黑名单、配置等信息，例如使用 HashMap 或专门的查找数据结构而不是线性查找。

4. **缓存结果**：对于频繁执行的检查，考虑缓存结果以避免重复计算。

5. **早期返回**：尽早检测和处理无法继续的情况，避免不必要的计算。

## 小结

`request_filter()` 方法是 Pingora 代理中一个强大而灵活的环节，它允许你：

1. 检查请求的各种属性，包括头部信息、方法、路径等
2. 实现访问控制、认证和授权逻辑
3. 直接向客户端返回响应，无需转发请求
4. 自定义错误处理和特定路径的本地响应

通过巧妙地使用这个方法，你可以构建各种复杂的代理行为，包括 API 网关、安全过滤器、缓存层等。在下一章中，我们将探讨如何在 `upstream_peer()` 方法中动态选择上游服务器。

## 练习

1. 编写一个 `request_filter()` 实现，检查请求中的 "X-Api-Key" 头部，并验证其是否在允许的 API 密钥列表中。

2. 实现一个基于地理位置的访问控制系统，从 "X-Forwarded-For" 或客户端 IP 中识别用户位置，并根据配置的规则允许或阻止访问。

3. 创建一个健康检查端点，当请求路径为 "/health" 时，返回一个包含系统状态的 JSON 响应，而不转发到上游服务器。

4. 扩展第 3 题，让健康检查响应包含当前代理实例的统计信息，如已处理请求数、错误数等。
