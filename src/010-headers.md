# 请求与响应头部处理

在 Pingora 代理中，除了路由和负载均衡外，另一个核心功能是修改请求和响应的头部信息。本章将详细介绍如何在不同的处理阶段修改 HTTP 头部，包括在请求发送到上游服务器之前的 `upstream_request_filter()` 和收到上游服务器响应后的 `upstream_response_filter()` 与 `response_filter()`。

## upstream_request_filter 方法

在 Pingora 的请求处理流程中，`upstream_request_filter()` 方法允许你在请求被发送到上游服务器之前对其进行修改。这是实现很多代理功能的关键环节，如添加认证信息、修改请求路径、去除敏感头部等。

方法签名如下：

```rust
async fn upstream_request_filter(
    &self,
    session: &mut Session,
    upstream_request: &mut RequestHeader,
    ctx: &mut Self::CTX,
) -> Result<()>
where
    Self::CTX: Send + Sync;
```

参数说明：

- `session`：当前会话，包含客户端请求的完整信息
- `upstream_request`：将要发送给上游的请求头，可以直接修改
- `ctx`：请求上下文对象，可用于在处理阶段之间共享数据

注意，`upstream_request` 是一个可变引用，你可以直接修改它来改变发送给上游的请求头。

### upstream_request_filter 的常见用途

以下是 `upstream_request_filter()` 方法的一些常见使用场景：

#### 1. 添加或修改请求头

最常见的需求是添加或修改请求头，例如添加认证信息、跟踪标识符或其他元数据：

```rust
async fn upstream_request_filter(
    &self,
    session: &mut Session,
    upstream_request: &mut RequestHeader,
    ctx: &mut Self::CTX,
) -> Result<()> {
    // 添加认证头部
    upstream_request.insert_header("Authorization", "Bearer your-token-here")?;

    // 添加请求 ID（可能在前面的阶段生成）
    if let Some(request_id) = &ctx.request_id {
        upstream_request.insert_header("X-Request-ID", request_id.clone())?;
    }

    // 添加代理相关信息
    upstream_request.insert_header("X-Proxy-Version", "pingora/1.0")?;

    Ok(())
}
```

#### 2. 删除敏感或不必要的头部

有时需要删除一些敏感的或对上游服务不必要的头部信息：

```rust
async fn upstream_request_filter(
    &self,
    _session: &mut Session,
    upstream_request: &mut RequestHeader,
    _ctx: &mut Self::CTX,
) -> Result<()> {
    // 删除可能包含敏感信息的头部
    upstream_request.remove_header("Cookie");
    upstream_request.remove_header("Authorization");

    // 删除一些与连接相关的头部，这些通常由代理自己管理
    upstream_request.remove_header("Connection");
    upstream_request.remove_header("Keep-Alive");
    upstream_request.remove_header("Proxy-Connection");

    Ok(())
}
```

#### 3. 添加客户端 IP 信息

一个常见的代理功能是将客户端 IP 地址传递给上游服务：

```rust
async fn upstream_request_filter(
    &self,
    session: &mut Session,
    upstream_request: &mut RequestHeader,
    _ctx: &mut Self::CTX,
) -> Result<()> {
    // 获取客户端 IP 地址
    if let Some(client_ip) = session.client_addr().map(|addr| addr.ip().to_string()) {
        // 添加 X-Forwarded-For 头部
        upstream_request.insert_header("X-Forwarded-For", client_ip)?;

        // 也可以添加其他标准的代理头部
        upstream_request.insert_header("X-Real-IP", client_ip)?;
    }

    Ok(())
}
```

#### 4. 修改请求路径

有时需要修改请求的目标路径，例如添加前缀或执行路径重写：

```rust
async fn upstream_request_filter(
    &self,
    _session: &mut Session,
    upstream_request: &mut RequestHeader,
    _ctx: &mut Self::CTX,
) -> Result<()> {
    // 获取原始路径
    let original_uri = upstream_request.uri();
    let original_path = original_uri.path();

    // 为路径添加前缀（例如 API 版本）
    let new_path = format!("/api/v2{}", original_path);

    // 创建一个新的 URI
    let mut parts = original_uri.clone().into_parts();
    let new_path_and_query = if let Some(query) = original_uri.query() {
        format!("{}?{}", new_path, query)
    } else {
        new_path
    };

    // 替换路径
    parts.path_and_query = Some(new_path_and_query.parse().unwrap());
    let new_uri = Uri::from_parts(parts).unwrap();

    // 设置新的 URI
    upstream_request.set_uri(new_uri);

    Ok(())
}
```

#### 5. 修改 Host 头部

当请求被转发到不同的主机时，可能需要相应地修改 Host 头部：

```rust
async fn upstream_request_filter(
    &self,
    _session: &mut Session,
    upstream_request: &mut RequestHeader,
    ctx: &mut Self::CTX,
) -> Result<()> {
    // 如果在 upstream_peer 中选择了上游服务器，可以使用其主机名
    if let Some(upstream_host) = &ctx.selected_upstream_host {
        upstream_request.insert_header("Host", upstream_host.clone())?;
    } else {
        // 或者使用一个固定的主机名
        upstream_request.insert_header("Host", "api.internal.example.com")?;
    }

    Ok(())
}
```

### 实际示例：API 网关

以下是一个更完整的示例，实现一个简单的 API 网关功能，该网关会：

1. 验证请求中的 API 密钥
2. 添加请求跟踪 ID
3. 添加客户端 IP 信息
4. 根据路径对请求进行分类并添加相应头部

```rust
async fn upstream_request_filter(
    &self,
    session: &mut Session,
    upstream_request: &mut RequestHeader,
    ctx: &mut ApiGatewayContext,
) -> Result<()> {
    // 1. 验证 API 密钥（假设已在 request_filter 中验证并存储在上下文中）
    if let Some(api_key_type) = &ctx.api_key_type {
        // 添加验证后的 API 权限信息
        upstream_request.insert_header("X-API-Client-Type", api_key_type)?;
        upstream_request.insert_header("X-API-Authenticated", "true")?;
    }

    // 2. 添加或保留请求跟踪 ID
    if ctx.request_id.is_none() {
        // 如果之前没有生成请求 ID，现在生成一个
        ctx.request_id = Some(format!("{}", uuid::Uuid::new_v4()));
    }
    upstream_request.insert_header("X-Request-ID", ctx.request_id.as_ref().unwrap())?;

    // 3. 添加客户端 IP 信息
    if let Some(client_ip) = session.client_addr().map(|addr| addr.ip().to_string()) {
        upstream_request.insert_header("X-Forwarded-For", client_ip.clone())?;
        upstream_request.insert_header("X-Real-IP", client_ip)?;
    }

    // 4. 根据路径进行分类并添加头部
    let path = upstream_request.uri().path();
    if path.starts_with("/api/users") {
        upstream_request.insert_header("X-Service-Category", "user-service")?;
    } else if path.starts_with("/api/products") {
        upstream_request.insert_header("X-Service-Category", "product-service")?;
    } else if path.starts_with("/api/orders") {
        upstream_request.insert_header("X-Service-Category", "order-service")?;
    }

    // 5. 添加一些通用的跟踪信息
    upstream_request.insert_header("X-Gateway-Time", chrono::Utc::now().to_rfc3339())?;

    // 6. 记录操作到上下文
    ctx.request_modified = true;

    Ok(())
}
```

## 响应头部处理

Pingora 提供了两个不同的回调方法来处理从上游服务器发回的响应头部：

1. `upstream_response_filter`：在响应到达代理后，缓存（如果启用）之前调用
2. `response_filter`：在响应发送给客户端前，缓存（如果启用）之后调用

这两个方法让你可以在不同阶段修改响应头部，根据不同的需求选择适当的方法。

### upstream_response_filter 方法

`upstream_response_filter` 方法允许你在响应被可能缓存之前修改它。这意味着你在这里所做的任何修改都会被缓存起来（如果启用了缓存）。

方法签名如下：

```rust
fn upstream_response_filter(
    &self,
    session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut Self::CTX,
) -> Result<()>;
```

注意这是一个同步方法，不是 `async`。这是因为处理响应头部通常不需要执行异步操作。

使用此方法的场景包括：

1. 修改缓存控制头部（如 `Cache-Control`、`Expires`）
2. 修改内容类型或编码信息
3. 添加需要被缓存的自定义头部

示例实现：

```rust
fn upstream_response_filter(
    &self,
    _session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut Self::CTX,
) -> Result<()> {
    // 保存上游响应状态码到上下文（用于日志或分析）
    ctx.upstream_status = Some(upstream_response.status.as_u16());

    // 修改缓存控制头部
    upstream_response.remove_header("Cache-Control");
    upstream_response.insert_header("Cache-Control", "public, max-age=3600")?;

    // 添加自定义头部（会被缓存）
    upstream_response.insert_header("X-Served-By-Backend", "backend-server-1")?;

    Ok(())
}
```

### response_filter 方法

`response_filter` 方法在响应即将发送给客户端之前被调用，这是你最后一次可以修改响应的机会。如果使用了缓存，这个方法会在从缓存检索内容后调用。

方法签名如下：

```rust
async fn response_filter(
    &self,
    session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut Self::CTX,
) -> Result<()>
where
    Self::CTX: Send + Sync;
```

使用此方法的场景包括：

1. 添加不应被缓存的动态响应头（如当前时间、请求特定信息）
2. 添加安全相关头部（如 CORS、CSP）
3. 添加代理标识信息
4. 删除不应暴露给客户端的头部

示例实现：

```rust
async fn response_filter(
    &self,
    _session: &mut Session,
    upstream_response: &mut ResponseHeader,
    _ctx: &mut Self::CTX,
) -> Result<()>
where
    Self::CTX: Send + Sync,
{
    // 添加服务器标识（覆盖上游服务器的标识）
    upstream_response.insert_header("Server", "MyPingoraProxy/1.0")?;

    // 添加 CORS 头部
    upstream_response.insert_header("Access-Control-Allow-Origin", "*")?;
    upstream_response.insert_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    upstream_response.insert_header("Access-Control-Allow-Headers", "Content-Type, Authorization")?;

    // 添加安全相关头部
    upstream_response.insert_header("X-Content-Type-Options", "nosniff")?;
    upstream_response.insert_header("X-Frame-Options", "DENY")?;
    upstream_response.insert_header("X-XSS-Protection", "1; mode=block")?;

    // 添加响应时间头部
    let now = chrono::Utc::now().to_rfc3339();
    upstream_response.insert_header("X-Response-Time", now)?;

    // 删除可能的敏感头部
    upstream_response.remove_header("X-Powered-By");
    upstream_response.remove_header("Server-Timing");

    Ok(())
}
```

### 实际示例：API 网关响应处理

以下是一个更完整的例子，展示了 API 网关如何处理响应：

```rust
// upstream_response_filter: 在响应被缓存前修改
fn upstream_response_filter(
    &self,
    _session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut ApiGatewayContext,
) -> Result<()> {
    // 保存状态码和响应时间
    ctx.upstream_status = Some(upstream_response.status.as_u16());
    ctx.upstream_response_time = Some(chrono::Utc::now());

    // 根据不同的响应状态码进行处理
    let status = upstream_response.status.as_u16();

    if status >= 500 {
        // 服务器错误，不缓存
        upstream_response.insert_header("Cache-Control", "no-store")?;
    } else if status >= 400 {
        // 客户端错误，短时间缓存
        upstream_response.insert_header("Cache-Control", "public, max-age=60")?;
    } else if status == 200 || status == 304 {
        // 成功响应，可以缓存更长时间
        if upstream_response.headers().get("Cache-Control").is_none() {
            // 只有上游没有指定缓存控制时才设置
            upstream_response.insert_header("Cache-Control", "public, max-age=3600")?;
        }
    }

    // 添加上游服务信息（会被缓存）
    if let Some(upstream_host) = &ctx.selected_upstream_host {
        upstream_response.insert_header("X-Upstream-Host", upstream_host)?;
    }

    Ok(())
}

// response_filter: 在响应发送给客户端前修改
async fn response_filter(
    &self,
    session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut ApiGatewayContext,
) -> Result<()>
where
    ApiGatewayContext: Send + Sync,
{
    // 添加请求处理信息
    if let Some(request_id) = &ctx.request_id {
        upstream_response.insert_header("X-Request-ID", request_id)?;
    }

    // 计算并添加响应时间
    if let Some(start_time) = ctx.request_start_time {
        let duration = chrono::Utc::now().signed_duration_since(start_time);
        let ms = duration.num_milliseconds();
        upstream_response.insert_header("X-Response-Time-Ms", ms.to_string())?;
    }

    // 添加服务器标识
    upstream_response.insert_header("Server", "PingoraApiGateway/1.0")?;

    // 添加 CORS 头部
    let origin = session.get_header("Origin");
    if !origin.is_empty() {
        // 有 Origin 头部，添加 CORS 头部
        upstream_response.insert_header("Access-Control-Allow-Origin", origin)?;
        upstream_response.insert_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")?;
        upstream_response.insert_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Api-Key")?;
        upstream_response.insert_header("Access-Control-Max-Age", "86400")?; // 24小时
    }

    // 添加安全相关头部
    upstream_response.insert_header("X-Content-Type-Options", "nosniff")?;
    upstream_response.insert_header("X-Frame-Options", "DENY")?;
    upstream_response.insert_header("Content-Security-Policy", "default-src 'self'")?;

    // 删除内部头部
    upstream_response.remove_header("X-Internal-Server");
    upstream_response.remove_header("X-Backend-Server");

    // 如果响应状态码为错误码，记录到上下文（用于日志）
    let status = upstream_response.status.as_u16();
    if status >= 400 {
        ctx.error_response = true;
        ctx.error_code = Some(status);
    }

    Ok(())
}
```

## 使用上下文在处理阶段之间共享数据

注意在上面的例子中，我们在不同的处理阶段之间共享了上下文数据。例如，在 `upstream_peer()` 中选择的上游服务器信息可以在 `upstream_request_filter()` 中使用，而在 `upstream_response_filter()` 中记录的状态码可以在 `response_filter()` 或 `logging()` 中使用。

这种共享是通过 `ctx` 参数实现的，它是在 `new_ctx()` 方法中创建的。为了有效地在处理阶段之间共享数据，你应该为你的代理定义一个结构良好的上下文类型：

```rust
struct ApiGatewayContext {
    // 请求相关
    request_id: Option<String>,
    request_start_time: Option<DateTime<Utc>>,
    api_key_type: Option<String>,
    request_modified: bool,

    // 上游相关
    selected_upstream_host: Option<String>,
    upstream_status: Option<u16>,
    upstream_response_time: Option<DateTime<Utc>>,

    // 响应相关
    error_response: bool,
    error_code: Option<u16>,
}

impl ApiGatewayContext {
    fn new() -> Self {
        Self {
            request_id: Some(format!("{}", uuid::Uuid::new_v4())),
            request_start_time: Some(chrono::Utc::now()),
            api_key_type: None,
            request_modified: false,

            selected_upstream_host: None,
            upstream_status: None,
            upstream_response_time: None,

            error_response: false,
            error_code: None,
        }
    }
}

struct ApiGateway;

impl ProxyHttp for ApiGateway {
    type CTX = ApiGatewayContext;

    fn new_ctx(&self) -> Self::CTX {
        ApiGatewayContext::new()
    }

    // 其他方法的实现...
}
```

## 总结

在本章中，我们学习了如何使用 Pingora 的 `upstream_request_filter()`、`upstream_response_filter()` 和 `response_filter()` 方法来修改请求和响应的头部信息。这些方法允许我们在不同的处理阶段对 HTTP 头部进行检查和修改，实现各种代理功能。

关键点总结：

1. `upstream_request_filter()` 允许你在请求发送到上游之前修改请求头
2. `upstream_response_filter()` 在缓存之前修改响应头
3. `response_filter()` 在响应发送给客户端之前修改响应头（包括从缓存提供的响应）
4. 使用上下文对象在不同处理阶段之间共享数据
5. 根据请求和响应特性有选择地添加、修改或删除头部信息

通过这些机制，你可以实现各种高级代理功能，如 API 网关、认证代理、内容修改、安全增强等。
