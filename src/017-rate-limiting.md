# 速率限制与连接限制

在前面的章节中，我们已经学习了 Pingora 的基本代理功能、HTTP 缓存、负载均衡和连接池管理等。本章将深入探讨速率限制和连接限制，这些功能对于保护你的代理服务和上游服务器免受过载非常重要。

## 速率限制的重要性

速率限制是一种保护机制，用于控制客户端在特定时间段内可以发送的请求数量。实施速率限制有以下几个好处：

1. **防止资源过载**：限制单个客户端可以消耗的资源，确保系统稳定
2. **防止滥用**：阻止恶意用户或有缺陷的客户端发送过多请求
3. **成本控制**：限制对付费 API 的调用或限制带宽使用
4. **保护上游服务**：防止上游服务器被大量请求压垮

## Pingora 中的速率限制

Pingora 通过 `pingora-limits` crate 提供速率限制功能。这个 crate 包含两个主要组件：

1. **Rate**：跟踪特定时间间隔内的请求率
2. **Inflight**：跟踪当前正在处理的请求数量

### 使用 Rate 进行请求速率限制

`Rate` 结构体使用滑动窗口算法来跟踪和限制请求率。它允许你：

- 观察和记录请求
- 计算特定时间窗口内的请求率
- 基于这些信息做出限制决策

#### 创建速率限制器

首先，我们需要添加必要的依赖：

```toml
# Cargo.toml
[dependencies]
pingora = { version = "0.3", features = ["lb"] }
pingora-limits = "0.3.0"
once_cell = "1.19.0"
```

然后，我们可以创建一个全局的速率限制器：

```rust
use once_cell::sync::Lazy;
use pingora_limits::rate::Rate;
use std::time::Duration;

// 创建一个每秒刷新的速率限制器
static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(1)));

// 每秒最大请求数
static MAX_REQUESTS_PER_SECOND: isize = 5;
```

#### 在请求处理中应用速率限制

要应用速率限制，我们需要重写 `ProxyHttp` trait 的 `request_filter` 方法：

```rust
use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::prelude::*;

struct RateLimitedProxy;

#[async_trait]
impl ProxyHttp for RateLimitedProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // 从请求中提取客户端标识
        // 这里使用 IP 地址作为示例，实际应用中可能使用其他标识如 API 密钥
        let client_ip = match session.client_addr() {
            Some(addr) => addr.to_string(),
            None => return Ok(false), // 无法获取 IP 地址，跳过限制
        };

        // 记录请求并获取当前窗口的请求数
        let current_requests = RATE_LIMITER.observe(&client_ip, 1);

        // 检查是否超过限制
        if current_requests > MAX_REQUESTS_PER_SECOND {
            // 超过限制，返回 429 状态码
            let mut header = ResponseHeader::build(429, None).unwrap();

            // 添加速率限制相关的标准响应头
            header.insert_header("X-RateLimit-Limit", MAX_REQUESTS_PER_SECOND.to_string())?;
            header.insert_header("X-RateLimit-Remaining", "0")?;
            header.insert_header("X-RateLimit-Reset", "1")?; // 1 秒后重置

            // 禁用 keep-alive 连接
            session.set_keepalive(None);

            // 返回响应
            session.write_response_header(Box::new(header), true).await?;

            // 返回 true 表示已处理请求，不再继续处理
            return Ok(true);
        }

        // 未超过限制，继续处理请求
        Ok(false)
    }

    // ... 其他方法的实现
}
```

### 基于应用 ID 的速率限制

在某些场景下，你可能希望基于应用 ID 或其他标识符而非 IP 地址进行限制。以下是一个基于请求头中的 `appid` 进行限制的示例：

```rust
struct APIGateway;

impl APIGateway {
    fn get_request_appid(&self, session: &mut Session) -> Option<String> {
        match session
            .req_header()
            .headers
            .get("appid")
            .map(|v| v.to_str())
        {
            None => None,
            Some(v) => match v {
                Ok(v) => Some(v.to_string()),
                Err(_) => None,
            },
        }
    }
}

#[async_trait]
impl ProxyHttp for APIGateway {
    // ... 其他方法

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let appid = match self.get_request_appid(session) {
            None => return Ok(false), // 没有应用 ID，跳过限制
            Some(id) => id,
        };

        // 记录请求并获取当前窗口的请求数
        let current_requests = RATE_LIMITER.observe(&appid, 1);

        if current_requests > MAX_REQUESTS_PER_SECOND {
            // 超过限制，返回 429 状态码
            // ... 与之前相同的响应处理逻辑 ...
            return Ok(true);
        }

        Ok(false)
    }
}
```

### 多级速率限制

在更复杂的应用中，你可能需要多级速率限制，如同时限制单个 IP 和整个应用的请求率：

```rust
// 全局速率限制器
static GLOBAL_RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(1)));
static IP_RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(1)));

// 限制阈值
static GLOBAL_LIMIT: isize = 100; // 每秒最多 100 个请求
static IP_LIMIT: isize = 5;      // 每个 IP 每秒最多 5 个请求

async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
    // 获取客户端 IP
    let client_ip = match session.client_addr() {
        Some(addr) => addr.to_string(),
        None => return Ok(false),
    };

    // 检查 IP 级别的限制
    let ip_requests = IP_RATE_LIMITER.observe(&client_ip, 1);
    if ip_requests > IP_LIMIT {
        // 返回 429 响应...
        return Ok(true);
    }

    // 检查全局级别的限制
    let global_requests = GLOBAL_RATE_LIMITER.observe(&"global", 1);
    if global_requests > GLOBAL_LIMIT {
        // 返回 429 响应...
        return Ok(true);
    }

    Ok(false)
}
```

## 连接限制

除了限制请求速率外，限制并发连接数也是保护服务器资源的重要方式。Pingora 提供了 `Inflight` 结构体来跟踪和限制并发连接或请求。

### 使用 Inflight 限制并发连接

`Inflight` 结构体使用一种近似计数器的机制来跟踪当前活跃的连接或请求。与 `Rate` 不同，`Inflight` 对象在超出作用域时会自动减少计数。

```rust
use once_cell::sync::Lazy;
use pingora_limits::inflight::Inflight;

// 全局连接限制器
static CONNECTION_LIMITER: Lazy<Inflight> = Lazy::new(|| Inflight::new());

// 每个 IP 的最大并发连接数
static MAX_CONNECTIONS_PER_IP: isize = 10;

async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    let client_ip = match session.client_addr() {
        Some(addr) => addr.to_string(),
        None => return Ok(false),
    };

    // 增加连接计数并获取当前连接数
    // 返回的 guard 会在离开作用域时自动减少计数
    let (guard, current_connections) = CONNECTION_LIMITER.incr(client_ip.clone(), 1);

    // 将 guard 存储在上下文中以保持其生命周期
    ctx.connection_guard = Some(guard);

    // 检查是否超过限制
    if current_connections > MAX_CONNECTIONS_PER_IP {
        // 超过限制，返回 429 响应
        let mut header = ResponseHeader::build(429, None).unwrap();
        header.insert_header("X-Connection-Limit-Reached", "true")?;
        session.set_keepalive(None);
        session.write_response_header(Box::new(header), true).await?;
        return Ok(true);
    }

    Ok(false)
}
```

注意，为了正确跟踪连接，我们需要一个有适当生命周期的上下文来存储 `guard`：

```rust
struct ProxyContext {
    connection_guard: Option<Guard>,
    // 其他上下文数据...
}
```

### 高级连接限制实现

在实际应用中，你可能需要更复杂的连接限制策略。以下是一个更完整的示例：

```rust
use pingora_limits::inflight::Inflight;
use std::collections::HashMap;
use std::sync::Mutex;

// 为不同服务定义不同的连接限制
struct ConnectionLimits {
    inflight: Inflight,
    service_limits: Mutex<HashMap<String, isize>>,
}

impl ConnectionLimits {
    fn new() -> Self {
        let mut service_limits = HashMap::new();
        service_limits.insert("default".to_string(), 50);
        service_limits.insert("api".to_string(), 100);
        service_limits.insert("static".to_string(), 200);

        ConnectionLimits {
            inflight: Inflight::new(),
            service_limits: Mutex::new(service_limits),
        }
    }

    fn get_limit(&self, service: &str) -> isize {
        let limits = self.service_limits.lock().unwrap();
        *limits.get(service).unwrap_or(&limits["default"])
    }

    fn is_limited(&self, ip: &str, service: &str) -> (Guard, bool) {
        let limit = self.get_limit(service);
        let key = format!("{}:{}", service, ip);
        let (guard, count) = self.inflight.incr(key, 1);
        (guard, count > limit)
    }
}

// 使用上面的限制器
static CONNECTION_LIMITS: Lazy<ConnectionLimits> = Lazy::new(|| ConnectionLimits::new());

async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    let client_ip = match session.client_addr() {
        Some(addr) => addr.to_string(),
        None => return Ok(false),
    };

    // 根据请求路径确定服务类型
    let path = session.req_header().uri.path();
    let service_type = if path.starts_with("/api") {
        "api"
    } else if path.starts_with("/static") {
        "static"
    } else {
        "default"
    };

    // 检查是否超过连接限制
    let (guard, is_limited) = CONNECTION_LIMITS.is_limited(&client_ip, service_type);
    ctx.connection_guard = Some(guard);

    if is_limited {
        // 返回 429 响应...
        return Ok(true);
    }

    Ok(false)
}
```

## 实际应用中的速率限制最佳实践

在实际应用中，速率限制和连接限制应该考虑多个因素：

### 1. 考虑负载均衡后的多实例部署

在多实例部署中，每个实例独立维护限制计数器可能导致实际限制是预期的 N 倍（N 为实例数）。解决方案包括：

- 使用共享的限制计数器（如 Redis）
- 调整每个实例的限制阈值（除以实例数）
- 使用一致性哈希将特定客户端总是路由到相同的实例

### 2. 分级限制策略

实施分级限制策略以适应不同的客户需求：

```rust
// 根据客户端类型返回不同的限制
fn get_rate_limit(&self, client_type: &str) -> isize {
    match client_type {
        "premium" => 50,  // 高级客户端
        "standard" => 20, // 标准客户端
        _ => 5,           // 默认限制
    }
}
```

### 3. 精细的速率限制响应

提供详细的速率限制信息以帮助客户端适应：

```rust
if is_rate_limited {
    let mut header = ResponseHeader::build(429, None).unwrap();

    // 添加标准的速率限制头
    header.insert_header("X-RateLimit-Limit", limit.to_string())?;
    header.insert_header("X-RateLimit-Remaining", "0")?;

    // 计算重置时间并添加
    let reset_time = RATE_LIMITER.rate_with(&client_id, |components| {
        (components.interval.as_secs_f64() - components.current_interval_fraction
            * components.interval.as_secs_f64()).ceil() as u64
    });
    header.insert_header("X-RateLimit-Reset", reset_time.to_string())?;

    // 添加 Retry-After 头（HTTP 标准）
    header.insert_header("Retry-After", reset_time.to_string())?;

    // 还可以添加更多详细信息
    header.insert_header("X-Rate-Limit-Type", "ip_based")?;

    session.write_response_header(Box::new(header), true).await?;
    return Ok(true);
}
```

### 4. 自适应速率限制

实施自适应速率限制，根据服务器负载或其他指标动态调整限制：

```rust
fn get_dynamic_rate_limit(&self) -> isize {
    // 根据系统负载计算动态限制
    let system_load = get_system_load(); // 获取系统负载的假设函数

    if system_load > 0.9 {  // 高负载
        return 2;  // 严格限制
    } else if system_load > 0.7 {  // 中等负载
        return 5;  // 适度限制
    } else {  // 低负载
        return 10; // 宽松限制
    }
}
```

## 完整示例：综合速率限制和连接限制

以下是一个综合速率限制和连接限制的完整示例：

```rust
use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora_limits::inflight::Inflight;
use pingora_limits::rate::Rate;
use std::time::Duration;

// 全局限制器
static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(1)));
static CONNECTION_LIMITER: Lazy<Inflight> = Lazy::new(|| Inflight::new());

// 限制阈值
static MAX_REQUESTS_PER_SECOND: isize = 5;
static MAX_CONNECTIONS_PER_IP: isize = 10;

struct LimitedProxy;

// 保存连接 guard 的上下文
struct Context {
    connection_guard: Option<Guard>,
}

#[async_trait]
impl ProxyHttp for LimitedProxy {
    type CTX = Context;

    fn new_ctx(&self) -> Self::CTX {
        Context {
            connection_guard: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let client_ip = match session.client_addr() {
            Some(addr) => addr.to_string(),
            None => return Ok(false),
        };

        // 连接限制检查
        let (guard, current_connections) = CONNECTION_LIMITER.incr(&client_ip, 1);
        ctx.connection_guard = Some(guard);

        if current_connections > MAX_CONNECTIONS_PER_IP {
            // 超过连接限制，返回 429
            let mut header = ResponseHeader::build(429, None).unwrap();
            header.insert_header("X-Connection-Limit-Reached", "true")?;
            session.set_keepalive(None);
            session.write_response_header(Box::new(header), true).await?;
            return Ok(true);
        }

        // 速率限制检查
        let current_requests = RATE_LIMITER.observe(&client_ip, 1);

        if current_requests > MAX_REQUESTS_PER_SECOND {
            // 超过速率限制，返回 429
            let mut header = ResponseHeader::build(429, None).unwrap();
            header.insert_header("X-RateLimit-Limit", MAX_REQUESTS_PER_SECOND.to_string())?;
            header.insert_header("X-RateLimit-Remaining", "0")?;
            header.insert_header("X-RateLimit-Reset", "1")?;
            session.set_keepalive(None);
            session.write_response_header(Box::new(header), true).await?;
            return Ok(true);
        }

        // 未超过任何限制，继续处理请求
        Ok(false)
    }

    // ... 其他 ProxyHttp 方法的实现
}

fn main() -> Result<()> {
    // 初始化日志
    env_logger::init();

    // 创建服务器
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务
    let proxy = LimitedProxy;
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // 配置监听地址
    proxy_service.add_tcp("0.0.0.0:8080");

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 启动服务器
    println!("Rate limited proxy running on 0.0.0.0:8080");
    server.run_forever();

    Ok(())
}
```

## 总结

Pingora 提供了强大而灵活的速率限制和连接限制功能，可以有效保护你的代理服务和上游服务器免受过载和滥用。通过 `pingora-limits` crate 中的 `Rate` 和 `Inflight` 结构体，你可以：

1. **控制请求速率**：限制客户端在特定时间窗口内的请求数量
2. **限制并发连接**：限制单个客户端可以同时维持的连接数量
3. **实施分级策略**：根据客户端类型、请求路径或其他属性应用不同的限制
4. **提供友好响应**：在限制触发时提供有用的信息，帮助客户端适应

通过合理配置和使用这些限制功能，你可以提高代理服务的可靠性和稳定性，同时确保资源的公平分配。
