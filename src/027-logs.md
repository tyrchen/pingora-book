# 日志追踪与诊断

在开发和运维 Pingora 应用时，有效地使用日志和诊断工具对于快速定位和解决问题至关重要。本章将深入探讨如何配置和使用 Pingora 的日志功能，特别是通过 `RUST_LOG` 环境变量和 `request_summary` 方法来追踪请求的完整处理流程和诊断错误。

## 配置 Pingora 日志级别

Pingora 使用 Rust 的标准日志库，通过 `RUST_LOG` 环境变量来控制日志级别。这个环境变量可以设置为多种不同的日志级别，以便在不同的场景下提供适当的详细程度：

- `error`：只显示错误信息，适用于生产环境
- `warn`：显示警告和错误，适用于大多数生产环境
- `info`：显示一般信息、警告和错误，适用于测试环境
- `debug`：显示调试信息及以上级别，适用于开发环境
- `trace`：显示最详细的跟踪信息，适用于问题诊断

### 基本配置

最简单的配置方式是在启动 Pingora 服务之前设置环境变量：

```bash
RUST_LOG=info cargo run --example simple_proxy
```

### 更精细的控制

`RUST_LOG` 支持更复杂的配置，可以为不同的模块设置不同的日志级别：

```bash
# Pingora 核心组件使用 info 级别，HTTP 相关组件使用 debug 级别
RUST_LOG=pingora=info,pingora_core::protocols::http=debug cargo run
```

这种配置特别有用，因为它允许您关注特定的模块，同时保持其他模块的日志级别较低，避免日志过于冗长。

### 配置日志输出格式

除了控制日志级别外，您还可以通过 `env_logger` 库配置日志的输出格式。例如，在项目的 `main.rs` 中添加以下代码：

```rust
fn configure_logging() {
    use env_logger::{Builder, Env};

    let env = Env::default()
        .filter_or("RUST_LOG", "info");

    Builder::from_env(env)
        .format(|buf, record| {
            use std::io::Write;
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            writeln!(
                buf,
                "{} [{}] {} - {}",
                timestamp,
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();
}
```

然后在 `main` 函数的开始调用这个函数：

```rust
fn main() {
    configure_logging();
    // 其余代码...
}
```

这将输出包含时间戳、日志级别、模块名称和日志消息的格式化日志。

## 使用 request_summary 追踪请求流程

`request_summary` 方法是 ProxyHttp trait 中的一个重要回调，它用于生成请求的摘要信息，这些信息会在错误日志和访问日志中使用。默认实现提供基本的请求信息，但您可以覆盖它以添加更多上下文：

```rust
fn request_summary(&self, session: &Session, ctx: &Self::CTX) -> String {
    let default_summary = session.as_ref().request_summary();
    let client_ip = session.client_addr().map_or("unknown".to_string(), |addr| addr.to_string());
    let request_id = ctx.request_id.clone().unwrap_or_else(|| "none".to_string());
    let processing_time = if let Some(start_time) = ctx.start_time {
        format!("{}ms", start_time.elapsed().as_millis())
    } else {
        "unknown".to_string()
    };

    format!(
        "{}, ClientIP: {}, RequestID: {}, ProcessingTime: {}",
        default_summary, client_ip, request_id, processing_time
    )
}
```

这个实现会生成类似以下的摘要：

```http
GET /api/users, Host: example.com:443, ClientIP: 203.0.113.42, RequestID: req-a1b2c3, ProcessingTime: 157ms
```

### 添加请求标识符

为每个请求添加唯一标识符是一种最佳实践，它可以帮助您在分布式系统中跟踪请求。在 `new_ctx` 中为每个请求生成唯一 ID：

```rust
fn new_ctx(&self) -> Self::CTX {
    MyContext {
        request_id: Some(format!("req-{}", uuid::Uuid::new_v4().to_string()[..8])),
        start_time: Some(std::time::Instant::now()),
        // 其他字段...
    }
}
```

然后在所有日志记录中包含这个 ID。

### 记录请求处理的各个阶段

为了全面了解请求的生命周期，您可以在请求处理的各个阶段添加日志：

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    let req = session.req_header();
    debug!(
        "[{}] Processing request: {} {}, Host: {}",
        ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
        req.method,
        req.uri.path(),
        req.uri.host().unwrap_or_default()
    );

    // 请求处理逻辑...

    Ok(false)
}

async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // 选择上游服务器...
    let peer = Box::new(HttpPeer::new(
        ("example.com", 443),
        true,
        "example.com".to_string(),
    ));

    debug!(
        "[{}] Selected upstream: {}:{}",
        ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
        peer.address().ip(),
        peer.address().port()
    );

    Ok(peer)
}

async fn connected_to_upstream(
    &self,
    session: &mut Session,
    reused: bool,
    peer: &HttpPeer,
    #[cfg(unix)] fd: std::os::unix::io::RawFd,
    #[cfg(windows)] sock: std::os::windows::io::RawSocket,
    digest: Option<&Digest>,
    ctx: &mut Self::CTX,
) -> Result<()> {
    debug!(
        "[{}] Connected to upstream: {}, Connection: {}",
        ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
        peer.address(),
        if reused { "reused" } else { "new" }
    );

    Ok(())
}
```

## 处理和分析错误日志

Pingora 提供了多种处理错误的回调，这些回调可以帮助您了解错误的性质和上下文，并尝试恢复或优雅地处理失败：

### 1. suppress_error_log

有时某些错误是预期的或不需要记录的。例如，当客户端过早关闭连接时：

```rust
fn suppress_error_log(&self, session: &Session, _ctx: &Self::CTX, error: &Error) -> bool {
    // 不记录客户端主动关闭连接的错误
    if error.esource() == &ErrorSource::Downstream
        && matches!(
            error.etype(),
            ErrorType::ConnectionClosed | ErrorType::ReadError | ErrorType::WriteError
        )
    {
        return true;
    }

    // 不记录特定路径的404错误
    if error.etype() == &ErrorType::HTTPStatus(404)
        && session.req_header().uri.path().starts_with("/health")
    {
        return true;
    }

    false
}
```

### 2. fail_to_connect

当无法连接到上游服务器时调用此回调。您可以更新错误信息，并决定是否应该重试：

```rust
fn fail_to_connect(
    &self,
    _session: &mut Session,
    peer: &HttpPeer,
    ctx: &mut Self::CTX,
    mut e: Box<e>,
) -> Box<e> {
    // 记录连接失败的次数
    ctx.connection_failures += 1;

    // 添加更多上下文到错误中
    e = e.more_context(format!(
        "Failed to connect to {} (attempt {})",
        peer.address(),
        ctx.connection_failures
    ));

    // 如果尝试次数少于最大值，标记为可重试
    if ctx.connection_failures < self.max_retries {
        debug!(
            "[{}] Connection failed, will retry: {}",
            ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
            e
        );
        e.set_retry(true);
    } else {
        info!(
            "[{}] Connection failed, max retries reached: {}",
            ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
            e
        );
    }

    e
}
```

### 3. error_while_proxy

当连接已经建立但在代理过程中出现错误时调用：

```rust
fn error_while_proxy(
    &self,
    peer: &HttpPeer,
    session: &mut Session,
    mut e: Box<e>,
    ctx: &mut Self::CTX,
    client_reused: bool,
) -> Box<e> {
    // 添加上下文信息
    e = e.more_context(format!("Error while proxying to {}", peer.address()));

    // 对于幂等请求（如 GET），如果连接是重用的且可能不稳定，可以标记为可重试
    let method = session.req_header().method.as_str();
    let safe_to_retry = matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE");

    if safe_to_retry && client_reused {
        debug!(
            "[{}] Proxy error on reused connection, will retry: {}",
            ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
            e
        );
        e.set_retry(true);
    } else {
        warn!(
            "[{}] Proxy error, cannot retry: {}",
            ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
            e
        );
    }

    e
}
```

### 4. fail_to_proxy

当请求处理过程中遇到致命错误时调用，用于定制向客户端发送的错误响应：

```rust
async fn fail_to_proxy(
    &self,
    session: &mut Session,
    e: &Error,
    ctx: &mut Self::CTX,
) -> FailToProxy
where
    Self::CTX: Send + Sync,
{
    // 确定适当的状态码
    let code = match e.etype() {
        HTTPStatus(code) => *code,
        _ => match e.esource() {
            ErrorSource::Upstream => 502,  // 上游错误 -> Bad Gateway
            ErrorSource::Downstream => match e.etype() {
                WriteError | ReadError | ConnectionClosed => 0,  // 连接已关闭，不发送响应
                _ => 400,  // 客户端错误 -> Bad Request
            },
            ErrorSource::Internal | ErrorSource::Unset => 500,  // 内部错误 -> Internal Server Error
        },
    };

    if code > 0 {
        // 为不同错误类型准备自定义错误页面
        let error_page = match code {
            502 => format!(
                "<html><body><h1>502 Bad Gateway</h1><p>请求处理失败。请稍后重试。</p><p>RequestID: {}</p></body></html>",
                ctx.request_id.as_ref().unwrap_or(&"none".to_string())
            ),
            500 => format!(
                "<html><body><h1>500 Internal Server Error</h1><p>服务器遇到错误。请联系管理员。</p><p>RequestID: {}</p></body></html>",
                ctx.request_id.as_ref().unwrap_or(&"none".to_string())
            ),
            _ => format!(
                "<html><body><h1>Error {}</h1><p>请求处理出错。</p><p>RequestID: {}</p></body></html>",
                code,
                ctx.request_id.as_ref().unwrap_or(&"none".to_string())
            ),
        };

        // 发送自定义错误页面
        if let Err(send_err) = session.respond_html(code, &error_page).await {
            error!(
                "[{}] Failed to send error response: {}",
                ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
                send_err
            );
        }
    }

    // 判断下游连接是否可以重用
    let can_reuse = code != 500 && code != 0;  // 不重用内部错误或已关闭的连接

    FailToProxy {
        error_code: code,
        can_reuse_downstream: can_reuse,
    }
}
```

## 日志分析与监控

除了生成日志外，还需要有效地分析和监控这些日志。以下是一些推荐的工具和方法：

### 1. 结构化日志

使用结构化日志格式（如 JSON）可以更容易地进行分析：

```rust
async fn logging(
    &self,
    session: &mut Session,
    error: Option<&Error>,
    ctx: &mut Self::CTX,
) {
    let status_code = session
        .response_written()
        .map_or(0, |resp| resp.status.as_u16());

    let duration = ctx.start_time.map_or(0, |t| t.elapsed().as_millis());
    let client_ip = session.client_addr().map_or("unknown".to_string(), |addr| addr.to_string());
    let request_method = session.req_header().method.to_string();
    let request_path = session.req_header().uri.path().to_string();
    let host = session.req_header().uri.host().unwrap_or_default().to_string();

    // 创建结构化日志
    let log_entry = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "request_id": ctx.request_id,
        "client_ip": client_ip,
        "method": request_method,
        "path": request_path,
        "host": host,
        "status_code": status_code,
        "duration_ms": duration,
        "upstream": ctx.upstream_address,
        "error": error.map(|e| e.to_string()),
    });

    // 使用不同的日志级别
    if let Some(err) = error {
        error!("{}", log_entry);
    } else if status_code >= 400 {
        warn!("{}", log_entry);
    } else {
        info!("{}", log_entry);
    }
}
```

### 2. 集成 ELK 或其他日志分析系统

将日志发送到 Elasticsearch、Logstash 和 Kibana (ELK) 或类似的日志聚合系统，可以提供强大的搜索、过滤和可视化功能：

```rust
async fn logging(
    &self,
    session: &mut Session,
    error: Option<&Error>,
    ctx: &mut Self::CTX,
) {
    // 生成日志条目，类似上面的示例
    let log_entry = generate_log_entry(session, error, ctx);

    // 本地记录
    if let Some(err) = error {
        error!("{}", log_entry.to_string());
    } else {
        info!("{}", log_entry.to_string());
    }

    // 异步发送到远程日志系统
    if let Some(log_sender) = &self.log_sender {
        if let Err(e) = log_sender.send(log_entry).await {
            error!("Failed to send log to remote system: {}", e);
        }
    }
}
```

### 3. 日志关联与请求跟踪

使用请求 ID 关联相关日志，并添加上下文信息，可以更容易地跟踪单个请求的完整生命周期：

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    // 从请求头中提取跟踪 ID（如果存在）
    if let Some(trace_id) = session.req_header().headers.get("X-Trace-ID") {
        if let Ok(id) = trace_id.to_str() {
            ctx.request_id = Some(id.to_string());
        }
    }

    // 如果没有跟踪 ID，生成一个新的
    if ctx.request_id.is_none() {
        ctx.request_id = Some(format!("req-{}", uuid::Uuid::new_v4().to_string()[..8]));
    }

    // 将跟踪 ID 添加到响应头中
    if let Some(id) = &ctx.request_id {
        if let Ok(headers) = session.insert_response_header("X-Trace-ID", id) {
            // 成功添加跟踪 ID 到响应头
            debug!("[{}] Added trace ID to response headers", id);
        }
    }

    // 继续正常处理
    Ok(false)
}
```

### 4. 性能分析与追踪

记录请求处理的各个阶段的时间，可以帮助识别性能瓶颈：

```rust
fn new_ctx(&self) -> Self::CTX {
    MyContext {
        request_id: None,
        start_time: Some(std::time::Instant::now()),
        stage_timings: HashMap::new(),
        // 其他字段...
    }
}

async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    // 记录阶段开始时间
    let stage_start = std::time::Instant::now();

    // 请求处理逻辑...

    // 记录阶段耗时
    let elapsed = stage_start.elapsed().as_millis();
    ctx.stage_timings.insert("request_filter".to_string(), elapsed);

    Ok(false)
}

// 在其他回调中也添加类似的计时代码...

async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
    let total_time = ctx.start_time.map_or(0, |t| t.elapsed().as_millis());

    debug!(
        "[{}] Request processing times: total={}ms, stages={:?}",
        ctx.request_id.as_ref().unwrap_or(&"none".to_string()),
        total_time,
        ctx.stage_timings
    );

    // 其他日志记录逻辑...
}
```

## 实用的日志分析命令

在生产环境中，快速筛选和分析日志是定位问题的关键。以下是一些有用的命令行工具和技巧：

### 使用 grep 和 jq 分析结构化日志

如果您使用 JSON 格式的日志，可以使用 `jq` 工具进行高效的分析：

```bash
# 查找特定请求 ID 的所有日志
cat application.log | grep "req-a1b2c3" | jq '.'

# 统计每个 HTTP 状态码的数量
cat application.log | jq -r 'select(.status_code != null) | .status_code' | sort | uniq -c | sort -nr

# 找出响应时间最长的请求
cat application.log | jq -r 'select(.duration_ms != null) | [.request_id, .path, .duration_ms] | @csv' | sort -t, -k3 -nr | head -10

# 分析特定时间段内的错误
cat application.log | jq -r 'select(.timestamp >= "2023-01-01T10:00:00" and .timestamp <= "2023-01-01T11:00:00" and .error != null)'
```

### 使用 awk 和 sed 分析传统日志

对于非结构化日志，可以使用 `awk` 和 `sed` 进行处理：

```bash
# 提取所有 5xx 错误
cat application.log | grep "status: 5" | awk '{print $1, $2, $5, $8}'

# 计算每分钟的请求数
cat application.log | grep "INFO" | awk '{print $1, $2}' | cut -d: -f1,2 | uniq -c

# 查找特定类型的错误
cat application.log | grep "ConnectionTimeout" | sed -E 's/.*ClientIP: ([^,]+).*/\1/' | sort | uniq -c
```

## 最佳实践总结

1. **分层日志级别**：在开发环境使用详细日志（debug 或 trace），在生产环境使用精简日志（info 或 warn）。

2. **唯一请求标识符**：为每个请求分配唯一 ID，并在所有日志中包含该 ID。

3. **结构化日志格式**：使用 JSON 或其他结构化格式，便于机器处理和分析。

4. **关键性能指标**：记录请求处理时间、上游连接时间等关键性能指标。

5. **错误上下文**：在错误日志中包含足够的上下文信息，以便快速诊断问题。

6. **日志轮换**：实施日志轮换策略，防止日志文件过大。

7. **集中式日志管理**：使用 ELK、Grafana Loki 或其他集中式日志管理系统收集和分析日志。

8. **关联请求和响应**：使用请求 ID 关联请求和响应的所有日志条目。

9. **适当的错误处理**：根据错误类型采取不同的处理策略，避免不必要的重试或错误响应。

10. **监控和告警**：基于日志设置适当的监控和告警，及时发现问题。

通过全面了解 Pingora 的日志和诊断功能，您可以更有效地开发、调试和维护您的代理服务，确保它们在生产环境中可靠运行。
