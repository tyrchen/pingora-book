# 日志记录与错误处理

在前面的章节中，我们已经学习了如何处理 HTTP 请求和响应的头部与主体。本章将深入探讨如何使用 Pingora 的日志记录功能以及如何优雅地处理代理过程中可能出现的各种错误。这些功能对于构建健壮的代理服务至关重要，尤其是在生产环境中。

## 日志记录：logging 方法

`logging` 方法是 ProxyHttp trait 中的一个重要回调，它在每个请求处理完成时被调用，无论请求是成功完成还是遇到错误。这个方法是收集请求指标、记录访问日志和执行请求后清理工作的理想位置。

方法签名如下：

```rust
async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX)
where
    Self::CTX: Send + Sync;
```

参数说明：

- `session`：当前会话，包含请求和响应的完整信息
- `error`：如果请求处理过程中出现错误，则包含该错误；否则为 None
- `ctx`：请求上下文，可用于访问在请求处理的各个阶段收集的数据

### logging 方法的工作原理

`logging` 方法在以下情况下被调用：

1. 请求成功完成时（error 参数为 None）
2. 请求处理过程中遇到错误时（error 参数包含错误信息）
3. 在请求的所有资源被释放之前

这个方法是异步的，可以执行 I/O 操作，如写入日志文件或发送遥测数据到远程系统。

### 基本日志记录实现

以下是一个基本的日志记录实现示例：

```rust
async fn logging(
    &self,
    session: &mut Session,
    error: Option<&Error>,
    ctx: &mut Self::CTX,
) {
    // 获取响应状态码（如果响应已经发送）
    let response_code = session
        .response_written()
        .map_or(0, |resp| resp.status.as_u16());

    // 获取请求处理时间（如果在上下文中记录了开始时间）
    let processing_time = if let Some(start_time) = ctx.start_time {
        std::time::Instant::now().duration_since(start_time).as_millis()
    } else {
        0
    };

    // 记录访问日志
    if let Some(err) = error {
        // 错误情况下的日志
        error!(
            "请求处理失败: {} - 响应码: {}, 处理时间: {}ms, 错误: {}",
            self.request_summary(session, ctx),
            response_code,
            processing_time,
            err
        );
    } else {
        // 成功情况下的日志
        info!(
            "请求处理成功: {} - 响应码: {}, 处理时间: {}ms",
            self.request_summary(session, ctx),
            response_code,
            processing_time
        );
    }
}
```

在这个示例中，我们：

1. 使用 `session.response_written()` 获取响应状态码（如果响应已发送）
2. 计算请求处理时间（假设在上下文中记录了开始时间）
3. 根据请求是否成功，使用不同的日志级别记录信息

### request_summary 方法

ProxyHttp trait 中的 `request_summary` 方法是一个辅助函数，用于生成请求的摘要信息。它在错误日志记录时自动调用，也可以在 `logging` 方法中手动调用。默认实现使用 `session.as_ref().request_summary()`，返回包含请求方法、路径和主机信息的字符串。

方法签名如下：

```rust
fn request_summary(&self, session: &Session, ctx: &Self::CTX) -> String {
    session.as_ref().request_summary()
}
```

默认的 `request_summary` 实现输出格式如下：

```http
GET /path, Host: example.com:443
```

你可以覆盖这个方法，根据需要添加更多信息，例如客户端 IP、请求 ID 或自定义请求属性：

```rust
fn request_summary(&self, session: &Session, ctx: &Self::CTX) -> String {
    let default_summary = session.as_ref().request_summary();
    let client_ip = session.client_addr().map_or("unknown".to_string(), |addr| addr.to_string());
    let request_id = ctx.request_id.as_ref().unwrap_or(&"unknown".to_string());

    format!("{}, ClientIP: {}, RequestID: {}", default_summary, client_ip, request_id)
}
```

### 集成指标收集

在现代应用程序中，除了日志记录外，收集指标也非常重要。`logging` 方法是更新和增加指标的理想位置。下面是一个集成 Prometheus 指标的例子：

```rust
pub struct MetricsProxy {
    request_counter: prometheus::IntCounter,
    response_status: prometheus::IntCounterVec,
    request_duration: prometheus::Histogram,
}

impl MetricsProxy {
    pub fn new() -> Self {
        let request_counter = prometheus::IntCounter::new(
            "http_requests_total",
            "Total number of HTTP requests received",
        ).unwrap();

        let response_status = prometheus::IntCounterVec::new(
            prometheus::Opts::new(
                "http_response_status",
                "HTTP response status codes",
            ),
            &["status_code"],
        ).unwrap();

        let request_duration = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        ).unwrap();

        // 注册指标
        prometheus::default_registry().register(Box::new(request_counter.clone())).unwrap();
        prometheus::default_registry().register(Box::new(response_status.clone())).unwrap();
        prometheus::default_registry().register(Box::new(request_duration.clone())).unwrap();

        Self {
            request_counter,
            response_status,
            request_duration,
        }
    }
}

pub struct MetricsContext {
    start_time: std::time::Instant,
    // 其他上下文字段...
}

#[async_trait]
impl ProxyHttp for MetricsProxy {
    type CTX = MetricsContext;

    fn new_ctx(&self) -> Self::CTX {
        MetricsContext {
            start_time: std::time::Instant::now(),
            // 初始化其他字段...
        }
    }

    // 其他方法的实现...

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&Error>,
        ctx: &mut Self::CTX,
    ) {
        // 增加请求计数
        self.request_counter.inc();

        // 获取响应状态码
        let status_code = session
            .response_written()
            .map_or(if error.is_some() { 500 } else { 0 }, |resp| resp.status.as_u16());

        // 如果有状态码，记录状态码指标
        if status_code > 0 {
            self.response_status
                .with_label_values(&[status_code.to_string().as_str()])
                .inc();
        }

        // 记录请求处理时间
        let duration = ctx.start_time.elapsed();
        self.request_duration.observe(duration.as_secs_f64());

        // 记录详细的访问日志
        info!(
            "{} - status: {}, duration: {:.3}s {}",
            self.request_summary(session, ctx),
            status_code,
            duration.as_secs_f64(),
            error.map_or("".to_string(), |e| format!(", error: {}", e))
        );
    }
}
```

在这个示例中，我们：

1. 定义了三个 Prometheus 指标：请求总数、响应状态码分布和请求处理时间
2. 在上下文中记录请求开始时间
3. 在 `logging` 方法中更新这些指标并记录详细的访问日志

### 结构化日志记录

对于更高级的日志记录需求，可以考虑使用结构化日志，这使得日志分析和处理更加容易。以下是使用 `serde_json` 创建结构化日志的示例：

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

    let duration = ctx.start_time.elapsed().as_secs_f64();
    let client_ip = session.client_addr().map_or("unknown".to_string(), |addr| addr.to_string());
    let request_method = session.req_header().method.to_string();
    let request_path = session.req_header().uri.path().to_string();
    let host = session.req_header().uri.host().unwrap_or_default().to_string();

    // 创建结构化日志
    let log_entry = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "client_ip": client_ip,
        "method": request_method,
        "path": request_path,
        "host": host,
        "status_code": status_code,
        "duration_seconds": duration,
        "error": error.map(|e| e.to_string()),
        "request_id": ctx.request_id.clone().unwrap_or_default(),
        // 其他字段...
    });

    // 记录结构化日志
    info!("{}", log_entry.to_string());
}
```

结构化日志的优势在于：

1. 可以轻松地过滤和搜索特定字段
2. 可以轻松地进行日志分析和可视化
3. 可以轻松地整合到日志分析系统（如 ELK Stack、Loki 等）

## 错误处理

在代理服务中，错误处理是一个至关重要的方面。Pingora 提供了多个回调方法来处理请求处理过程中的不同类型的错误。

### suppress_error_log 方法

`suppress_error_log` 方法允许你控制是否应该为特定错误生成错误日志。默认情况下，所有错误都会被记录，但你可以重写此方法以抑制某些错误的日志记录：

```rust
fn suppress_error_log(&self, session: &Session, ctx: &Self::CTX, error: &Error) -> bool {
    // 如果是 404 错误，不记录错误日志
    if let ErrorType::HTTPStatus(status) = error.etype() {
        if *status == 404 {
            return true;
        }
    }

    // 对于健康检查请求，不记录错误日志
    if session.req_header().uri.path() == "/health" {
        return true;
    }

    false
}
```

### fail_to_connect 方法

`fail_to_connect` 方法在尝试连接到上游服务器失败时被调用。这个方法允许你决定是否应该重试请求，以及如何处理连接错误：

```rust
fn fail_to_connect(
    &self,
    session: &mut Session,
    peer: &HttpPeer,
    ctx: &mut Self::CTX,
    mut e: Box<e>,
) -> Box<e> {
    // 记录连接失败信息
    warn!(
        "连接到上游 {} 失败: {}",
        peer,
        e
    );

    // 如果是第一次尝试，标记为可重试
    if ctx.retries < self.max_retries {
        ctx.retries += 1;
        info!("标记请求为可重试，这是第 {} 次尝试", ctx.retries);
        e.set_retry(true);
    } else {
        info!("已达到最大重试次数 {}, 不再重试", self.max_retries);
    }

    e
}
```

当 `fail_to_connect` 将错误标记为可重试（通过调用 `e.set_retry(true)`）时，Pingora 将再次调用 `upstream_peer` 方法，让你有机会选择另一个上游服务器。

### error_while_proxy 方法

`error_while_proxy` 方法在已经与上游服务器建立连接但代理过程中出错时被调用。这个方法也允许你决定是否应该重试请求：

```rust
fn error_while_proxy(
    &self,
    peer: &HttpPeer,
    session: &mut Session,
    mut e: Box<e>,
    ctx: &mut Self::CTX,
    client_reused: bool,
) -> Box<e> {
    // 添加上下文信息到错误
    let e = e.more_context(format!("代理到 {} 时出错", peer));

    // 对于幂等方法（如 GET），可以考虑重试
    let method = session.req_header().method.as_str();
    let is_idempotent = matches!(method, "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE");

    if is_idempotent && ctx.retries < self.max_retries && client_reused {
        ctx.retries += 1;
        info!("标记幂等请求为可重试，这是第 {} 次尝试", ctx.retries);
        e.set_retry(true);
    }

    e
}
```

`error_while_proxy` 方法中，需要特别注意 `client_reused` 参数。如果连接是重用的，那么在某些情况下（例如连接已被远程关闭），重试是安全的。但对于非幂等方法（如 POST），即使连接是重用的，通常也不应该重试，因为这可能导致重复操作。

### fail_to_proxy 方法

`fail_to_proxy` 方法在请求处理过程中遇到致命错误时被调用。在这个方法中，你可以向客户端发送自定义错误响应：

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
    // 根据错误类型确定响应状态码
    let code = match e.etype() {
        ErrorType::HTTPStatus(status) => *status,
        _ => {
            match e.esource() {
                ErrorSource::Upstream => 502, // 上游服务器错误
                ErrorSource::Downstream => 400, // 客户端请求错误
                ErrorSource::Internal | ErrorSource::Unset => 500, // 内部服务器错误
            }
        }
    };

    // 向客户端发送自定义错误页面
    if code > 0 && session.is_downstream_writable() {
        // 根据错误类型选择不同的错误页面
        let error_body = match code {
            502 | 503 | 504 => {
                include_bytes!("../templates/server_error.html").to_vec()
            }
            404 => {
                include_bytes!("../templates/not_found.html").to_vec()
            }
            _ => {
                format!(
                    "<html><body><h1>错误 {}</h1><p>请求处理过程中出现错误。</p></body></html>",
                    code
                ).into_bytes()
            }
        };

        // 发送错误响应
        let _ = session.respond_error_with_body(code, Bytes::from(error_body)).await;
    }

    // 返回处理结果
    FailToProxy {
        error_code: code,
        can_reuse_downstream: code != 400, // 对于客户端错误，不重用连接
    }
}
```

`fail_to_proxy` 方法返回一个 `FailToProxy` 结构体，其中包含：

- `error_code`：用于日志记录的错误码
- `can_reuse_downstream`：指示是否可以重用下游（客户端）连接

### 重试和故障转移的实现

下面是一个更完整的示例，展示了如何实现重试和故障转移逻辑：

```rust
pub struct ReliableProxy {
    upstream_servers: Vec<(String, u16)>,
    max_retries: usize,
}

pub struct ProxyContext {
    retries: usize,
    failed_servers: HashSet<String>,
    start_time: std::time::Instant,
}

#[async_trait]
impl ProxyHttp for ReliableProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext {
            retries: 0,
            failed_servers: HashSet::new(),
            start_time: std::time::Instant::now(),
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // 选择一个未被标记为失败的服务器
        for &(ref host, port) in &self.upstream_servers {
            let server_key = format!("{}:{}", host, port);
            if !ctx.failed_servers.contains(&server_key) {
                info!("选择上游服务器: {}", server_key);

                let peer = Box::new(HttpPeer::new(
                    (host.clone(), port),
                    true,
                    session.req_header().uri.host().unwrap_or(host).to_string(),
                ));

                return Ok(peer);
            }
        }

        // 如果所有服务器都失败了，重置失败记录并选择第一个
        ctx.failed_servers.clear();
        let (host, port) = &self.upstream_servers[0];

        info!("所有服务器都已尝试，重新使用: {}:{}", host, port);

        let peer = Box::new(HttpPeer::new(
            (host.clone(), port.clone()),
            true,
            session.req_header().uri.host().unwrap_or(host).to_string(),
        ));

        Ok(peer)
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<e>,
    ) -> Box<e> {
        // 记录失败的服务器
        let server_key = format!("{}:{}", peer.address().host(), peer.address().port());
        ctx.failed_servers.insert(server_key.clone());

        warn!("连接到 {} 失败: {}", server_key, e);

        // 如果还有其他服务器可以尝试，标记为可重试
        if ctx.failed_servers.len() < self.upstream_servers.len() {
            info!("还有其他服务器可以尝试，标记为可重试");
            e.set_retry(true);
        } else {
            warn!("所有服务器都已尝试过，不再重试");
        }

        e
    }

    // 其他方法实现...
}
```

在这个示例中，我们：

1. 维护一个上游服务器列表
2. 在 `upstream_peer` 中选择一个未被标记为失败的服务器
3. 在 `fail_to_connect` 中记录失败的服务器并决定是否重试
4. 当所有服务器都失败时，重置失败记录并重新开始

## 总结

日志记录和错误处理是构建健壮代理服务的关键组成部分。Pingora 提供了一套全面的工具，使你能够：

1. 在 `logging` 方法中记录详细的请求信息和性能指标
2. 使用 `request_summary` 生成请求摘要
3. 通过 `suppress_error_log` 控制错误日志的生成
4. 在 `fail_to_connect` 和 `error_while_proxy` 中实现重试和故障转移逻辑
5. 在 `fail_to_proxy` 中提供自定义错误响应

通过正确实现这些方法，你可以创建一个能够优雅处理各种错误情况的高可靠性代理服务，同时收集有价值的日志和指标，以便进行监控和故障排除。
