# Pingora 应用的调试方法与工具

在开发 Pingora 应用的过程中，我们不可避免地会遇到各种问题，从逻辑错误到性能瓶颈。本章将介绍一系列有效的调试方法和工具，帮助开发者快速定位和解决 Pingora 应用中的问题。

## Pingora 调试的特殊挑战

Pingora 应用通常是高性能、多线程的网络服务，这给调试带来了一些特殊的挑战：

1. **异步和并发**：Pingora 基于 Tokio 的异步运行时，调试异步代码可能比同步代码更复杂。
2. **分布式请求流程**：请求经过多个处理阶段和回调函数，错误可能在任何阶段发生。
3. **高并发负载**：在高负载下出现的问题可能在开发环境中难以重现。
4. **性能敏感**：调试工具本身可能影响性能，导致某些问题难以观察。

针对这些挑战，我们需要采用专门的调试策略和工具。

## 日志记录与分析

日志是调试 Pingora 应用的首要工具。Pingora 使用 Rust 的 `log` 生态系统，可以与多种日志后端集成。

### 配置日志级别

通过环境变量 `RUST_LOG` 可以控制日志级别：

```bash
# 只显示错误日志
RUST_LOG=error cargo run

# 显示 Pingora 组件的 debug 日志，其他组件显示 info 日志
RUST_LOG=info,pingora=debug cargo run

# 显示所有 debug 日志，但过滤掉过于详细的 tokio 调度器日志
RUST_LOG=debug,tokio=info cargo run

# 针对特定模块设置更详细的日志级别
RUST_LOG=info,pingora::proxy::http=trace cargo run
```

### 自定义日志记录

在 Pingora 应用中，可以在关键位置添加自定义日志：

```rust
impl ProxyHttp for MyProxy {
    // ...

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut MyContext) -> Result<Box<HttpPeer>> {
        // 记录请求信息
        let uri = session.req_header().uri();
        let path = uri.path();
        let method = session.req_header().method();

        log::debug!("Selecting peer for {} {}", method, path);

        // ... 选择上游服务器的逻辑

        log::debug!("Selected peer: {:?}", peer_addr);

        // ... 创建并返回 HttpPeer
    }

    // ...
}
```

### 结构化日志

对于更复杂的场景，考虑使用结构化日志：

```rust
use serde_json::json;

// ...

log::info!("{}", json!({
    "event": "upstream_selected",
    "request_id": ctx.request_id,
    "path": session.req_header().uri().path(),
    "upstream": peer_addr,
    "timing_ms": start_time.elapsed().as_millis()
}));
```

这样的日志更易于后续的自动化分析。

## 使用 request_summary 跟踪请求

Pingora 的 `ProxyHttp` trait 提供了 `request_summary` 方法，可以用来记录请求的摘要信息：

```rust
fn request_summary(&self, session: &Session, ctx: &Self::CTX) -> String {
    let uri = session.req_header().uri();
    let peer_info = session.upstream_info()
        .map(|p| format!("{}", p.addr().unwrap_or_else(|| "unknown".to_string())))
        .unwrap_or_else(|| "none".to_string());

    let status = session.resp_header()
        .map(|h| h.status.as_u16())
        .unwrap_or(0);

    // 记录请求路径、状态码、上游服务器、处理时间等
    format!(
        "path={} status={} upstream={} duration_ms={} cache_status={}",
        uri.path(),
        status,
        peer_info,
        ctx.timing.elapsed().as_millis(),
        ctx.cache_status.as_str()
    )
}
```

此方法的返回值会被记录到日志中，为每个请求提供了一个简洁的摘要。

## 请求追踪与分析

### 请求 ID 和关联日志

为每个请求分配一个唯一的请求 ID，并在所有日志中包含这个 ID：

```rust
impl ProxyHttp for MyProxy {
    type CTX = MyContext;

    fn new_ctx(&self) -> Self::CTX {
        MyContext {
            request_id: format!("{:x}", rand::random::<u64>()),
            // ... 其他字段
        }
    }

    // ... 其他方法
}

// 在所有日志中包含请求 ID
log::debug!("[req:{}] Selecting peer", ctx.request_id);
```

这样可以轻松地关联属于同一请求的所有日志条目。

### 计时点和性能分析

在请求处理的关键阶段添加计时点：

```rust
impl ProxyHttp for MyProxy {
    // ...

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut MyContext) -> Result<Box<HttpPeer>> {
        let start = std::time::Instant::now();

        // ... 选择上游服务器的逻辑

        let duration = start.elapsed();
        log::debug!("[req:{}] Peer selection took {:?}", ctx.request_id, duration);

        // ... 返回结果
    }

    // ...
}
```

### 提取和分析请求与响应

在调试过程中，经常需要检查请求和响应的详细内容：

```rust
async fn request_filter(
    &self,
    session: &mut Session,
    ctx: &mut Self::CTX
) -> Result<bool> {
    // 提取和记录请求头
    let req = session.req_header();
    log::debug!("[req:{}] Method: {}, Path: {}",
               ctx.request_id, req.method(), req.uri().path());

    // 提取和记录请求头
    for (name, value) in req.headers.iter() {
        log::trace!("[req:{}] Header: {}: {}",
                  ctx.request_id, name, value.to_str().unwrap_or("(invalid)"));
    }

    // ... 继续处理请求

    Ok(true) // 继续处理请求
}
```

对于响应也可以采用类似的方法。

## 使用环境变量控制调试行为

创建特定的环境变量来控制调试功能：

```rust
// 检查是否启用了调试模式
let debug_mode = std::env::var("MY_PROXY_DEBUG").is_ok();

if debug_mode {
    // 记录更详细的信息
    log::info!("Full request body: {:?}", body_bytes);

    // 可能启用更多的检查或验证
    validate_request_structure(req)?;
}
```

这允许开发者在不修改代码的情况下启用额外的调试信息。

## 集成调试工具

### HTTP 调试端点

添加特殊的 HTTP 端点来暴露内部状态或调试信息：

```rust
async fn request_filter(
    &self,
    session: &mut Session,
    ctx: &mut Self::CTX
) -> Result<bool> {
    let path = session.req_header().uri().path();

    // 特殊的调试端点
    if path == "/_debug/status" {
        // 检查认证
        if !self.is_debug_authorized(session) {
            session.respond_error(StatusCode::UNAUTHORIZED)?;
            return Ok(false);
        }

        // 收集调试信息
        let debug_info = self.collect_debug_info().await?;

        // 构建响应
        let body = serde_json::to_string_pretty(&debug_info)?;
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(())?;

        session.respond(&resp, Some(body.as_bytes()))?;
        return Ok(false);
    }

    // ... 常规请求处理

    Ok(true)
}
```

### 实时配置调整

Pingora 允许通过 HTTP 端点动态调整配置，这对调试非常有用：

```rust
// 定义配置结构体
struct DebugConfig {
    verbose_logging: AtomicBool,
    sample_rate: AtomicUsize,
    // ... 其他可调整的参数
}

// 在服务中设置一个端点来调整这些配置
async fn handle_config_update(&self, session: &mut Session) -> Result<()> {
    // 解析请求体获取新配置
    let body = read_body(session).await?;
    let new_config: serde_json::Value = serde_json::from_slice(&body)?;

    // 应用新配置
    if let Some(verbose) = new_config.get("verbose_logging") {
        if let Some(value) = verbose.as_bool() {
            self.config.verbose_logging.store(value, Ordering::Relaxed);
        }
    }

    // ... 更新其他配置参数

    // 返回当前配置
    let current = self.get_current_config();
    let resp_body = serde_json::to_string_pretty(&current)?;

    // ... 发送响应

    Ok(())
}
```

## 调试工具集成

### 使用 Prometheus 进行指标监控

Pingora 可以与 Prometheus 集成，提供详细的性能指标：

```rust
use prometheus::{register_counter, register_histogram, Counter, Histogram};
use std::sync::Mutex;
use once_cell::sync::Lazy;

// 定义全局指标
static REQUEST_COUNTER: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "my_proxy_requests_total",
        "Total number of requests processed"
    ).unwrap()
});

static REQUEST_DURATION: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "my_proxy_request_duration_seconds",
        "Request processing duration in seconds",
        vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    ).unwrap()
});

// 在请求处理中更新指标
impl ProxyHttp for MyProxy {
    // ...

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // 记录请求开始时间
        ctx.start_time = Some(std::time::Instant::now());

        // 增加请求计数
        REQUEST_COUNTER.inc();

        // ... 处理请求

        Ok(true)
    }

    fn logging(&self, session: &Session, ctx: &Self::CTX) {
        // 记录请求处理时间
        if let Some(start_time) = ctx.start_time {
            let duration = start_time.elapsed().as_secs_f64();
            REQUEST_DURATION.observe(duration);
        }

        // ... 其他日志记录
    }

    // ...
}
```

然后添加一个 HTTP 端点来暴露 Prometheus 指标：

```rust
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    let path = session.req_header().uri().path();

    // Prometheus 指标端点
    if path == "/metrics" {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&prometheus::gather(), &mut buffer)?;

        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", encoder.format_type())
            .body(())?;

        session.respond(&resp, Some(&buffer))?;
        return Ok(false);
    }

    // ... 处理常规请求

    Ok(true)
}
```

### 与分布式追踪系统集成

Pingora 可以集成 OpenTelemetry 等分布式追踪系统：

```rust
use opentelemetry::trace::{Tracer, Span};
use opentelemetry::global;

// ... 在应用启动时初始化 OpenTelemetry

impl ProxyHttp for MyProxy {
    // ...

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // 为请求创建 span
        let tracer = global::tracer("my_proxy");
        let mut span = tracer.start("request");

        // 记录请求信息
        span.set_attribute("http.method", session.req_header().method().to_string());
        span.set_attribute("http.path", session.req_header().uri().path().to_string());

        // 保存 span 在上下文中
        ctx.span = Some(span);

        // ... 处理请求

        Ok(true)
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // 创建子 span
        let mut span = if let Some(parent) = &ctx.span {
            parent.create_child("upstream_selection")
        } else {
            global::tracer("my_proxy").start("upstream_selection")
        };

        // ... 选择上游服务器

        // 记录选择的上游服务器
        span.set_attribute("upstream.addr", peer_addr.to_string());

        // 结束子 span
        drop(span);

        // ... 返回 HttpPeer
    }

    // ... 在其他方法中也可以创建和记录 span

    fn logging(&self, session: &Session, ctx: &Self::CTX) {
        // 结束主 span
        if let Some(span) = &ctx.span {
            // 记录最终状态
            if let Some(resp) = session.resp_header() {
                span.set_attribute("http.status_code", resp.status.as_u16() as i64);
            }

            // span 会在这里被自动结束（当它被 drop 时）
        }

        // ... 其他日志记录
    }
}
```

## 专用调试构建

有时可能需要创建专用的调试构建，包含额外的检查和验证：

```rust
// 在 Cargo.toml 中添加 feature
// [features]
// debug_validation = []

#[cfg(feature = "debug_validation")]
fn validate_request(session: &Session) -> Result<()> {
    // 执行额外的验证
    if let Some(content_length) = session.req_header().headers.get("content-length") {
        // 确保 content-length 是有效的数字
        if content_length.to_str().ok().and_then(|s| s.parse::<usize>().ok()).is_none() {
            return Err(pingora::Error::user("Invalid Content-Length header"));
        }
    }

    // ... 其他验证

    Ok(())
}

#[cfg(not(feature = "debug_validation"))]
fn validate_request(_session: &Session) -> Result<()> {
    // 在非调试构建中不执行额外的验证
    Ok(())
}

// 在代码中使用
async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    // 调用验证函数
    validate_request(session)?;

    // ... 继续处理请求

    Ok(true)
}
```

然后可以使用以下命令构建调试版本：

```bash
cargo run --features debug_validation
```

## 调试常见问题的策略

### 1. 处理连接问题

```rust
async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
    // ... 选择上游服务器

    // 添加更多日志来帮助调试连接问题
    log::debug!("Connecting to upstream: {}, TLS: {}, SNI: {}",
               peer_addr, use_tls, sni);

    // ... 创建 HttpPeer
}

async fn fail_to_connect(
    &self,
    session: &mut Session,
    upstream_addr: &str,
    error: &pingora::Error,
    ctx: &mut Self::CTX,
) -> Option<Box<HttpPeer>> {
    // 详细记录连接失败
    log::error!("[req:{}] Failed to connect to {}: {:?}",
               ctx.request_id, upstream_addr, error);

    // 记录网络信息和客户端信息
    if let Some(client_ip) = session.peer_ip() {
        log::debug!("[req:{}] Client IP: {}", ctx.request_id, client_ip);
    }

    // ... 故障转移逻辑

    None
}
```

### 2. 调试请求/响应体问题

```rust
async fn request_body_filter(
    &self,
    session: &mut Session,
    chunk: Bytes,
    ctx: &mut Self::CTX,
) -> Result<Bytes> {
    // 在调试模式下记录请求体
    if self.config.debug_mode.load(Ordering::Relaxed) {
        ctx.body_size += chunk.len();

        // 限制记录的大小以避免日志过大
        if ctx.body_size <= 1024 {
            // 尝试记录为文本
            match std::str::from_utf8(&chunk) {
                Ok(text) => log::debug!("[req:{}] Request body chunk: {}", ctx.request_id, text),
                Err(_) => log::debug!("[req:{}] Request body chunk (binary): {:?}", ctx.request_id, &chunk[..chunk.len().min(64)]),
            }
        } else if ctx.body_size - chunk.len() < 1024 {
            // 超过大小限制，只记录一次
            log::debug!("[req:{}] Request body exceeds debug log limit (1KB)", ctx.request_id);
        }
    }

    // ... 处理请求体

    Ok(chunk)
}
```

### 3. 处理超时问题

```rust
// 为上游请求设置诊断计时器
async fn upstream_request_filter(
    &self,
    session: &mut Session,
    upstream_request: &mut http::request::Parts,
    ctx: &mut Self::CTX,
) -> Result<bool> {
    // 设置诊断计时器
    let request_id = ctx.request_id.clone();
    let uri = upstream_request.uri.clone();

    tokio::spawn(async move {
        let checkpoints = [5, 10, 30];
        let mut elapsed_secs = 0;

        for checkpoint in checkpoints {
            tokio::time::sleep(tokio::time::Duration::from_secs(checkpoint - elapsed_secs)).await;
            elapsed_secs = checkpoint;

            log::warn!("[req:{}] Request to {} has been pending for {}s",
                      request_id, uri, elapsed_secs);
        }
    });

    // ... 继续处理请求

    Ok(true)
}
```

### 4. 检测和处理内存泄漏

```rust
// 周期性记录内存使用情况
fn start_memory_monitor(interval_secs: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            #[cfg(target_os = "linux")]
            {
                use std::io::Read;

                // 读取 /proc/self/status 获取内存信息
                if let Ok(mut file) = std::fs::File::open("/proc/self/status") {
                    let mut content = String::new();
                    if file.read_to_string(&mut content).is_ok() {
                        for line in content.lines() {
                            if line.starts_with("VmRSS:") ||
                               line.starts_with("VmSize:") ||
                               line.starts_with("VmPeak:") {
                                log::info!("Memory: {}", line.trim());
                            }
                        }
                    }
                }
            }
        }
    });
}
```

## 使用外部调试工具

除了内置的调试功能，还可以使用一些外部工具来辅助调试 Pingora 应用：

### 1. tcpdump/Wireshark

对于网络层面的问题，可以使用 tcpdump 捕获网络流量，然后用 Wireshark 分析：

```bash
# 捕获特定端口的流量
sudo tcpdump -i any -w capture.pcap port 8080

# 捕获与特定主机的通信
sudo tcpdump -i any -w capture.pcap host 10.0.0.1
```

### 2. strace/perf

对于系统调用和性能问题，可以使用 strace 或 perf 工具：

```bash
# 追踪系统调用
strace -f -p <pid>

# 性能分析
perf record -p <pid> -g
perf report
```

### 3. curl 调试模式

使用 curl 的详细输出模式测试 HTTP 请求：

```bash
# 详细输出
curl -v http://localhost:8080/test

# 查看完整 HTTP 头和计时信息
curl -v --trace-time http://localhost:8080/test
```

### 4. hey/wrk 进行负载测试

使用负载测试工具来检测高并发下的问题：

```bash
# 使用 hey 进行测试
hey -n 1000 -c 100 http://localhost:8080/test

# 使用 wrk 进行测试
wrk -t12 -c400 -d30s http://localhost:8080/test
```

## 常见调试场景与解决方案

### 场景一：请求未到达上游服务器

检查点:

1. 查看日志中是否有连接错误
2. 检查 DNS 解析是否正确
3. 验证网络连接和防火墙规则
4. 检查 TLS 配置（如果使用 HTTPS）

### 场景二：响应状态码异常

检查点:

1. 检查请求是否被正确转发
2. 查看请求头是否被正确设置
3. 检查上游服务器日志
4. 验证上游服务器的响应是否被修改

### 场景三：性能问题

检查点:

1. 检查各阶段的处理时间
2. 监控 CPU 和内存使用情况
3. 分析连接池配置
4. 检查 I/O 和网络延迟

### 场景四：内存泄漏

检查点:

1. 监控内存使用趋势
2. 检查长时间运行的异步任务
3. 确保资源在不需要时被正确释放
4. 使用内存分析工具定位泄漏

## 总结

调试 Pingora 应用需要综合运用多种工具和技术。通过本章介绍的方法，开发者可以更有效地:

1. 设置详细和有针对性的日志
2. 使用请求跟踪和性能指标进行监控
3. 集成专业的调试和监控工具
4. 针对特定问题采用有效的调试策略

良好的调试实践不仅有助于解决当前的问题，还能提高代码质量，避免未来出现类似问题。在 Pingora 这样的高性能代理环境中，掌握高效的调试技术尤为重要。
