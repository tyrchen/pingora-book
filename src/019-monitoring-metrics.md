# 监控与指标收集

在前面的章节中，我们已经探讨了 Pingora 的多种核心功能，从基本代理到高级功能如 HTTP/2 和子请求。本章将介绍如何监控 Pingora 应用的性能和健康状况，使用 Prometheus 收集指标，并将 Pingora 集成到现有的监控系统中。

## 监控的重要性

对于任何生产环境中的代理服务来说，监控都是至关重要的。良好的监控可以帮助你：

1. **检测异常**：快速发现性能下降或错误增加
2. **进行容量规划**：了解系统负载和资源利用率
3. **优化性能**：识别瓶颈并验证优化的效果
4. **验证服务级别目标（SLOs）**：确保服务符合可用性和性能标准
5. **支持故障排除**：提供问题诊断所需的数据

Pingora 提供了与 Prometheus 的内置集成，使得收集和暴露指标变得简单直接。

## Prometheus 指标服务

Pingora 内置了一个 Prometheus HTTP 指标服务，可以轻松地将其添加到你的应用中。这个服务会自动收集和暴露所有通过 Prometheus Rust 库注册的指标。

### 添加 Prometheus 指标服务

添加 Prometheus 指标服务非常简单：

```rust
use pingora::prelude::*;
use pingora_core::services::listening::Service;

fn main() -> Result<()> {
    // 创建服务器
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 添加你的主代理服务
    let proxy = MyProxy::new();
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp("0.0.0.0:8080");
    server.add_service(proxy_service);

    // 添加 Prometheus 指标服务，监听在不同的端口
    let mut prometheus_service = Service::prometheus_http_service();
    prometheus_service.add_tcp("0.0.0.0:9090");
    server.add_service(prometheus_service);

    // 启动服务器
    server.run_forever();

    Ok(())
}
```

这段代码创建了一个在端口 9090 上运行的 Prometheus 指标端点。当 Prometheus 抓取这个端点时，它会收集到所有注册的指标。

### 访问指标

一旦服务运行起来，你可以使用 HTTP 客户端来查看指标：

```bash
curl http://localhost:9090/
```

你会看到 Prometheus 格式的指标输出，类似于：

```text
# HELP req_counter Number of requests
# TYPE req_counter counter
req_counter 42
# HELP http_response_status HTTP response status codes
# TYPE http_response_status counter
http_response_status{status_code="200"} 38
http_response_status{status_code="404"} 3
http_response_status{status_code="500"} 1
# HELP http_request_duration_seconds HTTP request duration in seconds
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.005"} 5
http_request_duration_seconds_bucket{le="0.01"} 18
...
```

## 定义自定义指标

Pingora 使用 Prometheus Rust 库来定义和收集指标。你可以使用多种类型的指标来跟踪你的应用的不同方面。

### 指标类型

Prometheus 支持几种主要的指标类型：

1. **计数器 (Counter)**：只能增加，不能减少的累积指标，如请求总数
2. **仪表盘 (Gauge)**：可以上升或下降的指标，如当前活跃连接数
3. **直方图 (Histogram)**：对观察值的分布进行采样，如请求持续时间
4. **汇总 (Summary)**：类似于直方图，但可以计算百分位数

### 静态指标

最简单的使用方式是定义静态指标，这些指标在整个程序生命周期内都有效：

```rust
use once_cell::sync::Lazy;
use prometheus::{register_int_counter, register_int_gauge, register_histogram, Histogram, IntCounter, IntGauge};

// 计数器：请求总数
static REQUEST_COUNTER: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("http_requests_total", "Total number of HTTP requests received").unwrap()
});

// 仪表盘：当前活跃连接数
static ACTIVE_CONNECTIONS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("active_connections", "Number of currently active connections").unwrap()
});

// 直方图：请求处理时间
static REQUEST_DURATION: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "request_duration_seconds",
        "HTTP request duration in seconds",
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).unwrap()
});
```

### 带标签的指标

当你需要按不同维度分类指标时，可以使用带标签的指标：

```rust
use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, IntCounterVec};

// 按 HTTP 状态码和请求路径分类的响应计数
static RESPONSE_STATUS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_responses_total",
        "Total HTTP responses by status code and path",
        &["status", "path"]
    ).unwrap()
});

// 使用时：
RESPONSE_STATUS.with_label_values(&["200", "/api/users"]).inc();
```

## 在 ProxyHttp 中实现指标收集

在实际应用中，最好将指标收集逻辑集成到 `ProxyHttp` trait 的实现中。这里是一个综合示例：

```rust
use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora::prelude::*;
use prometheus::{register_histogram, register_int_counter_vec, Histogram, IntCounterVec};
use std::sync::Arc;
use std::time::Instant;

// 定义指标
static HTTP_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests",
        &["method", "path"]
    )
    .unwrap()
});

static HTTP_RESPONSE_STATUS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_response_status",
        "HTTP response status codes",
        &["status_code"]
    )
    .unwrap()
});

static HTTP_UPSTREAM_ERRORS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_upstream_errors",
        "Errors when connecting to or proxying to upstream",
        &["error_type"]
    )
    .unwrap()
});

static HTTP_REQUEST_DURATION: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap()
});

// 定义上下文，存储指标相关信息
struct MetricsContext {
    start_time: Instant,
}

// 实现 ProxyHttp
struct MetricsProxy;

#[async_trait]
impl ProxyHttp for MetricsProxy {
    type CTX = MetricsContext;

    fn new_ctx(&self) -> Self::CTX {
        MetricsContext {
            start_time: Instant::now(),
        }
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // 计算请求路径和方法
        let path = session.req_header().uri.path();
        let method = &session.req_header().method;

        // 增加请求计数
        HTTP_REQUESTS
            .with_label_values(&[method, path])
            .inc();

        Ok(false) // 继续处理请求
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // 创建上游对等点...
        let peer = Box::new(HttpPeer::new(
            ("example.com", 443),
            true,
            "example.com".to_string(),
        ));

        Ok(peer)
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 记录响应状态码
        if let Some(resp) = session.resp_header() {
            let status = resp.status.as_str();
            HTTP_RESPONSE_STATUS.with_label_values(&[status]).inc();
        }

        Ok(())
    }

    async fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        // 记录连接错误
        HTTP_UPSTREAM_ERRORS
            .with_label_values(&["connect_error"])
            .inc();

        e
    }

    async fn error_while_proxy(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        // 记录代理错误
        HTTP_UPSTREAM_ERRORS
            .with_label_values(&["proxy_error"])
            .inc();

        e
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&Error>, ctx: &mut Self::CTX) {
        // 计算请求持续时间
        let duration = ctx.start_time.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION.observe(duration);
    }
}
```

### 关键的监控点

在 Pingora 代理中，以下是需要监控的关键点：

1. **请求接收（request_filter）**：记录传入请求数量和类型
2. **上游连接（fail_to_connect）**：监控连接失败
3. **代理过程（error_while_proxy）**：跟踪代理过程中的错误
4. **响应处理（response_filter）**：记录响应状态和类型
5. **请求完成（logging）**：测量端到端延迟和完成指标

## 指标收集最佳实践

### 选择合适的指标

在设计监控时，选择有意义的指标至关重要：

1. **常见的 HTTP 指标**：
   - 请求总数
   - 按状态码分类的响应计数
   - 请求处理时间
   - 错误率

2. **代理特定指标**：
   - 上游连接错误数
   - 上游响应时间
   - 缓存命中/未命中率
   - 连接池使用情况

3. **系统资源指标**：
   - CPU 使用率
   - 内存使用
   - 网络流量
   - 打开的文件描述符数

### 指标命名和标签约定

遵循这些约定可使你的指标更易于理解和使用：

1. **命名约定**：
   - 使用下划线分隔的命名，如 `http_requests_total`
   - 包含单位，如 `request_duration_seconds`
   - 对计数器使用 `_total` 后缀

2. **标签选择**：
   - 使用有意义的标签来分类数据，如 `method`、`status_code`、`path`
   - 避免基数太高的标签（如唯一 ID）
   - 确保标签值是有限的集合

### 将 Prometheus 与可视化工具集成

Prometheus 数据通常通过 Grafana 等工具进行可视化：

1. **创建 Grafana 仪表板**：
   - 为 HTTP 流量、错误率、延迟创建图表
   - 设置阈值和警报

2. **示例 PromQL 查询**：
   - 请求率：`rate(http_requests_total[5m])`
   - 错误率：`sum(rate(http_response_status{status_code=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))`
   - 95 百分位延迟：`histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))`

### 完整示例：带有指标的 Pingora 服务

以下是一个完整的示例，展示了如何创建具有全面监控的 Pingora 服务：

```rust
use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora::prelude::*;
use prometheus::{register_histogram, register_int_counter_vec, Histogram, IntCounterVec};
use std::sync::Arc;
use std::time::Instant;

// 定义指标
static HTTP_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests",
        &["method", "path"]
    )
    .unwrap()
});

static HTTP_RESPONSE_STATUS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_response_status",
        "HTTP response status codes",
        &["status_code"]
    )
    .unwrap()
});

static HTTP_REQUEST_DURATION: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap()
});

// 定义上下文和代理
struct MetricsContext {
    start_time: Instant,
    path: String,
    method: String,
}

struct MonitoredProxy;

#[async_trait]
impl ProxyHttp for MonitoredProxy {
    type CTX = MetricsContext;

    fn new_ctx(&self) -> Self::CTX {
        MetricsContext {
            start_time: Instant::now(),
            path: String::new(),
            method: String::new(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // 提取并存储请求信息
        ctx.path = session.req_header().uri.path().to_string();
        ctx.method = session.req_header().method.clone();

        // 记录请求
        HTTP_REQUESTS
            .with_label_values(&[&ctx.method, &ctx.path])
            .inc();

        Ok(false)
    }

    async fn response_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
        // 记录响应状态码
        if let Some(resp) = session.resp_header() {
            let status = resp.status.as_str();
            HTTP_RESPONSE_STATUS.with_label_values(&[status]).inc();
        }

        Ok(())
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&Error>, ctx: &mut Self::CTX) {
        // 记录请求持续时间
        let duration = ctx.start_time.elapsed().as_secs_f64();
        HTTP_REQUEST_DURATION.observe(duration);
    }

    // 其他必要的方法实现...
    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            ("example.com", 443),
            true,
            "example.com".to_string(),
        ));
        Ok(peer)
    }
}

fn main() -> Result<()> {
    // 初始化日志
    env_logger::init();

    // 创建服务器
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务
    let proxy = MonitoredProxy;
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp("0.0.0.0:8080");
    server.add_service(proxy_service);

    // 添加 Prometheus 指标服务
    let mut prometheus_service = Service::prometheus_http_service();
    prometheus_service.add_tcp("0.0.0.0:9090");
    server.add_service(prometheus_service);

    // 启动服务器
    println!("Monitored proxy running on 0.0.0.0:8080");
    println!("Prometheus metrics available on 0.0.0.0:9090");
    server.run_forever();

    Ok(())
}
```

## 告警和监控最佳实践

除了收集指标外，设置告警也很重要，以便在问题发生时得到通知：

1. **定义关键 SLIs 和 SLOs**：
   - 服务可用性（成功率）
   - 延迟阈值（P95 < 500ms）
   - 错误率（< 0.1%）

2. **设置多级告警**：
   - 警告级别：接近但未违反 SLO
   - 严重级别：违反 SLO 或关键错误

3. **避免告警疲劳**：
   - 设置适当的阈值和持续时间
   - 分组相关告警
   - 实施静默期

## 总结

本章介绍了如何使用 Prometheus 监控 Pingora 应用。通过内置的 Prometheus 服务和自定义指标，你可以全面了解应用的性能和健康状况。合理的监控对于生产环境中的代理服务至关重要，可以帮助你检测问题、优化性能并确保服务质量。

通过遵循本章介绍的最佳实践，你可以创建一个稳健的监控系统，使你的 Pingora 应用在生产环境中更加可靠和高效。
