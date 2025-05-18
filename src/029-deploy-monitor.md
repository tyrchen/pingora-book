# 部署与监控

将 Pingora 服务部署到生产环境需要仔细考虑系统配置、安全加固和监控策略。本章将探讨 Pingora 服务的生产环境部署最佳实践，以及如何有效监控其性能和资源使用情况。

## 生产环境部署准备

### 系统要求

Pingora 对系统配置有一些基本要求：

- **操作系统**：Linux 是一级支持环境（推荐 Ubuntu 20.04+ 或 CentOS 8+）
- **架构**：支持 x86_64 和 aarch64
- **Rust 版本**：至少使用 MSRV（最低支持的 Rust 版本，目前为 1.82）
- **内存**：根据预期流量和使用的功能（如缓存大小）调整，通常建议至少 2GB
- **CPU**：多核处理器，核心数量取决于预期的并发连接数

### 预发布检查清单

在生产环境部署前，请完成以下检查：

1. **功能测试**：确保所有功能按预期工作
2. **性能测试**：在类似生产环境的条件下进行负载测试
3. **内存泄漏检查**：长时间运行测试以确保没有内存泄漏
4. **错误处理测试**：测试各种错误情况的处理
5. **配置验证**：验证所有配置参数是否正确
6. **日志输出验证**：确保日志配置适合生产环境

## 生产环境系统配置

### 操作系统优化

#### 文件描述符限制

Pingora 作为代理服务器会打开大量连接，需要调整系统的文件描述符限制：

```bash
# 在 /etc/security/limits.conf 中添加
pingora_user soft nofile 65536
pingora_user hard nofile 131072

# 检查系统全局限制
sysctl -w fs.file-max=2097152
```

#### 网络调优

```bash
# 增加本地端口范围
sysctl -w net.ipv4.ip_local_port_range="10000 65535"

# 启用 TCP Fast Open
sysctl -w net.ipv4.tcp_fastopen=3

# 调整 TCP keepalive 设置
sysctl -w net.ipv4.tcp_keepalive_time=60
sysctl -w net.ipv4.tcp_keepalive_intvl=10
sysctl -w net.ipv4.tcp_keepalive_probes=6

# 启用 TCP BBR 拥塞控制算法（Linux 4.9+）
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr

# 增加连接队列大小
sysctl -w net.core.somaxconn=32768
sysctl -w net.ipv4.tcp_max_syn_backlog=16384
```

#### 内存管理

```bash
# 禁用透明大页面（可能导致延迟波动）
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag

# 调整 swappiness（减少交换使用）
sysctl -w vm.swappiness=10
```

### 编译优化

在生产环境中，应该使用 release 模式编译 Pingora，并启用适当的优化：

```bash
# 在 Cargo.toml 中添加以下部分：
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
panic = "abort"  # 可选，减小二进制大小
```

编译命令：

```bash
cargo build --release
```

## 安全加固措施

### 权限控制

1. **创建专用用户**：为 Pingora 服务创建一个专用的低权限用户：

```bash
sudo useradd -r -s /sbin/nologin pingora
```

2. **使用 systemd 限制权限**：

```ini
[Service]
User=pingora
Group=pingora
# 限制系统调用
SystemCallFilter=@system-service
# 禁止提升权限
NoNewPrivileges=true
# 限制目录访问
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/pingora /var/log/pingora
```

### TLS 加固

1. **使用强密码套件**：

```rust
let mut tls_settings = pingora_core::listeners::tls::TlsSettings::intermediate(
    "/path/to/cert.pem",
    "/path/to/key.pem",
).unwrap();

// 设置现代密码套件
tls_settings.set_ciphers("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

// 最小 TLS 版本设置为 1.2
tls_settings.set_min_proto_version(Some(4)); // TLS 1.2
```

2. **证书管理**：
   - 使用自动更新证书的工具（如 certbot）
   - 实现证书轮换机制，避免证书过期导致服务中断
   - 定期检查证书有效性

### 网络安全

1. **防火墙配置**：

```bash
# 只开放必要端口
ufw allow 80/tcp
ufw allow 443/tcp
# 如有管理端口，限制访问源
ufw allow from 10.0.0.0/8 to any port 8080
```

2. **DDoS 防护**：

```bash
# 限制单一 IP 连接数
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j DROP

# 使用 fail2ban 对可疑 IP 进行自动封禁
apt install fail2ban
```

3. **实现速率限制**：

```rust
// 在代理中实现基于 IP 的速率限制
use pingora_limits::RateLimiter;

let mut rate_limiter = RateLimiter::new(100); // 每 IP 每秒 100 个请求
let client_ip = session.client_addr().unwrap().ip();

if !rate_limiter.check_key(&client_ip.to_string()) {
    session.respond_error(429).await?;
    return Ok(true);
}
```

### 配置安全

1. **保护敏感配置**：
   - 使用环境变量或安全存储服务保存密钥和证书密码
   - 限制配置文件的访问权限
   - 对配置文件中的敏感信息进行加密

2. **配置验证**：
   - 部署前对配置进行自动验证
   - 使用版本控制管理配置变更
   - 实现配置更改的审计日志

## 部署策略

### 容器化部署

使用 Docker 容器部署 Pingora 可以提供环境一致性和简化部署流程：

1. **Dockerfile 示例**：

```dockerfile
FROM rust:1.82 as builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/my-pingora-app /usr/local/bin/
COPY config /etc/pingora/
EXPOSE 80 443
CMD ["my-pingora-app", "-c", "/etc/pingora/config.yaml"]
```

2. **Docker Compose 配置**：

```yaml
version: '3'

services:
  pingora:
    build: .
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config:/etc/pingora
      - ./logs:/var/log/pingora
    environment:
      - RUST_LOG=info
    restart: always
    sysctls:
      - net.core.somaxconn=32768
    ulimits:
      nofile:
        soft: 65536
        hard: 131072
```

### Kubernetes 部署

在 Kubernetes 中部署 Pingora：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pingora-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pingora
  template:
    metadata:
      labels:
        app: pingora
    spec:
      containers:
      - name: pingora
        image: your-registry/pingora:latest
        ports:
        - containerPort: 80
        - containerPort: 443
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
          requests:
            cpu: "1"
            memory: "2Gi"
        volumeMounts:
        - name: config
          mountPath: /etc/pingora
        - name: logs
          mountPath: /var/log/pingora
        env:
        - name: RUST_LOG
          value: "info"
        securityContext:
          capabilities:
            add: ["NET_BIND_SERVICE"]
      volumes:
      - name: config
        configMap:
          name: pingora-config
      - name: logs
        emptyDir: {}
```

### 使用 systemd 管理服务

在传统部署中，使用 systemd 管理 Pingora 服务：

```ini
[Unit]
Description=Pingora Proxy Service
After=network.target

[Service]
Type=simple
User=pingora
Group=pingora
ExecStart=/usr/local/bin/my-pingora-app -c /etc/pingora/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=131072
Environment="RUST_LOG=info"

# 安全增强
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/pingora /var/lib/pingora
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true

[Install]
WantedBy=multi-user.target
```

### 零停机部署

实现零停机部署更新：

1. **使用 Pingora 的优雅关闭功能**：

```rust
// 在应用中捕获 SIGTERM 信号
use tokio::signal::unix::{signal, SignalKind};

let mut term_signal = signal(SignalKind::terminate()).unwrap();
tokio::spawn(async move {
    term_signal.recv().await;
    println!("SIGTERM received, shutting down gracefully...");
    // 通知 Pingora 服务器停止接受新连接但处理完现有请求
    server.shutdown();
});
```

2. **在部署脚本中实现滚动更新**：

```bash
#!/bin/bash
# 假设我们有两个实例 pingora1 和 pingora2

# 更新第一个实例
systemctl stop pingora1
cp /path/to/new/binary /usr/local/bin/pingora1
systemctl start pingora1

# 等待第一个实例完全启动
sleep 10

# 更新第二个实例
systemctl stop pingora2
cp /path/to/new/binary /usr/local/bin/pingora2
systemctl start pingora2
```

## 监控 Pingora 服务

### 关键指标

有效监控 Pingora 服务需要关注以下关键指标：

1. **请求指标**：
   - 请求速率（RPS）
   - 响应时间（平均值、95 百分位、99 百分位）
   - 状态码分布
   - 错误率

2. **连接指标**：
   - 活跃连接数
   - 连接建立率
   - 连接错误率
   - 连接池使用率

3. **系统资源指标**：
   - CPU 使用率
   - 内存使用率
   - 网络流量
   - 文件描述符使用量

4. **缓存指标**（如果使用）：
   - 缓存命中率
   - 缓存大小
   - 缓存逐出率
   - 缓存 TTL 分布

### 使用 Prometheus 收集指标

Pingora 可以轻松集成 Prometheus 来收集指标：

```rust
use std::sync::Arc;
use prometheus::{register_counter, register_histogram, Counter, Histogram, HistogramOpts};
use lazy_static::lazy_static;

lazy_static! {
    static ref REQUEST_COUNTER: Counter = register_counter!(
        "pingora_requests_total",
        "Total number of processed requests"
    ).unwrap();

    static ref RESPONSE_TIME: Histogram = register_histogram!(
        "pingora_response_time_seconds",
        "Request response time in seconds",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).unwrap();
}

pub struct MyMetricsProxy {
    // ... 其他字段
}

#[async_trait]
impl ProxyHttp for MyMetricsProxy {
    // ... 其他方法

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        // 增加请求计数
        REQUEST_COUNTER.inc();

        // 记录响应时间
        if let Some(start_time) = ctx.start_time {
            let duration = start_time.elapsed().as_secs_f64();
            RESPONSE_TIME.observe(duration);
        }

        // ... 其他日志记录逻辑
    }
}

// 暴露 Prometheus 指标端点
fn main() {
    // ... 初始化 Pingora 服务器

    // 创建 Prometheus 指标 HTTP 服务
    let metrics_app = HttpMetricsExposer::new();
    let mut metrics_server = Server::new(None).unwrap();
    metrics_server.bootstrap();

    let metrics_service = Service::new(
        "metrics".to_string(),
        Arc::new(metrics_app),
    );
    metrics_service.add_tcp_listener("127.0.0.1:9091".parse().unwrap());
    metrics_server.add_service(metrics_service);

    // 启动主服务和指标服务
    tokio::spawn(async move {
        metrics_server.run_forever();
    });

    server.run_forever();
}

// 实现指标暴露 HTTP 应用
struct HttpMetricsExposer;

#[async_trait]
impl ServeHttp for HttpMetricsExposer {
    async fn response(&self, _: &mut ServerSession) -> Response<Vec<u8>> {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body(buffer)
            .unwrap()
    }
}
```

### 使用 Grafana 可视化

使用 Prometheus 和 Grafana 创建仪表板：

1. **Prometheus 配置**：

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'pingora'
    static_configs:
      - targets: ['pingora-host:9091']
```

2. **Grafana 仪表板示例**：

创建一个包含以下面板的仪表板：

- 请求速率图表
- 响应时间分布热图
- 状态码分布饼图
- 错误率图表
- 活跃连接数图表
- 系统资源使用率图表
- 缓存命中率图表

### 报警设置

设置关键指标的报警阈值：

1. **请求相关警报**：
   - 错误率超过 1%
   - 95% 响应时间超过 500ms
   - 5xx 错误率超过 0.1%

2. **资源相关警报**：
   - CPU 使用率持续超过 80%
   - 内存使用率超过 90%
   - 文件描述符使用量超过 80%

3. **可用性警报**：
   - 服务实例数量不足
   - 健康检查失败

使用 Prometheus AlertManager 配置：

```yaml
groups:
- name: pingora-alerts
  rules:
  - alert: HighErrorRate
    expr: sum(rate(pingora_requests_total{status=~"5.."}[5m])) / sum(rate(pingora_requests_total[5m])) > 0.01
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High error rate (> 1%)"
      description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"

  - alert: SlowResponses
    expr: histogram_quantile(0.95, sum(rate(pingora_response_time_seconds_bucket[5m])) by (le)) > 0.5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Slow responses (95th percentile > 500ms)"
      description: "95th percentile response time is {{ $value }} seconds for the last 5 minutes"
```

## 性能分析与优化

当 Pingora 应用出现性能瓶颈或内存泄漏时，可以采取以下步骤进行分析和优化：

### 性能分析工具

1. **perf**：Linux 性能分析工具

```bash
# 收集 CPU 性能数据
perf record -F 99 -p $(pgrep my-pingora-app) -g -- sleep 30

# 分析数据
perf report
```

2. **flamegraph**：可视化性能热点

```bash
# 安装 flamegraph 工具
cargo install flamegraph

# 生成火焰图
cargo flamegraph --bin my-pingora-app
```

3. **JEMALLOC 分析**：通过 JEMALLOC 分析内存使用

```bash
# 启用 JEMALLOC 分析
export MALLOC_CONF="prof:true,prof_prefix:jeprof.out"

# 运行应用后分析内存使用
jeprof --pdf /path/to/my-pingora-app jeprof.out.0 > memory_profile.pdf
```

### 常见性能瓶颈及解决方案

1. **连接建立开销**：
   - 增加连接池大小
   - 增加连接的 keepalive 时间
   - 配置代码示例：

```rust
let mut peer = Box::new(HttpPeer::new(
    (upstream_host, upstream_port),
    use_tls,
    sni.to_string(),
));

// 配置连接池大小
peer.options.connection_pool_max_idle = 100;

// 配置 keepalive 时间
peer.options.keepalive_timeout = Some(Duration::from_secs(60));
```

2. **高 CPU 使用率**：
   - 优化请求处理逻辑
   - 实现智能缓存
   - 添加业务逻辑分析代码

3. **内存泄漏**：
   - 检查应用中的资源释放
   - 监控并分析内存使用增长模式
   - 查找未关闭的句柄和连接

### 调整 Pingora 工作线程

根据服务器 CPU 核心数调整工作线程数量：

```rust
let mut server = Server::new(opt).unwrap();

// 设置工作线程数，通常设置为 CPU 核心数的 1-2 倍
server.setup(num_cpu::get() * 2).await;
```

在配置文件中：

```yaml
server:
  # 工作线程数，0 表示自动选择（通常为 CPU 核心数）
  threads: 0
```

### IO 相关优化

1. **异步 IO 调优**：

```rust
// 设置 tokio runtime 配置
use tokio::runtime::Builder;

let runtime = Builder::new_multi_thread()
    .worker_threads(num_cpu::get())
    .enable_io()
    .enable_time()
    .thread_name("pingora-worker")
    .thread_stack_size(2 * 1024 * 1024)
    .build()
    .unwrap();
```

2. **减少内存复制**：

```rust
// 使用引用而不是克隆大型数据
fn process_body<'a>(&self, body: &'a [u8]) -> &'a [u8] {
    // 处理逻辑...
    body
}
```

## 生产环境运维最佳实践

### 日志管理

1. **日志轮转**：使用 logrotate 定期轮转日志文件：

```
/var/log/pingora/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 pingora pingora
    sharedscripts
    postrotate
        systemctl reload pingora
    endscript
}
```

2. **日志聚合**：使用 ELK 或 Grafana Loki 集中收集和分析日志

### 备份和灾难恢复

1. **配置备份**：定期备份配置文件和证书
2. **灾难恢复计划**：制定详细的灾难恢复流程
3. **多区域部署**：在多个数据中心或云区域部署实例

### 持续监控

1. **自动化健康检查**：定期执行端到端健康检查
2. **性能基准测试**：定期测试性能以检测退化
3. **安全扫描**：定期检查安全漏洞

## 总结

将 Pingora 部署到生产环境需要全面考虑系统配置、安全加固、监控和性能优化。通过遵循本章介绍的最佳实践，您可以确保 Pingora 服务稳定、安全地运行，并能够及时发现和解决潜在问题。

关键要点：

1. **系统配置**：调整文件描述符限制和网络参数以优化性能
2. **安全加固**：实施最小权限原则、TLS 加固和网络安全措施
3. **部署策略**：使用容器化或 systemd 管理服务，实现零停机部署
4. **监控指标**：收集和可视化关键性能指标，设置适当的报警阈值
5. **性能优化**：识别和解决性能瓶颈，调整工作线程和连接池设置

通过这些措施，您可以构建一个可靠、高性能且易于维护的 Pingora 生产环境。
