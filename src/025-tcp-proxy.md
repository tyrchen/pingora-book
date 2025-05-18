# 构建非 HTTP 的 TCP 代理服务

虽然 Pingora 主要用于 HTTP 代理服务，但它的底层架构允许我们构建通用的 TCP 代理服务。这种类型的代理可以用于转发各种 TCP 协议的流量，例如 MySQL、Redis、SMTP 等。

本章将介绍如何使用 Pingora 构建一个非 HTTP 的 TCP 代理服务，包括实现技术细节和注意事项。

## TCP 代理基础

TCP 代理与 HTTP 代理的主要区别在于它工作在更低的网络层：

1. **协议不可知**：TCP 代理不解析或理解传输的数据内容，只是简单地转发字节流
2. **无状态**：不理解应用层协议的状态（如 HTTP 请求/响应周期）
3. **端口映射**：通常关注的是将源端口映射到目标端口
4. **双向数据流**：需要同时处理从客户端到服务器和从服务器到客户端的数据流

## Pingora 中的 TCP 代理实现

Pingora 提供了实现 TCP 代理所需的基础设施，主要通过两种方式：

1. **使用 ServeL4 trait**：直接实现底层 L4 (TCP/UDP) 协议处理
2. **使用 ServeApp trait**：实现自定义的应用层协议代理

在本章中，我们将主要关注 ServeL4 方法，因为它更适合通用 TCP 代理场景。

## 实现 TCP 代理服务

### 基本结构

首先，让我们创建一个简单的 TCP 代理服务的基本结构：

```rust
use async_trait::async_trait;
use pingora::prelude::*;
use pingora_core::protocols::l4::socket::Socket;
use pingora_core::server::configuration::Opt;
use pingora_core::server::{Server, Service};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{copy, split};
use log::{error, info};

// TCP 代理服务实现
pub struct TcpProxy {
    // 上游服务器地址
    upstream: SocketAddr,
}

impl TcpProxy {
    pub fn new(upstream: SocketAddr) -> Self {
        Self { upstream }
    }
}

#[async_trait]
impl ServeL4 for TcpProxy {
    async fn serve_l4(&self, downstream: Socket, _ctx: &mut ()) -> Result<()> {
        info!("接收到来自 {} 的连接", downstream.peer_addr()?);

        // 连接到上游服务器
        let upstream = match Socket::connect(self.upstream).await {
            Ok(socket) => socket,
            Err(e) => {
                error!("无法连接到上游服务器 {}: {}", self.upstream, e);
                return Err(e);
            }
        };

        info!("已连接到上游服务器 {}", self.upstream);

        // 处理转发逻辑
        self.relay_traffic(downstream, upstream).await
    }
}

impl TcpProxy {
    // 双向转发数据
    async fn relay_traffic(&self, downstream: Socket, upstream: Socket) -> Result<()> {
        // 分离读写流
        let (down_read, down_write) = split(downstream);
        let (up_read, up_write) = split(upstream);

        // 创建两个任务分别处理上下游数据转发
        let client_to_server = copy(down_read, up_write);
        let server_to_client = copy(up_read, down_write);

        // 并发执行两个数据转发任务
        match tokio::try_join!(client_to_server, server_to_client) {
            Ok((from_client, from_server)) => {
                info!(
                    "连接关闭：从客户端转发 {} 字节，从服务器转发 {} 字节",
                    from_client, from_server
                );
                Ok(())
            }
            Err(e) => {
                error!("数据转发错误: {}", e);
                Err(e.into())
            }
        }
    }
}

fn main() {
    // 初始化日志
    env_logger::init();

    // 创建服务器
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // 上游服务器地址
    let upstream_addr: SocketAddr = "192.168.1.100:5432".parse().unwrap();

    // 创建 TCP 代理服务
    let tcp_proxy = Arc::new(TcpProxy::new(upstream_addr));

    // 创建服务
    let mut service = Service::new(
        "tcp_proxy".to_string(),
        tcp_proxy,
    );

    // 添加 TCP 监听器
    service.add_tcp_listener("0.0.0.0:5000".parse().unwrap());

    // 添加服务到服务器
    server.add_service(service);

    // 运行服务器
    server.run_forever();
}
```

这个基本实现展示了一个简单的 TCP 代理服务，它将所有 TCP 连接转发到指定的上游服务器。下面让我们来详细讨论一些关键点。

### ServeL4 Trait

`ServeL4` trait 是 Pingora 中处理底层 TCP/UDP 连接的核心接口。关键方法是 `serve_l4`，它接收下游 Socket（从客户端来的连接）并实现代理逻辑：

```rust
#[async_trait]
impl ServeL4 for TcpProxy {
    async fn serve_l4(&self, downstream: Socket, _ctx: &mut ()) -> Result<()> {
        // 实现代理逻辑
    }
}
```

### 数据转发机制

TCP 代理的核心是双向数据转发。我们使用 `tokio::io::copy` 来高效地复制数据流：

```rust
async fn relay_traffic(&self, downstream: Socket, upstream: Socket) -> Result<()> {
    // 分离读写流
    let (down_read, down_write) = split(downstream);
    let (up_read, up_write) = split(upstream);

    // 创建两个任务分别处理上下游数据转发
    let client_to_server = copy(down_read, up_write);
    let server_to_client = copy(up_read, down_write);

    // 并发执行两个数据转发任务
    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}
```

使用 `tokio::try_join!` 同时处理两个方向的数据流，当任何一个方向出错时，两个方向都会停止。

## 高级功能

### 多目标上游服务器

在实际应用中，我们可能需要根据某些规则选择不同的上游服务器。下面是一个基于简单规则路由到不同上游的示例：

```rust
use std::collections::HashMap;

pub struct MultiTcpProxy {
    // 上游服务器映射
    upstreams: HashMap<u16, SocketAddr>,
    // 默认上游服务器
    default_upstream: SocketAddr,
}

impl MultiTcpProxy {
    pub fn new(default_upstream: SocketAddr) -> Self {
        Self {
            upstreams: HashMap::new(),
            default_upstream,
        }
    }

    // 添加源端口到目标上游的映射
    pub fn add_upstream_mapping(&mut self, source_port: u16, upstream: SocketAddr) {
        self.upstreams.insert(source_port, upstream);
    }

    // 根据源端口选择上游服务器
    fn select_upstream(&self, source_port: u16) -> SocketAddr {
        *self.upstreams.get(&source_port).unwrap_or(&self.default_upstream)
    }
}

#[async_trait]
impl ServeL4 for MultiTcpProxy {
    async fn serve_l4(&self, downstream: Socket, _ctx: &mut ()) -> Result<()> {
        // 获取源端口
        let source_port = match downstream.peer_addr() {
            Ok(addr) => addr.port(),
            Err(_) => return Err(Error::internal("无法获取源端口")),
        };

        // 选择上游服务器
        let upstream_addr = self.select_upstream(source_port);

        info!("从端口 {} 转发到上游 {}", source_port, upstream_addr);

        // 连接到上游服务器
        let upstream = Socket::connect(upstream_addr).await?;

        // 转发数据
        self.relay_traffic(downstream, upstream).await
    }
}
```

### 添加 TLS 支持

对于需要 TLS 加密的场景，我们可以在代理服务中添加 TLS 支持：

```rust
use tokio_rustls::TlsAcceptor;
use std::fs::File;
use std::io::BufReader;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};

pub struct TlsTcpProxy {
    upstream: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
}

impl TlsTcpProxy {
    // 创建一个支持 TLS 的 TCP 代理
    pub fn new_with_tls(
        upstream: SocketAddr,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self> {
        // 加载证书
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()?;

        // 加载私钥
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let keys = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()?;

        // 创建 TLS 配置
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys[0].clone())?;

        let tls_acceptor = Some(TlsAcceptor::from(Arc::new(config)));

        Ok(Self {
            upstream,
            tls_acceptor,
        })
    }
}
```

### 连接池管理

对于高性能应用，重用连接可以显著提高性能。我们可以实现一个简单的连接池：

```rust
use std::collections::VecDeque;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};

struct PooledSocket {
    socket: Socket,
    last_used: Instant,
}

pub struct TcpProxyWithPool {
    upstream: SocketAddr,
    connection_pool: Mutex<VecDeque<PooledSocket>>,
    max_idle: usize,
    max_idle_time: Duration,
}

impl TcpProxyWithPool {
    pub fn new(upstream: SocketAddr, max_idle: usize, max_idle_time: Duration) -> Self {
        Self {
            upstream,
            connection_pool: Mutex::new(VecDeque::with_capacity(max_idle)),
            max_idle,
            max_idle_time,
        }
    }

    // 获取一个连接（从池中或创建新的）
    async fn get_connection(&self) -> Result<Socket> {
        let now = Instant::now();
        let mut pool = self.connection_pool.lock().await;

        // 尝试从池中获取一个可用连接
        while let Some(pooled) = pool.pop_front() {
            // 检查连接是否过期
            if now.duration_since(pooled.last_used) > self.max_idle_time {
                // 连接过期，关闭并继续查找
                continue;
            }

            // 返回找到的有效连接
            return Ok(pooled.socket);
        }

        // 池中没有可用连接，创建新连接
        Socket::connect(self.upstream).await
    }

    // 将连接放回池中
    async fn return_connection(&self, socket: Socket) {
        let mut pool = self.connection_pool.lock().await;

        // 如果池未满，将连接放回池中
        if pool.len() < self.max_idle {
            pool.push_back(PooledSocket {
                socket,
                last_used: Instant::now(),
            });
        }
        // 否则连接将被丢弃并关闭
    }
}

#[async_trait]
impl ServeL4 for TcpProxyWithPool {
    async fn serve_l4(&self, downstream: Socket, _ctx: &mut ()) -> Result<()> {
        // 获取上游连接
        let upstream = match self.get_connection().await {
            Ok(socket) => socket,
            Err(e) => {
                error!("无法连接到上游服务器: {}", e);
                return Err(e);
            }
        };

        // 使用连接，完成后返回到池中
        let result = self.relay_traffic(downstream, upstream.clone()).await;

        // 如果没有错误，将连接放回池中
        if result.is_ok() {
            self.return_connection(upstream).await;
        }

        result
    }
}
```

## 性能优化

### 缓冲区设置

适当设置缓冲区大小可以提高 TCP 代理的性能：

```rust
async fn relay_traffic(&self, downstream: Socket, upstream: Socket) -> Result<()> {
    // 设置较大的缓冲区
    downstream.set_recv_buffer_size(65536)?;
    downstream.set_send_buffer_size(65536)?;
    upstream.set_recv_buffer_size(65536)?;
    upstream.set_send_buffer_size(65536)?;

    // 分离读写流
    let (down_read, down_write) = split(downstream);
    let (up_read, up_write) = split(upstream);

    // 使用自定义缓冲区大小的复制操作
    let client_to_server = copy_with_buffer(down_read, up_write, 65536);
    let server_to_client = copy_with_buffer(up_read, down_write, 65536);

    // 并发执行两个转发任务
    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

// 使用自定义缓冲区大小的复制函数
async fn copy_with_buffer<R, W>(mut reader: R, mut writer: W, buffer_size: usize) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; buffer_size];
    let mut total_copied = 0u64;

    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        writer.write_all(&buffer[..n]).await?;
        total_copied += n as u64;
    }

    writer.flush().await?;
    Ok(total_copied)
}
```

### 工作线程设置

调整 Pingora 服务器的工作线程数可以更好地利用多核 CPU：

```rust
fn main() {
    let mut server = Server::new(None).unwrap();

    // 设置工作线程数量为 CPU 核心数的两倍
    let num_workers = num_cpus::get() * 2;
    server.configuration.threads = num_workers;

    server.bootstrap();

    // ... 其他代码 ...

    server.run_forever();
}
```

### TCP 参数优化

为获得最佳性能，可以优化 TCP 套接字参数：

```rust
async fn serve_l4(&self, mut downstream: Socket, _ctx: &mut ()) -> Result<()> {
    // 设置 TCP 参数
    downstream.set_nodelay(true)?;  // 禁用 Nagle 算法，减少延迟
    downstream.set_keepalive(Some(Duration::from_secs(60)))?;  // 启用 keepalive

    let mut upstream = Socket::connect(self.upstream).await?;
    upstream.set_nodelay(true)?;
    upstream.set_keepalive(Some(Duration::from_secs(60)))?;

    // ... 其他代码 ...
}
```

## 安全性考虑

### 访问控制

实现基本的 IP 地址过滤，只允许特定 IP 访问 TCP 代理：

```rust
use std::collections::HashSet;
use std::net::IpAddr;

pub struct SecureTcpProxy {
    upstream: SocketAddr,
    allowed_ips: HashSet<IpAddr>,
}

impl SecureTcpProxy {
    pub fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            allowed_ips: HashSet::new(),
        }
    }

    pub fn allow_ip(&mut self, ip: IpAddr) {
        self.allowed_ips.insert(ip);
    }

    fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        // 如果允许列表为空，则允许所有 IP
        self.allowed_ips.is_empty() || self.allowed_ips.contains(&ip)
    }
}

#[async_trait]
impl ServeL4 for SecureTcpProxy {
    async fn serve_l4(&self, downstream: Socket, _ctx: &mut ()) -> Result<()> {
        // 检查客户端 IP
        let peer_addr = downstream.peer_addr()?;

        if !self.is_ip_allowed(peer_addr.ip()) {
            error!("拒绝来自 {} 的未授权连接", peer_addr.ip());
            return Err(Error::internal("未授权的 IP 地址"));
        }

        // ... 其他代理逻辑 ...
    }
}
```

### 限流

为防止代理服务被滥用，可以实现简单的速率限制：

```rust
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::{sleep, Duration};

pub struct RateLimitedTcpProxy {
    upstream: SocketAddr,
    max_connections: usize,
    current_connections: AtomicUsize,
}

impl RateLimitedTcpProxy {
    pub fn new(upstream: SocketAddr, max_connections: usize) -> Self {
        Self {
            upstream,
            max_connections,
            current_connections: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ServeL4 for RateLimitedTcpProxy {
    async fn serve_l4(&self, downstream: Socket, _ctx: &mut ()) -> Result<()> {
        // 检查当前连接数
        let current = self.current_connections.load(Ordering::Relaxed);
        if current >= self.max_connections {
            error!("达到最大连接数 {}", self.max_connections);
            return Err(Error::internal("达到最大连接数"));
        }

        // 增加连接计数
        self.current_connections.fetch_add(1, Ordering::Relaxed);

        // 连接到上游服务器
        let upstream = Socket::connect(self.upstream).await?;

        // 构造结果处理，无论何种方式返回都要减少连接计数
        let result = self.relay_traffic(downstream, upstream).await;

        // 减少连接计数
        self.current_connections.fetch_sub(1, Ordering::Relaxed);

        result
    }
}
```

## 实际应用示例

### 数据库代理

一个 MySQL 数据库的 TCP 代理示例：

```rust
fn main() {
    env_logger::init();

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // 创建 MySQL 代理
    let mysql_proxy = Arc::new(TcpProxy::new("mysql-server.internal:3306".parse().unwrap()));

    // 创建服务
    let mut mysql_service = Service::new(
        "mysql_proxy".to_string(),
        mysql_proxy,
    );

    // 在公共端口上监听 MySQL 连接
    mysql_service.add_tcp_listener("0.0.0.0:3306".parse().unwrap());

    // 添加服务
    server.add_service(mysql_service);

    // 运行服务器
    server.run_forever();
}
```

### 多协议代理

支持多种不同协议的代理服务：

```rust
fn main() {
    env_logger::init();

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // 创建 MySQL 代理
    let mysql_proxy = Arc::new(TcpProxy::new("mysql-server.internal:3306".parse().unwrap()));
    let mut mysql_service = Service::new("mysql_proxy".to_string(), mysql_proxy);
    mysql_service.add_tcp_listener("0.0.0.0:3306".parse().unwrap());

    // 创建 Redis 代理
    let redis_proxy = Arc::new(TcpProxy::new("redis-server.internal:6379".parse().unwrap()));
    let mut redis_service = Service::new("redis_proxy".to_string(), redis_proxy);
    redis_service.add_tcp_listener("0.0.0.0:6379".parse().unwrap());

    // 创建 SMTP 代理
    let smtp_proxy = Arc::new(TcpProxy::new("smtp-server.internal:25".parse().unwrap()));
    let mut smtp_service = Service::new("smtp_proxy".to_string(), smtp_proxy);
    smtp_service.add_tcp_listener("0.0.0.0:25".parse().unwrap());

    // 添加所有服务
    server.add_service(mysql_service);
    server.add_service(redis_service);
    server.add_service(smtp_service);

    // 运行服务器
    server.run_forever();
}
```

## 监控与指标

为 TCP 代理添加简单的监控指标：

```rust
use prometheus::{register_counter, register_gauge, Counter, Gauge};

pub struct MonitoredTcpProxy {
    upstream: SocketAddr,
    connections_total: Counter,
    active_connections: Gauge,
    bytes_transferred_total: Counter,
}

impl MonitoredTcpProxy {
    pub fn new(upstream: SocketAddr, service_name: &str) -> Self {
        let connections_total = register_counter!(
            format!("{}_connections_total", service_name),
            format!("Total connections for {}", service_name)
        ).unwrap();

        let active_connections = register_gauge!(
            format!("{}_active_connections", service_name),
            format!("Active connections for {}", service_name)
        ).unwrap();

        let bytes_transferred_total = register_counter!(
            format!("{}_bytes_transferred_total", service_name),
            format!("Total bytes transferred for {}", service_name)
        ).unwrap();

        Self {
            upstream,
            connections_total,
            active_connections,
            bytes_transferred_total,
        }
    }
}

#[async_trait]
impl ServeL4 for MonitoredTcpProxy {
    async fn serve_l4(&self, downstream: Socket, _ctx: &mut ()) -> Result<()> {
        // 增加连接计数
        self.connections_total.inc();
        self.active_connections.inc();

        // 在函数退出时减少活跃连接计数
        let _guard = scopeguard::guard((), |_| {
            self.active_connections.dec();
        });

        // 连接到上游服务器
        let upstream = Socket::connect(self.upstream).await?;

        // 转发数据
        match self.relay_traffic_monitored(downstream, upstream).await {
            Ok((client_bytes, server_bytes)) => {
                let total_bytes = client_bytes + server_bytes;
                self.bytes_transferred_total.inc_by(total_bytes);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl MonitoredTcpProxy {
    async fn relay_traffic_monitored(&self, downstream: Socket, upstream: Socket) -> Result<(u64, u64)> {
        // ... 转发逻辑，返回传输的字节数 ...
    }
}
```

## 总结

本章介绍了如何使用 Pingora 构建通用的 TCP 代理服务。我们涵盖了从基本实现到高级功能，以及性能优化和安全考虑。

通过 ServeL4 trait，Pingora 提供了强大的基础设施来构建高性能的 TCP 代理，可以用于多种协议和应用场景。虽然 Pingora 主要关注 HTTP 代理，但其灵活的架构使得它同样适用于各种 TCP 代理需求。

关键要点总结：

1. TCP 代理工作在传输层，不理解应用层协议的具体内容
2. 实现 ServeL4 trait 是构建 TCP 代理的核心
3. 双向数据转发是 TCP 代理的基本功能
4. 连接池、TLS 支持和多目标路由是高级功能
5. 性能优化包括缓冲区设置、线程管理和 TCP 参数调整
6. 安全性考虑包括访问控制和限流
7. 监控指标对于生产环境部署非常重要

通过本章学习，你应该能够基于 Pingora 实现各种 TCP 代理服务，以满足不同应用场景的需求。
