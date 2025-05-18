# 配置与管理 Pingora 服务

在前面的章节中，我们深入探讨了 Pingora 的核心功能，包括请求处理、响应处理、日志记录和错误处理。本章将转向更实用的方面，聚焦于如何配置和管理 Pingora 服务，这对于将 Pingora 部署到生产环境至关重要。

## 配置服务的监听地址和端口

Pingora 服务可以配置为监听不同的 IP 地址和端口，用于接收客户端请求。这可以通过 YAML 配置文件或代码直接配置实现。

### 通过配置文件设置监听地址和端口

在 `pingora_conf.yaml` 文件中，可以这样配置：

```yaml
proxy:
  services:
    - name: "web_proxy"
      listeners:
        - address: "0.0.0.0:80"    # 监听所有网络接口的 80 端口
          protocol: "http"

        - address: "127.0.0.1:8080" # 仅监听本地回环接口的 8080 端口
          protocol: "http"
```

### 通过代码配置监听地址和端口

在 Rust 代码中可以这样配置 Pingora 监听地址：

```rust
use pingora::prelude::*;
use pingora_proxy::ProxyHttp;
use std::sync::Arc;

// 定义一个简单的代理服务
struct SimpleProxy;

// 实现 ProxyHttp trait
impl ProxyHttp for SimpleProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    // 必要的方法实现...
    // ...
}

fn main() -> Result<()> {
    // 创建服务器实例
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务
    let mut proxy_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        SimpleProxy,
    );

    // 配置服务监听地址和端口
    proxy_service.add_tcp("0.0.0.0:80");     // 监听所有接口的 80 端口
    proxy_service.add_tcp("127.0.0.1:8080"); // 仅监听本地回环接口的 8080 端口

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 运行服务器
    server.run_forever();

    Ok(())
}
```

在这个例子中，我们使用 `add_tcp` 方法添加了两个监听地址：一个是 `0.0.0.0:80`，监听所有网络接口的 80 端口；另一个是 `127.0.0.1:8080`，仅监听本地回环接口的 8080 端口。

### 高级监听选项

除了简单的监听地址和端口配置外，Pingora 还支持更高级的 TCP 套接字选项：

```rust
use pingora::listeners::TcpSocketOptions;
use std::time::Duration;

// 创建自定义 TCP 套接字选项
let mut tcp_options = TcpSocketOptions::default();
tcp_options.tcp_keepalive = Some(TcpKeepalive {
    idle: Duration::from_secs(60),
    interval: Duration::from_secs(5),
    count: 5,
});
tcp_options.tcp_fastopen = Some(10);
tcp_options.dscp = Some(46); // 设置 DSCP 优先级

// 使用自定义选项添加监听地址
proxy_service.add_tcp_with_settings("0.0.0.0:80", tcp_options);
```

这些高级选项对于调整 Pingora 服务的网络性能和行为很有用，特别是在高流量环境或特殊网络要求下。

## 配置 TLS 和 HTTPS 支持

要使 Pingora 服务支持 HTTPS，需要配置 TLS 证书和私钥。Pingora 支持通过配置文件或代码方式配置 TLS。

### 通过配置文件配置 TLS

在 `pingora_conf.yaml` 文件中，可以这样配置 HTTPS 监听器：

```yaml
proxy:
  services:
    - name: "secure_proxy"
      listeners:
        - address: "0.0.0.0:443"
          protocol: "https"
          cert: "/path/to/cert.pem"
          key: "/path/to/key.pem"
```

### 通过代码配置 TLS

在 Rust 代码中，可以这样配置 HTTPS 监听器：

```rust
// 在前面的示例基础上
let cert_path = "/path/to/cert.pem";
let key_path = "/path/to/key.pem";

// 添加 HTTPS 监听器
proxy_service.add_tls("0.0.0.0:443", cert_path, key_path)?;
```

### 高级 TLS 配置

Pingora 还支持高级 TLS 配置，如 ALPN 协议协商（用于 HTTP/2 支持）和自定义 TLS 设置：

```rust
use pingora::listeners::tls::TlsSettings;

// 创建基础 TLS 设置
let mut tls_settings = TlsSettings::intermediate(cert_path, key_path)?;

// 启用 HTTP/2 支持
tls_settings.enable_h2();

// 添加自定义 TLS 监听器
proxy_service.add_tls_with_settings("0.0.0.0:443", tls_settings)?;
```

## 同时支持 HTTP 和 HTTPS

Pingora 允许一个服务同时监听 HTTP 和 HTTPS 端口，这样可以提供更灵活的访问方式：

```rust
// 创建代理服务
let mut proxy_service = pingora_proxy::http_proxy_service(
    &server.configuration,
    SimpleProxy,
);

// 添加 HTTP 监听器
proxy_service.add_tcp("0.0.0.0:80");

// 添加 HTTPS 监听器
proxy_service.add_tls("0.0.0.0:443", cert_path, key_path)?;

// 添加服务到服务器
server.add_service(proxy_service);
```

这样配置后，代理服务将同时接受 HTTP（80 端口）和 HTTPS（443 端口）请求。

## 配置多个服务

Pingora 支持在一个服务器实例中运行多个服务，每个服务可以有不同的处理逻辑、监听地址和配置。

### 创建和配置多个服务

```rust
// 定义不同的代理服务类型
struct ApiProxy;
struct StaticProxy;

// 实现 ProxyHttp trait
impl ProxyHttp for ApiProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX { () }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // API 请求路由到 API 服务器
        let peer = Box::new(HttpPeer::new(
            ("api.example.com", 443),
            true,
            "api.example.com".to_string(),
        ));
        Ok(peer)
    }

    // 其他必要的方法实现...
}

impl ProxyHttp for StaticProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX { () }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // 静态内容请求路由到静态内容服务器
        let peer = Box::new(HttpPeer::new(
            ("static.example.com", 443),
            true,
            "static.example.com".to_string(),
        ));
        Ok(peer)
    }

    // 其他必要的方法实现...
}

fn main() -> Result<()> {
    // 创建服务器实例
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建 API 代理服务
    let mut api_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        ApiProxy,
    );
    // API 服务监听 8080 端口
    api_service.add_tcp("0.0.0.0:8080");

    // 创建静态内容代理服务
    let mut static_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        StaticProxy,
    );
    // 静态内容服务监听 8081 端口
    static_service.add_tcp("0.0.0.0:8081");

    // 添加服务到服务器
    server.add_service(api_service);
    server.add_service(static_service);

    // 运行服务器
    server.run_forever();

    Ok(())
}
```

在这个例子中，我们创建了两个不同的代理服务：一个用于 API 请求，另一个用于静态内容。每个服务有自己的监听地址和上游配置。

### 不同端口的不同服务

多个服务可以在不同端口上运行，提供不同类型的服务：

```rust
// API 服务（HTTP）
let mut api_service = pingora_proxy::http_proxy_service(
    &server.configuration,
    ApiProxy,
);
api_service.add_tcp("0.0.0.0:8080");

// 静态内容服务（HTTPS）
let mut static_service = pingora_proxy::http_proxy_service(
    &server.configuration,
    StaticProxy,
);
static_service.add_tls("0.0.0.0:8443", cert_path, key_path)?;

// 添加服务到服务器
server.add_service(api_service);
server.add_service(static_service);
```

## 配置工作线程数量

Pingora 允许配置每个服务的工作线程数量，这对于性能调优非常重要。

### 通过配置文件设置线程数

在 `pingora_conf.yaml` 文件中：

```yaml
proxy:
  threads: 4  # 默认线程数

  services:
    - name: "cpu_intensive_service"
      threads: 8  # 为这个服务配置 8 个线程
```

### 通过代码设置线程数

```rust
// 设置特定服务的线程数
api_service.threads = Some(4);
static_service.threads = Some(2);
```

线程数的最佳设置取决于多种因素，包括：

1. 服务器的 CPU 核心数
2. 请求的复杂性和处理时间
3. I/O 密集型还是 CPU 密集型工作负载
4. 并发连接数

通常，对于 I/O 密集型工作负载，可以设置线程数为 CPU 核心数的 1-2 倍；对于 CPU 密集型工作负载，线程数接近 CPU 核心数可能更为合适。

## 以守护进程模式运行

在生产环境中，通常需要以守护进程（后台）模式运行 Pingora 服务。

### 通过配置文件设置守护进程模式

在 `pingora_conf.yaml` 文件中：

```yaml
proxy:
  server:
    daemon: true
    pid_file: "/var/run/pingora.pid"
    user: "www-data"
    group: "www-data"
```

这些配置项的意义：

- `daemon`: 是否以守护进程模式运行
- `pid_file`: PID 文件的路径
- `user`/`group`: 运行服务的用户和用户组（在以 root 用户启动后会切换到这些用户/组）

### 通过代码设置守护进程模式

```rust
use pingora::server::configuration::ServerConf;

// 创建自定义配置
let mut conf = ServerConf::default();
conf.daemon = true;
conf.pid_file = "/var/run/pingora.pid".to_string();
conf.user = Some("www-data".to_string());
conf.group = Some("www-data".to_string());

// 使用自定义配置创建服务器
let mut server = Server::new_with_config(conf, None)?;
```

## 信号处理与服务管理

Pingora 支持通过进程信号进行服务管理，这在生产环境中非常有用。

### 支持的信号

Pingora 支持以下信号：

1. **SIGTERM/SIGINT**: 触发优雅关闭
2. **SIGHUP**: 重新加载配置（如果启用）
3. **SIGUSR1/SIGUSR2**: 可用于自定义操作

### 发送信号示例

```bash
# 优雅关闭
kill -TERM $(cat /var/run/pingora.pid)

# 重新加载配置
kill -HUP $(cat /var/run/pingora.pid)
```

### 启用配置重新加载

要支持通过 SIGHUP 信号重新加载配置，需要在代码中显式启用：

```rust
// 在启动服务器之前启用配置重新加载
server.enable_reload();
```

## 综合配置示例

下面是一个综合示例，展示了 Pingora 的多种配置选项：

```rust
use pingora::prelude::*;
use pingora::listeners::TcpSocketOptions;
use pingora::listeners::tls::TlsSettings;
use pingora_proxy::ProxyHttp;
use std::sync::Arc;
use std::time::Duration;

// 代理服务实现
struct WebProxy;

impl ProxyHttp for WebProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // 根据请求路径选择上游服务器
        let path = session.req_header().uri.path();

        let (host, port) = if path.starts_with("/api") {
            ("api.example.com", 443)
        } else if path.starts_with("/static") {
            ("static.example.com", 443)
        } else {
            ("www.example.com", 443)
        };

        let peer = Box::new(HttpPeer::new(
            (host, port),
            true,
            host.to_string(),
        ));

        Ok(peer)
    }

    // 其他必要的方法实现...
}

fn main() -> Result<()> {
    // 创建自定义配置
    let mut conf = ServerConf::default();
    conf.threads = 8;
    conf.daemon = true;
    conf.pid_file = "/var/run/pingora.pid".to_string();

    // 创建服务器
    let mut server = Server::new_with_config(conf, None)?;
    server.bootstrap();
    server.enable_reload();

    // 创建代理服务
    let mut proxy_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        WebProxy,
    );

    // 配置 HTTP 监听器
    let mut tcp_options = TcpSocketOptions::default();
    tcp_options.tcp_keepalive = Some(TcpKeepalive {
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(5),
        count: 5,
    });
    proxy_service.add_tcp_with_settings("0.0.0.0:80", tcp_options);

    // 配置 HTTPS 监听器
    let cert_path = "/path/to/cert.pem";
    let key_path = "/path/to/key.pem";
    let mut tls_settings = TlsSettings::intermediate(cert_path, key_path)?;
    tls_settings.enable_h2(); // 启用 HTTP/2 支持
    proxy_service.add_tls_with_settings("0.0.0.0:443", tls_settings)?;

    // 设置线程数
    proxy_service.threads = Some(8);

    // 添加服务到服务器
    server.add_service(proxy_service);

    // 运行服务器
    server.run_forever();

    Ok(())
}
```

## 总结

配置和管理 Pingora 服务是部署生产就绪应用程序的重要方面。通过适当的配置，可以优化性能、提高安全性并满足各种部署需求。本章涵盖了以下关键方面：

1. 配置服务监听地址和端口
2. 配置 TLS 和 HTTPS 支持
3. 运行多个不同的服务
4. 调整工作线程数量
5. 以守护进程模式运行
6. 使用信号进行服务管理

通过灵活地组合这些配置选项，可以构建出适合不同场景的高性能代理服务。无论是作为简单的反向代理，还是复杂的 API 网关，Pingora 都提供了所需的配置灵活性。
