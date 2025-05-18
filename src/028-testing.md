# 单元测试与集成测试

为 Pingora 应用编写测试是确保其可靠性和稳定性的关键步骤。本章将探讨如何为 Pingora 应用编写单元测试和集成测试，包括模拟客户端请求和上游服务器响应的方法。

## Pingora 测试概述

Pingora 采用了 Rust 的标准测试框架，包括：

1. **单元测试**：测试单个组件的功能，通常位于源文件中，使用 `#[test]` 注解。
2. **集成测试**：测试多个组件的交互，通常位于 `tests/` 目录中。

Pingora 的集成测试通常涉及以下内容：

- 启动测试服务器
- 发送 HTTP 请求
- 验证响应
- 检查边缘情况和错误处理

## 单元测试

### 测试 ProxyHttp trait 实现

对于 Pingora 应用，我们需要测试 `ProxyHttp` trait 的实现：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::*;
    use pingora_http::{RequestHeader, ResponseHeader};
    use pingora_proxy::Session;

    // 为测试创建一个模拟的 Session
    mock! {
        pub SessionMock {}
        impl Session for SessionMock {
            fn req_header(&self) -> &RequestHeader;
            fn client_addr(&self) -> Option<std::net::SocketAddr>;
            fn server_addr(&self) -> Option<std::net::SocketAddr>;
            // 其他需要模拟的方法...
        }
    }

    #[tokio::test]
    async fn test_upstream_peer_selection() {
        let proxy = MyProxy::new();
        let mut ctx = proxy.new_ctx();

        // 创建模拟的 Session
        let mut mock_session = MockSessionMock::new();

        // 设置模拟的行为
        mock_session
            .expect_req_header()
            .returning(|| {
                let mut req = RequestHeader::build("GET", b"/api/test", None).unwrap();
                req.headers.insert("host", "example.com".parse().unwrap());
                &req
            });

        // 调用被测试的方法
        let result = proxy.upstream_peer(&mut mock_session, &mut ctx).await;

        // 验证结果
        assert!(result.is_ok());
        let peer = result.unwrap();
        assert_eq!(peer.address().ip().to_string(), "203.0.113.1");
        assert_eq!(peer.address().port(), 443);
    }

    #[tokio::test]
    async fn test_request_filter() {
        let proxy = MyProxy::new();
        let mut ctx = proxy.new_ctx();

        // 模拟 Session...

        // 测试请求过滤逻辑
        let result = proxy.request_filter(&mut mock_session, &mut ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false); // 不终止请求处理

        // 验证上下文中的值
        assert_eq!(ctx.some_value, expected_value);
    }
}
```

### 模拟依赖组件

使用 `mockall` 或其他模拟库来模拟依赖组件：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::*;

    mock! {
        CacheService {}
        impl Cache for CacheService {
            fn get(&self, key: &str) -> Option<String>;
            fn set(&self, key: &str, value: String, ttl: Duration) -> Result<()>;
        }
    }

    #[tokio::test]
    async fn test_cache_response_filter() {
        let mut mock_cache = MockCacheService::new();
        mock_cache
            .expect_get()
            .with(eq("test-key"))
            .returning(|_| Some("cached-response".to_string()));

        let proxy = MyProxyWithCache::new(Arc::new(mock_cache));
        // 测试逻辑...
    }
}
```

### 测试 CTX 上下文对象

测试自定义的 CTX 类型：

```rust
#[test]
fn test_new_ctx() {
    let proxy = MyProxy::new();
    let ctx = proxy.new_ctx();

    // 验证默认值
    assert_eq!(ctx.request_id, None);
    assert_eq!(ctx.upstream_attempts, 0);

    // 测试上下文方法
    let updated_ctx = ctx.with_request_id("req-123");
    assert_eq!(updated_ctx.request_id, Some("req-123".to_string()));
}
```

## 集成测试

Pingora 的集成测试需要启动实际的服务器组件，并使用 HTTP 客户端发送请求。查看 Pingora 源码中的测试实现，我们可以发现以下模式：

### 测试服务器设置

创建一个测试用的服务器，并在测试开始前启动：

```rust
use once_cell::sync::Lazy;
use std::{thread, time};

pub struct TestServer {
    pub handle: thread::JoinHandle<()>,
}

impl TestServer {
    pub fn start() -> Self {
        // 启动服务器
        let server_handle = thread::spawn(|| {
            // 创建并配置 Pingora 服务器
            let mut server = Server::new(None).unwrap();
            server.bootstrap();

            // 添加测试服务
            let listeners = Listeners::tcp("127.0.0.1:8000");
            let service = Service::new("test_service".to_string(), MyProxy::new());
            service.add_listeners(listeners);

            server.add_service(service);
            server.run_forever();
        });

        // 等待服务器启动
        thread::sleep(time::Duration::from_secs(2));

        TestServer {
            handle: server_handle,
        }
    }
}

// 使用 Lazy 静态初始化，确保测试共享同一个服务器实例
static TEST_SERVER: Lazy<TestServer> = Lazy::new(TestServer::start);

pub fn init() {
    // 触发服务器启动
    let _ = &*TEST_SERVER;
}
```

### 测试代理功能

编写针对实际运行的服务器的测试：

```rust
#[tokio::test]
async fn test_proxy_basic() {
    // 初始化测试服务器
    init();

    // 发送请求
    let client = reqwest::Client::new();
    let res = client
        .get("http://127.0.0.1:8000/api/test")
        .send()
        .await
        .unwrap();

    // 验证响应
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers().get("x-custom-header").unwrap(), "test-value");

    let body = res.text().await.unwrap();
    assert_eq!(body, "Expected response body");
}

#[tokio::test]
async fn test_proxy_error_handling() {
    init();

    // 测试错误情况
    let client = reqwest::Client::new();
    let res = client
        .get("http://127.0.0.1:8000/trigger-error")
        .send()
        .await
        .unwrap();

    // 验证错误响应
    assert_eq!(res.status(), 502);
    let body = res.text().await.unwrap();
    assert!(body.contains("Error message"));
}
```

### 模拟上游服务器

创建模拟的上游服务器以测试代理行为：

```rust
// 在测试模块中启动模拟上游服务器
pub fn start_mock_upstream() -> impl FnOnce() {
    let (tx, rx) = std::sync::mpsc::channel();

    // 在新线程中启动服务器
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:9000").await.unwrap();
            tx.send(()).unwrap(); // 信号服务器已启动

            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0; 4096];
                        // 读取请求
                        stream.read(&mut buf).await.unwrap();

                        // 发送模拟响应
                        let response = "HTTP/1.1 200 OK\r\n\
                                        Content-Type: text/plain\r\n\
                                        Content-Length: 12\r\n\
                                        \r\n\
                                        Hello World!";
                        stream.write_all(response.as_bytes()).await.unwrap();
                    });
                }
            }
        });
    });

    // 等待服务器启动
    rx.recv().unwrap();

    // 返回清理函数
    || {
        // 可选的清理代码
    }
}

#[tokio::test]
async fn test_proxy_to_mock_upstream() {
    let _cleanup = start_mock_upstream();
    init(); // 启动代理服务器

    // 验证代理到模拟上游的行为
    let client = reqwest::Client::new();
    let res = client
        .get("http://127.0.0.1:8000/to-mock")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert_eq!(body, "Hello World!");
}
```

## 测试缓存功能

测试 Pingora 的缓存行为需要特别注意：

```rust
#[tokio::test]
async fn test_cache_behavior() {
    init();

    // 第一次请求 - 应该缓存
    let client = reqwest::Client::new();
    let res1 = client
        .get("http://127.0.0.1:8000/cacheable")
        .send()
        .await
        .unwrap();

    assert_eq!(res1.status(), 200);
    assert_eq!(res1.headers().get("x-cache-status").unwrap(), "MISS");

    // 第二次请求 - 应该命中缓存
    let res2 = client
        .get("http://127.0.0.1:8000/cacheable")
        .send()
        .await
        .unwrap();

    assert_eq!(res2.status(), 200);
    assert_eq!(res2.headers().get("x-cache-status").unwrap(), "HIT");

    // 验证两次响应内容相同
    let body1 = res1.text().await.unwrap();
    let body2 = res2.text().await.unwrap();
    assert_eq!(body1, body2);
}
```

## 测试并发和负载

测试代理在高并发情况下的行为：

```rust
#[tokio::test]
async fn test_concurrent_requests() {
    init();

    // 创建多个并发请求
    let client = reqwest::Client::new();
    let mut handles = Vec::new();

    for i in 0..100 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let res = client
                .get(format!("http://127.0.0.1:8000/test/{}", i))
                .send()
                .await
                .unwrap();

            assert_eq!(res.status(), 200);
        }));
    }

    // 等待所有请求完成
    for handle in handles {
        handle.await.unwrap();
    }
}
```

## 测试错误处理和恢复

测试代理如何处理上游错误和重试：

```rust
#[tokio::test]
async fn test_upstream_failure_and_retry() {
    // 启动一个会失败的模拟上游
    let _failing_upstream = start_failing_upstream();
    init();

    // 发送触发重试的请求
    let client = reqwest::Client::new();
    let res = client
        .get("http://127.0.0.1:8000/retry-test")
        .send()
        .await
        .unwrap();

    // 验证最终响应（可能是成功的重试或错误响应）
    assert_eq!(res.status(), 200);
    assert!(res.headers().contains_key("x-retry-count"));
}

fn start_failing_upstream() -> impl FnOnce() {
    // 启动一个有时会失败的上游服务器
    // 实现省略...
    || {}
}
```

## 测试 TLS 和 HTTP/2

测试 TLS 和 HTTP/2 功能：

```rust
#[tokio::test]
async fn test_https_http2() {
    init();

    // 创建支持 HTTP/2 的客户端
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // 测试环境可接受自签名证书
        .build()
        .unwrap();

    let res = client
        .get("https://127.0.0.1:8443")
        .send()
        .await
        .unwrap();

    // 验证 HTTP/2
    assert_eq!(res.status(), 200);
    assert_eq!(res.version(), reqwest::Version::HTTP_2);
}
```

## 最佳实践总结

1. **分离测试环境**：为测试创建专用配置和环境，确保不影响生产环境。

2. **测试覆盖全面**：
   - 基本代理功能
   - 缓存行为
   - 错误处理和恢复
   - 性能和并发处理
   - TLS 和 协议特性（如 HTTP/2）

3. **模拟组件**：
   - 使用 mockall 或类似工具模拟依赖
   - 创建模拟的上游服务器
   - 模拟网络延迟和错误

4. **隔离单元测试**：
   - 单元测试每个回调函数
   - 验证正确的数据处理
   - 检查边缘情况

5. **自动化测试**：
   - 集成到 CI/CD 流程
   - 在多种环境中运行测试
   - 执行性能基准测试

6. **记录测试结果**：
   - 保存测试日志和指标
   - 建立性能基线
   - 检测性能退化

## Pingora 测试工具

Pingora 提供了一些实用的测试工具：

```rust
// 使用 Pingora 的测试工具
use pingora_core::protocols::http::testutil::RequestBuilder;

#[test]
fn test_request_parsing() {
    // 创建测试请求
    let req = RequestBuilder::new()
        .method("GET")
        .path("/test")
        .header("Host", "example.com")
        .header("User-Agent", "test-client")
        .build();

    // 使用请求进行测试
    assert_eq!(req.method(), "GET");
    assert_eq!(req.uri().path(), "/test");
    assert_eq!(req.headers().get("host").unwrap(), "example.com");
}
```

## 结论

为 Pingora 应用编写全面的测试套件是确保其稳定性和可靠性的关键。通过结合单元测试和集成测试，您可以验证代理的各个方面，包括基本功能、性能和错误处理。

Pingora 的测试框架提供了必要的工具来模拟复杂的网络交互，使您能够在受控环境中测试代理行为。通过遵循本章中的最佳实践，您可以构建强大的测试套件，确保您的 Pingora 应用能够处理实际生产环境中的各种场景。
