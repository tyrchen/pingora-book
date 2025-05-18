# 前言

以下问题旨在引导您思考如何利用 Pingora 的强大功能来构建各种网络应用程序。

## 入门与基本设置

1. [x] 我需要具备哪些 Rust 和网络编程的基础知识才能开始使用 Pingora 开发？

2. [x] 如何在我的开发环境中设置 Pingora？如何编译并运行官方提供的示例程序？

3. [x] 一个最小化的 Pingora 应用（例如一个简单的反向代理）的代码结构是怎样的？main.rs 和 Cargo.toml 文件通常包含哪些内容？

4. [x] pingora 的配置长什么样子，都有什么意义和用途？

5. [x] Pingora 服务启动时，Server::bootstrap() 和 Server::run_forever() 这两个核心方法分别做了什么？我应该如何组织我的启动代码？

## 实现核心代理逻辑 (ProxyHttp Trait)

1. [x] 我应该如何定义一个结构体，并为其实现 ProxyHttp trait 来定制我的代理行为？

2. [x] ProxyHttp::new_ctx() 方法的目的是什么？我应该在自定义的 CTX 结构体中存放哪些数据以便在请求处理的不同阶段共享？

3. [x] 如何在 request_filter() 方法中检查传入请求的头部信息（例如 User-Agent, Authorization）并根据这些信息做出决策（例如拒绝请求、添加标记）？

4. [x] 如果我想在 request_filter() 阶段直接响应客户端（例如返回一个 403 Forbidden 或 302 Redirect），应该如何操作？

5. [x] 如何在 upstream_peer() 方法中根据请求的特性（例如路径、Host头部）动态选择不同的上游服务器或服务组？

6. [x] 如何结合 pingora-load-balancing crate 在 upstream_peer() 中实现对一组上游服务器的负载均衡？

7. [x] 我想在请求发送到上游之前修改请求的 URI 或添加/删除某些请求头，应该在 upstream_request_filter() 中如何实现？

8. [x] 当从上游服务器收到响应后，如何在 upstream_response_filter()（缓存前）或 response_filter()（缓存后）中修改响应状态码或响应头（例如添加 CORS 头部、设置 Set-Cookie）？

9. [x] 如果需要检查或修改请求体（例如 JSON payload 验证或转换），应该如何使用 request_body_filter()？这个回调是分块调用的，我需要注意什么？

10. [x] 类似地，如果需要流式处理或修改响应体（例如内容替换、压缩指示），应该如何使用 upstream_response_body_filter() 或 response_body_filter()？

11. [x] 如何在 logging() 方法中收集请求处理过程中的关键信息（例如请求ID、处理耗时、上游响应码）并输出到日志？

12. [x] 当连接上游失败 (fail_to_connect) 或代理过程中出错 (error_while_proxy) 时，我应该如何处理这些错误以提高应用的容错性？例如，如何实现重试逻辑？

13. [x] fail_to_proxy() 回调在什么情况下被触发？我应该如何在这个回调中定制发送给客户端的错误页面？

## 配置与管理 Pingora 服务

1. [x] pingora_conf.yaml 中，如何配置服务监听的 IP 地址和端口？如何同时监听 HTTP 和 HTTPS 端口？

2. [x] 如何为我的 Pingora 服务配置 TLS 证书和私钥以启用 HTTPS？支持哪些 TLS 参数配置（例如密码套件、ALPN）？

3. [x] 如果我的应用需要提供多种不同的服务（例如一个 API 服务和一个静态资源服务），如何在配置文件中定义多个 services 并将它们路由到不同的 ProxyHttp 实现？

4. [x] 如何配置 Pingora 服务的工作线程数量？这个配置对性能有什么影响？

5. [x] 如何让我的 Pingora 服务在后台以守护进程模式运行？

6. [x] Pingora 服务支持哪些信号来进行管理（例如优雅关闭、重新加载配置）？我应该如何向 Pingora 进程发送这些信号？

## 利用 Pingora 的高级功能

1. [x] 我想为我的应用启用 HTTP 缓存，应该如何在 ProxyHttp trait 中实现 request_cache_filter()、cache_key_callback()、response_cache_filter() 等缓存相关方法？

2. [x] 如何通过 CacheMeta 和 CacheKey 来精细控制缓存行为，例如设置缓存有效期 (TTL)、处理 Vary 头部？

3. [x] 如何配置 pingora-cache 使用内存缓存？如何限制缓存的大小？

4. [x] 如何使用 pingora-load-balancing 为一组上游服务器配置健康检查？可以自定义健康检查的请求和判断逻辑吗？

5. [x] 如果内置的负载均衡算法不满足需求，我是否可以实现自定义的 SelectionAlgorithm？

6. [x] 如何使用 pingora-timeout 为到上游服务器的连接和请求设置合理的超时时间？

7. [x] 如何配置和使用 pingora-pool 来管理到上游服务器的连接池，以减少连接建立的开销？

8. [x] 我希望对某些 API 接口进行速率限制，或者限制来自单个 IP 的并发连接数，可以如何利用 pingora-limits crate (或自行实现) 来达到目的？

9. [x] Pingora 对 HTTP/2 的支持程度如何？在我的应用中启用 HTTP/2 (包括对下游和对上游) 需要哪些配置？

10. [x] 我需要在处理一个请求时，额外向其他内部服务发起请求并聚合结果，应该如何使用 Pingora 的子请求 (subrequest) 功能？

11. [x] 如何将 Pingora 服务接入现有的监控体系？例如，如何通过 HttpApp 暴露 Prometheus 指标端点？

## 构建具体应用场景示例

1. [x] 请给出一个最简单的反向代理的 Pingora 实现骨架，它将所有请求转发到单个上游。

2. [x] 如何扩展上述反向代理，使其能够根据请求路径将请求路由到不同的上游服务组？

3. [x] 我想构建一个 API 网关，它需要实现请求认证（例如检查 JWT Token）、请求转换和基本的 API 限流，使用 Pingora 该如何入手？

4. [x] 如何使用 Pingora 实现一个简单的静态文件服务器，能够提供指定目录下的文件访问？

5. [x] 如果我想在代理过程中对 JSON 请求体或响应体进行修改（例如添加字段、过滤敏感信息），应该如何在 request_body_filter 或 response_body_filter 中安全地操作这些数据流？

6. [x] 如何使用 Pingora 实现一个简单的 WebSocket 代理？

7. [x] 我能否使用 Pingora 构建非 HTTP 的 TCP 代理服务？如果可以，需要关注哪些不同的点？

## 调试、测试与部署

1. [x] 在开发 Pingora 应用时，有哪些推荐的调试方法和工具可以帮助我快速定位问题？

2. [x] 如何有效地利用 Pingora 的日志（特别是 RUST_LOG 环境变量和 request_summary）来追踪请求的完整处理流程和诊断错误？

3. [x] 为 Pingora 应用编写单元测试和集成测试的最佳实践是什么？如何模拟客户端请求和上游响应？

4. [x] 将 Pingora 服务部署到生产环境时，有哪些推荐的系统配置和安全加固措施？

5. [x] 如何监控 Pingora 服务的性能指标（例如请求延迟、错误率、资源使用情况）？

6. [x] 如果我的 Pingora 应用出现性能瓶颈或内存泄漏，应该从哪些方面入手进行分析和优化？
