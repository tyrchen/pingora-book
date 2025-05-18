# HTTP 缓存

在前面的章节中，我们已经学习了 Pingora 的基本代理功能、请求和响应处理、错误处理以及配置管理。本章将深入探讨 Pingora 的 HTTP 缓存功能，这是构建高性能代理服务的关键特性之一。

HTTP 缓存可以显著提高代理性能，减少对上游服务器的请求，降低带宽消耗，并减少用户感知的延迟。Pingora 提供了强大而灵活的缓存机制，允许你精细控制缓存行为。

## HTTP 缓存基础

在深入 Pingora 的缓存实现之前，让我们先简要回顾一下 HTTP 缓存的基础概念：

1. **缓存键（Cache Key）**：用于标识缓存条目的唯一键，通常基于请求的 URL、方法、头部等。
2. **缓存元数据（Cache Metadata）**：包含缓存条目的元信息，如创建时间、过期时间、响应头等。
3. **缓存新鲜度（Freshness）**：确定缓存内容是否仍然有效的机制，通常通过 `max-age` 或过期时间控制。
4. **条件请求（Conditional Requests）**：使用 `If-Modified-Since` 或 `If-None-Match` 等头部验证缓存是否仍然有效。
5. **变体（Variance）**：处理相同 URL 但因不同请求头（如 `Accept-Encoding` 或 `Accept-Language`）而产生不同响应的机制。

## 启用 HTTP 缓存

要在 Pingora 中启用 HTTP 缓存，需要实现 `ProxyHttp` trait 的几个关键方法：

1. `request_cache_filter`：决定请求是否可缓存，并配置缓存后端
2. `cache_key_callback`：生成用于缓存查找的键
3. `response_cache_filter`：决定响应是否应该被缓存
4. `cache_vary_filter`：处理响应的变体缓存

让我们逐个探讨这些方法的实现。

### request_cache_filter 方法

`request_cache_filter` 方法用于决定是否为当前请求启用缓存，并配置要使用的缓存后端：

```rust
fn request_cache_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
    // 只缓存 GET 和 HEAD 请求
    if !matches!(session.req_header().method, Method::GET | Method::HEAD) {
        return Ok(());
    }

    // 检查是否有特定头部表示不使用缓存
    if session.get_header_bytes("Cache-Control") == b"no-cache" {
        return Ok(());
    }

    // 启用内存缓存，其中 MEMORY_CACHE 是一个预先创建的静态缓存实例
    // 这里的 None 参数是可选的逐出管理器（eviction manager）
    session.cache.enable(&*MEMORY_CACHE, None, None, None);

    // 可选：设置缓存文件的最大大小
    session.cache.set_max_file_size_bytes(5_000_000); // 5MB

    Ok(())
}
```

在这个例子中，我们使用静态的内存缓存实例，可以这样定义：

```rust
use pingora_cache::MemCache;
use once_cell::sync::Lazy;

// 创建一个静态的内存缓存实例
static MEMORY_CACHE: Lazy<MemCache> = Lazy::new(|| MemCache::new());
```

### cache_key_callback 方法

`cache_key_callback` 方法负责生成缓存键，该键用于查找缓存中的条目：

```rust
fn cache_key_callback(&self, session: &Session, _ctx: &mut Self::CTX) -> Result<CacheKey> {
    let req_header = session.req_header();

    // 默认的缓存键基于请求的 URL 和方法
    // 但你可以自定义这个行为
    let mut key = CacheKey::default(req_header);

    // 可选：添加额外的元素到缓存键
    // 例如，考虑 Cookie 头的特定部分
    if let Some(cookie) = req_header.headers.get("cookie") {
        if let Ok(cookie_str) = cookie.to_str() {
            if let Some(session_id) = extract_session_id(cookie_str) {
                key.add_extra(session_id.as_bytes());
            }
        }
    }

    // 可选：根据某些条件排除某些请求
    if req_header.uri.path().starts_with("/admin") {
        return Err(Error::msg("Admin pages are not cacheable"));
    }

    Ok(key)
}

// 辅助函数：从 cookie 字符串中提取 session_id
fn extract_session_id(cookie_str: &str) -> Option<String> {
    cookie_str
        .split(';')
        .map(|s| s.trim())
        .find(|s| s.starts_with("session_id="))
        .map(|s| s.replacen("session_id=", "", 1))
}
```

### response_cache_filter 方法

`response_cache_filter` 方法用于决定是否应当缓存来自上游服务器的响应：

```rust
use pingora_cache::RespCacheable::{self, Cacheable, Uncacheable};
use pingora_cache::NoCacheReason;
use pingora_cache::{CacheMeta, CacheMetaDefaults};

// 定义缓存默认值（在结构体外部）
const CACHE_DEFAULTS: CacheMetaDefaults = CacheMetaDefaults::new(
    |status| match status {
        StatusCode::OK => Some(3600),          // 200 响应缓存 1 小时
        StatusCode::NOT_FOUND => Some(300),    // 404 响应缓存 5 分钟
        _ => None,                             // 其他状态码不缓存
    },
    60,   // stale-while-revalidate 60 秒
    600,  // stale-if-error 600 秒
);

fn response_cache_filter(
    &self,
    session: &Session,
    resp: &ResponseHeader,
    _ctx: &mut Self::CTX,
) -> Result<RespCacheable> {
    // 检查响应是否可缓存

    // 1. 某些状态码不适合缓存
    if !matches!(resp.status(), StatusCode::OK | StatusCode::NOT_FOUND | StatusCode::MOVED_PERMANENTLY) {
        return Ok(Uncacheable(NoCacheReason::Status));
    }

    // 2. 检查 Cache-Control 头
    if let Some(cc) = resp.headers.get("Cache-Control") {
        if let Ok(cc_str) = cc.to_str() {
            if cc_str.contains("private") || cc_str.contains("no-store") {
                return Ok(Uncacheable(NoCacheReason::Private));
            }
        }
    }

    // 3. 检查 Authorization 头
    let has_authorization = session.req_header().headers.contains_key("Authorization");

    // 使用 Pingora 的缓存控制解析和默认值创建元数据
    // CacheControl::from_resp_headers 会解析响应头中的缓存控制指令
    let cache_control = cache_control::CacheControl::from_resp_headers(resp);

    // 应用缓存规则，生成缓存元数据
    let cache_result = filters::resp_cacheable(
        cache_control.as_ref(),
        resp,
        has_authorization,
        &CACHE_DEFAULTS,
    );

    Ok(cache_result)
}
```

### cache_vary_filter 方法

`cache_vary_filter` 方法用于处理响应的变体。当上游服务器使用 `Vary` 头部指示响应可能因不同的请求头值而变化时，我们需要为每个变体创建不同的缓存键：

```rust
fn cache_vary_filter(
    &self,
    meta: &CacheMeta,
    _ctx: &mut Self::CTX,
    req: &RequestHeader,
) -> Option<HashBinary> {
    // 如果没有 Vary 头，不需要变体键
    let vary_headers = meta.headers().get_all("Vary");
    if vary_headers.is_empty() {
        return None;
    }

    // 创建变体键构建器
    let mut key = VarianceBuilder::new();

    // 处理所有 Vary 头部
    for vary in vary_headers {
        if let Ok(vary_str) = vary.to_str() {
            for header_name in vary_str.split(',').map(|s| s.trim().to_lowercase()) {
                // 考虑我们允许的 Vary 头部列表
                if ALLOWED_VARY_HEADERS.contains(&header_name.as_str()) {
                    // 添加请求头的值到变体键
                    key.add_value(
                        &header_name,
                        req.headers
                            .get(&header_name)
                            .map(|v| v.as_bytes())
                            .unwrap_or(&[]),
                    );
                }
            }
        }
    }

    // 最终化并返回变体键
    Some(key.finalize())
}

// 我们允许的 Vary 头部列表
const ALLOWED_VARY_HEADERS: [&str; 3] = [
    "accept-encoding",
    "accept-language",
    "user-agent",
];
```

## 管理缓存行为

除了基本的缓存过滤器外，Pingora 还提供了其他几个方法来控制缓存行为：

### cache_hit_filter 方法

当缓存命中时，`cache_hit_filter` 方法被调用，允许你记录缓存命中或强制使缓存条目失效：

```rust
async fn cache_hit_filter(
    &self,
    session: &Session,
    meta: &CacheMeta,
    is_fresh: bool,
    ctx: &mut Self::CTX,
) -> Result<Option<ForcedInvalidationKind>> {
    // 记录缓存命中
    log::info!(
        "Cache hit for {}: is_fresh={}, age={}s",
        session.req_header().uri,
        is_fresh,
        SystemTime::now()
            .duration_since(meta.updated())
            .unwrap_or_default()
            .as_secs()
    );

    // 检查特殊头部以强制缓存失效（用于测试或调试）
    if session.get_header_bytes("X-Force-Cache-Miss") == b"true" {
        return Ok(Some(ForcedInvalidationKind::ForceMiss));
    }

    // 检查是否需要强制使缓存过期（但仍然使用它）
    if session.get_header_bytes("X-Force-Revalidate") == b"true" {
        return Ok(Some(ForcedInvalidationKind::ForceExpired));
    }

    // 正常使用缓存
    Ok(None)
}
```

### cache_not_modified_filter 方法

`cache_not_modified_filter` 方法用于处理条件请求，决定是否可以返回 304 Not Modified 响应：

```rust
fn cache_not_modified_filter(
    &self,
    session: &Session,
    resp: &ResponseHeader,
    _ctx: &mut Self::CTX,
) -> Result<bool> {
    // 使用 Pingora 的默认实现
    Ok(
        pingora_core::protocols::http::conditional_filter::not_modified_filter(
            session.req_header(),
            resp,
        )
    )

    // 或者，你可以实现自定义逻辑：
    /*
    let req = session.req_header();

    // 检查 If-None-Match
    if let Some(if_none_match) = req.headers.get("If-None-Match") {
        if let Some(etag) = resp.headers.get("ETag") {
            if if_none_match == etag {
                return Ok(true); // 可以返回 304
            }
        }
    }

    // 检查 If-Modified-Since
    if let Some(if_modified_since) = req.headers.get("If-Modified-Since") {
        if let Some(last_modified) = resp.headers.get("Last-Modified") {
            if is_not_modified(if_modified_since, last_modified) {
                return Ok(true); // 可以返回 304
            }
        }
    }

    Ok(false) // 不能返回 304，需要完整响应
    */
}
```

## 配置内存缓存大小

Pingora 的 `MemCache` 允许你限制缓存使用的内存大小。这是在创建缓存实例时配置的：

```rust
use pingora_cache::MemCache;
use once_cell::sync::Lazy;

// 创建一个最大大小为 100MB 的内存缓存
static MEMORY_CACHE: Lazy<MemCache> = Lazy::new(|| MemCache::new(100 * 1024 * 1024));
```

此外，你还可以使用 `pingora_cache::eviction` 模块中的逻辑来管理缓存逐出策略：

```rust
use pingora_cache::eviction::lru::Manager as EvictionManager;

// 创建一个 8MB 容量的 LRU 逐出管理器
static EVICTION_MANAGER: Lazy<EvictionManager> = Lazy::new(|| EvictionManager::new(8 * 1024 * 1024));

// 在 request_cache_filter 中使用
fn request_cache_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
    // 启用带有逐出管理器的缓存
    session.cache.enable(
        &*MEMORY_CACHE,
        Some(&*EVICTION_MANAGER as &'static (dyn pingora_cache::eviction::EvictionManager + Sync)),
        None,
        None,
    );
    Ok(())
}
```

## 缓存预测

在某些情况下，提前知道请求是否可能产生可缓存的响应是有益的。Pingora 提供了 `predictor` 模块来帮助预测响应的可缓存性：

```rust
use pingora_cache::predictor::Predictor;

// 创建一个预测器，记录最近 5 个请求的路径，内存大小为 32 条目
static CACHE_PREDICTOR: Lazy<Predictor<32>> = Lazy::new(|| Predictor::new(5, None));

// 在 request_cache_filter 中使用
fn request_cache_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
    session.cache.enable(
        &*MEMORY_CACHE,
        Some(&*EVICTION_MANAGER),
        Some(&*CACHE_PREDICTOR as &'static (dyn pingora_cache::predictor::CacheablePredictor + Sync)),
        None,
    );
    Ok(())
}
```

预测器帮助 Pingora 避免为不太可能可缓存的响应分配资源，从而提高缓存效率。

## 避免缓存冲突（Cache Stampede）

当多个并发请求尝试缓存同一资源时，可能会发生缓存冲突。Pingora 提供了缓存锁机制来防止这种情况：

```rust
use pingora_cache::lock::CacheLock;
use std::time::Duration;

// 创建一个缓存锁，锁超时为 2 秒
static CACHE_LOCK: Lazy<Box<dyn pingora_cache::lock::CacheKeyLockImpl + Send + Sync>> =
    Lazy::new(|| CacheLock::new_boxed(Duration::from_secs(2)));

// 在 request_cache_filter 中使用
fn request_cache_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
    session.cache.enable(
        &*MEMORY_CACHE,
        Some(&*EVICTION_MANAGER),
        Some(&*CACHE_PREDICTOR),
        Some(CACHE_LOCK.as_ref()),
    );
    Ok(())
}
```

使用缓存锁确保只有一个请求会生成缓存内容，其他并发请求会等待直到内容被缓存。

## 完整的缓存实现示例

下面是一个完整的实现示例，展示了如何在 Pingora 应用中集成 HTTP 缓存：

```rust
use pingora::prelude::*;
use pingora_cache::{
    MemCache, CacheKey, CacheMeta, CacheMetaDefaults, RespCacheable,
    NoCacheReason, VarianceBuilder, ForcedInvalidationKind,
    eviction::lru::Manager as EvictionManager,
    predictor::Predictor,
    lock::CacheLock,
    cache_control,
    filters,
};
use pingora_proxy::ProxyHttp;
use http::StatusCode;
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

// 创建缓存和相关组件
static MEMORY_CACHE: Lazy<MemCache> = Lazy::new(|| MemCache::new(100 * 1024 * 1024));
static EVICTION_MANAGER: Lazy<EvictionManager> = Lazy::new(|| EvictionManager::new(8 * 1024 * 1024));
static CACHE_PREDICTOR: Lazy<Predictor<32>> = Lazy::new(|| Predictor::new(5, None));
static CACHE_LOCK: Lazy<Box<dyn pingora_cache::lock::CacheKeyLockImpl + Send + Sync>> =
    Lazy::new(|| CacheLock::new_boxed(Duration::from_secs(2)));

const CACHE_DEFAULTS: CacheMetaDefaults = CacheMetaDefaults::new(
    |status| match status {
        StatusCode::OK => Some(3600),          // 200 响应缓存 1 小时
        StatusCode::NOT_FOUND => Some(300),    // 404 响应缓存 5 分钟
        _ => None,                             // 其他状态码不缓存
    },
    60,   // stale-while-revalidate 60 秒
    600,  // stale-if-error 600 秒
);

// 代理实现
struct CachingProxy;

impl ProxyHttp for CachingProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    // 请求缓存过滤器
    fn request_cache_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
        // 只缓存 GET 和 HEAD 请求
        if !matches!(session.req_header().method, Method::GET | Method::HEAD) {
            return Ok(());
        }

        // 检查是否有特定头部表示不使用缓存
        if session.get_header_bytes("Cache-Control") == b"no-cache" {
            return Ok(());
        }

        // 启用缓存
        session.cache.enable(
            &*MEMORY_CACHE,
            Some(&*EVICTION_MANAGER as &'static (dyn pingora_cache::eviction::EvictionManager + Sync)),
            Some(&*CACHE_PREDICTOR as &'static (dyn pingora_cache::predictor::CacheablePredictor + Sync)),
            Some(CACHE_LOCK.as_ref()),
        );

        // 设置缓存文件的最大大小
        session.cache.set_max_file_size_bytes(5_000_000); // 5MB

        Ok(())
    }

    // 缓存键回调
    fn cache_key_callback(&self, session: &Session, _ctx: &mut Self::CTX) -> Result<CacheKey> {
        let req_header = session.req_header();

        // 使用默认缓存键实现
        Ok(CacheKey::default(req_header))
    }

    // 响应缓存过滤器
    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        // 检查响应是否可缓存

        // 1. 某些状态码不适合缓存
        if !matches!(resp.status(), StatusCode::OK | StatusCode::NOT_FOUND | StatusCode::MOVED_PERMANENTLY) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Status));
        }

        // 2. 检查 Cache-Control 头
        if let Some(cc) = resp.headers.get("Cache-Control") {
            if let Ok(cc_str) = cc.to_str() {
                if cc_str.contains("private") || cc_str.contains("no-store") {
                    return Ok(RespCacheable::Uncacheable(NoCacheReason::Private));
                }
            }
        }

        // 3. 检查 Authorization 头
        let has_authorization = session.req_header().headers.contains_key("Authorization");

        // 使用 Pingora 的缓存控制解析和默认值创建元数据
        let cache_control = cache_control::CacheControl::from_resp_headers(resp);

        // 应用缓存规则，生成缓存元数据
        let cache_result = filters::resp_cacheable(
            cache_control.as_ref(),
            resp,
            has_authorization,
            &CACHE_DEFAULTS,
        );

        Ok(cache_result)
    }

    // 缓存变体过滤器
    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        _ctx: &mut Self::CTX,
        req: &RequestHeader,
    ) -> Option<HashBinary> {
        // 如果没有 Vary 头，不需要变体键
        let vary_headers = meta.headers().get_all("Vary");
        if vary_headers.is_empty() {
            return None;
        }

        // 创建变体键构建器
        let mut key = VarianceBuilder::new();

        // 处理所有 Vary 头部
        for vary in vary_headers {
            if let Ok(vary_str) = vary.to_str() {
                for header_name in vary_str.split(',').map(|s| s.trim().to_lowercase()) {
                    // 添加请求头的值到变体键
                    key.add_value(
                        &header_name,
                        req.headers
                            .get(&header_name)
                            .map(|v| v.as_bytes())
                            .unwrap_or(&[]),
                    );
                }
            }
        }

        // 最终化并返回变体键
        Some(key.finalize())
    }

    // 缓存命中过滤器
    async fn cache_hit_filter(
        &self,
        session: &Session,
        meta: &CacheMeta,
        is_fresh: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<Option<ForcedInvalidationKind>> {
        // 记录缓存命中
        log::info!(
            "Cache hit for {}: is_fresh={}, age={}s",
            session.req_header().uri,
            is_fresh,
            SystemTime::now()
                .duration_since(meta.updated())
                .unwrap_or_default()
                .as_secs()
        );

        Ok(None)
    }

    // 上游服务器选择
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // 简单地连接到一个上游服务器
        let peer = Box::new(HttpPeer::new(
            ("example.com", 443),
            true, // 使用 HTTPS
            "example.com".to_string(),
        ));

        Ok(peer)
    }

    // 其他必要的方法实现...
}

fn main() -> Result<()> {
    // 初始化日志
    env_logger::init();

    // 创建服务器
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建代理服务
    let mut proxy_service = pingora_proxy::http_proxy_service(
        &server.configuration,
        CachingProxy,
    );

    // 配置监听地址
    proxy_service.add_tcp("0.0.0.0:8080");

    // 添加服务并运行
    server.add_service(proxy_service);
    server.run_forever();

    Ok(())
}
```

## 总结

Pingora 的 HTTP 缓存系统提供了强大的功能，允许你精细控制缓存行为。通过实现 `ProxyHttp` trait 的相关方法，你可以：

1. 决定哪些请求可以使用缓存
2. 自定义缓存键的生成
3. 控制哪些响应应该被缓存以及缓存多长时间
4. 处理响应变体
5. 管理缓存命中行为
6. 限制缓存大小并配置逐出策略

这些功能允许你构建高性能的代理服务，显著减少对上游服务器的请求，提高响应速度，降低带宽消耗。对于大规模部署，适当的缓存策略可以极大地提高整体系统性能和稳定性。
