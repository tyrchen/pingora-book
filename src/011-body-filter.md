# 请求与响应体处理

在前面的章节中，我们已经学习了如何处理 HTTP 请求和响应的头部信息。本章将深入探讨如何使用 Pingora 的过滤方法来检查和修改请求体（Request Body）和响应体（Response Body）。这些功能对于实现内容验证、数据转换、内容增强等高级代理功能至关重要。

## 请求体处理：request_body_filter 方法

`request_body_filter` 方法允许你在请求体被发送到上游服务器之前检查和修改它。与请求头部处理不同，请求体通常以流的形式处理，这意味着 `request_body_filter` 方法可能会被多次调用，每次处理请求体的一部分（chunk）。

方法签名如下：

```rust
async fn request_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut Self::CTX,
) -> Result<()>
where
    Self::CTX: Send + Sync;
```

参数说明：

- `session`：当前会话，包含请求的完整信息
- `body`：当前收到的请求体部分，可修改
- `end_of_stream`：表示这是否是请求体的最后一部分
- `ctx`：请求上下文，可用于在不同处理阶段之间共享数据

### request_body_filter 的工作方式

理解 `request_body_filter` 方法的关键是认识到它处理的是请求体的片段而非完整请求体：

1. 当客户端发送的请求包含请求体时，Pingora 会将请求体分成多个部分逐一处理
2. 对于每个部分，Pingora 都会调用 `request_body_filter` 方法
3. 最后一个部分调用时，`end_of_stream` 参数会被设置为 `true`

这种逐部分处理的方式允许 Pingora 高效地处理任意大小的请求体，而不需要在内存中一次性加载整个请求体。

### 请求体缓冲与处理

由于请求体是分块处理的，如果需要处理完整的请求体（例如验证 JSON 格式或执行复杂转换），你需要在上下文中缓冲这些块，直到接收到完整的请求体。以下是一个示例，展示如何缓冲和处理 JSON 请求体：

```rust
struct JsonValidatorContext {
    // 用于缓冲请求体的字段
    request_body_buffer: Vec<u8>,
    // 其他上下文字段...
}

impl JsonValidatorContext {
    fn new() -> Self {
        Self {
            request_body_buffer: Vec::new(),
            // 初始化其他字段...
        }
    }
}

async fn request_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut JsonValidatorContext,
) -> Result<()> {
    // 检查内容类型是否是 JSON
    if !ctx.is_json_checked {
        ctx.is_json_checked = true;

        let content_type = session
            .req_header()
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        ctx.is_json_content = content_type.contains("application/json");

        // 如果不是 JSON，不需要进一步处理
        if !ctx.is_json_content {
            return Ok(());
        }
    }

    // 如果是 JSON 内容，缓冲请求体
    if ctx.is_json_content {
        if let Some(chunk) = body.as_ref() {
            ctx.request_body_buffer.extend_from_slice(chunk);
        }

        // 如果是最后一个块，验证完整的 JSON
        if end_of_stream {
            // 尝试解析 JSON
            match serde_json::from_slice::<serde_json::Value>(&ctx.request_body_buffer) {
                Ok(json_value) => {
                    // JSON 有效，可以进行额外的验证
                    if let Err(e) = self.validate_json(&json_value) {
                        // JSON 验证失败，返回错误响应
                        let error_msg = format!("JSON 验证失败: {}", e);
                        let response = format!("{{\"error\": \"{}\"}}", error_msg);

                        let mut resp = ResponseHeader::build(StatusCode::BAD_REQUEST, None)?;
                        resp.insert_header(header::CONTENT_TYPE, "application/json")?;

                        session.write_response_header(Box::new(resp)).await?;
                        session.write_response_body(Bytes::from(response), true).await?;

                        // 请求已处理，更新状态
                        ctx.request_processed = true;

                        // 清空请求体，阻止其被转发到上游
                        *body = None;

                        return Err(Error::msg("JSON 验证失败"));
                    }

                    // 可以在这里修改 JSON
                    if self.should_modify_json {
                        let modified_json = self.modify_json(json_value)?;
                        let modified_bytes = serde_json::to_vec(&modified_json)?;

                        // 替换原始请求体
                        *body = Some(Bytes::from(modified_bytes));
                    }
                }
                Err(e) => {
                    // JSON 解析失败，返回错误响应
                    let error_msg = format!("无效的 JSON: {}", e);
                    let response = format!("{{\"error\": \"{}\"}}", error_msg);

                    let mut resp = ResponseHeader::build(StatusCode::BAD_REQUEST, None)?;
                    resp.insert_header(header::CONTENT_TYPE, "application/json")?;

                    session.write_response_header(Box::new(resp)).await?;
                    session.write_response_body(Bytes::from(response), true).await?;

                    // 请求已处理，更新状态
                    ctx.request_processed = true;

                    // 清空请求体，阻止其被转发到上游
                    *body = None;

                    return Err(Error::msg("无效的 JSON"));
                }
            }
        }
    }

    Ok(())
}

// JSON 验证逻辑
fn validate_json(&self, json: &serde_json::Value) -> Result<()> {
    // 检查必需字段
    match json.as_object() {
        Some(obj) => {
            // 检查必要字段是否存在
            if !obj.contains_key("user_id") {
                return Err(Error::msg("缺少必要字段 'user_id'"));
            }

            // 检查字段类型
            if let Some(age) = obj.get("age") {
                if !age.is_number() {
                    return Err(Error::msg("'age' 必须是数字"));
                }
            }

            // 其他验证逻辑...

            Ok(())
        }
        None => Err(Error::msg("请求必须是 JSON 对象")),
    }
}

// JSON 修改逻辑
fn modify_json(&self, mut json: serde_json::Value) -> Result<serde_json::Value> {
    if let Some(obj) = json.as_object_mut() {
        // 添加或修改字段
        obj.insert(
            "processed_at".to_string(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );

        // 删除敏感字段
        obj.remove("password");
    }

    Ok(json)
}
```

### 请求体限制和过滤

另一个常见用例是限制请求体的大小或过滤有害内容。以下是一个示例：

```rust
struct ContentFilterContext {
    request_size: usize,
    max_request_size: usize,
}

impl ContentFilterContext {
    fn new(max_size: usize) -> Self {
        Self {
            request_size: 0,
            max_request_size: max_size,
        }
    }
}

async fn request_body_filter(
    &self,
    _session: &mut Session,
    body: &mut Option<Bytes>,
    _end_of_stream: bool,
    ctx: &mut ContentFilterContext,
) -> Result<()> {
    if let Some(chunk) = body.as_ref() {
        // 累计请求体大小
        ctx.request_size += chunk.len();

        // 检查请求体大小是否超过限制
        if ctx.request_size > ctx.max_request_size {
            // 超过大小限制，返回错误
            return Err(Error::msg(format!(
                "请求体超过大小限制 {} 字节",
                ctx.max_request_size
            )));
        }

        // 检查有害内容
        let chunk_str = String::from_utf8_lossy(chunk);
        if chunk_str.contains("<script>") || chunk_str.contains("eval(") {
            // 检测到潜在的 XSS 攻击
            return Err(Error::msg("请求包含潜在的恶意内容"));
        }
    }

    Ok(())
}
```

## 响应体处理

除了请求体处理，Pingora 还提供了两种方法来处理响应体：

1. `upstream_response_body_filter`：在从上游服务器收到响应体后立即调用，在缓存之前
2. `response_body_filter`：在将响应体发送给客户端之前调用，在缓存之后

这两个方法的签名和行为与 `request_body_filter` 类似，但有不同的用途和调用时机。

### upstream_response_body_filter 方法

`upstream_response_body_filter` 方法允许你在响应可能被缓存之前修改响应体：

```rust
fn upstream_response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut Self::CTX,
) -> Result<()>;
```

注意这是一个同步方法，不是 `async`。这意味着任何在此方法中的长时间运行的操作都会阻塞请求处理线程。

### response_body_filter 方法

`response_body_filter` 方法允许你在响应发送给客户端之前修改响应体，包括从缓存提供的响应：

```rust
fn response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut Self::CTX,
) -> Result<Option<Duration>>
where
    Self::CTX: Send + Sync;
```

这个方法与 `upstream_response_body_filter` 的主要区别在于：

1. 它是在缓存之后调用的，因此也适用于从缓存提供的响应
2. 它返回一个 `Option<Duration>`，允许你指定在发送响应体之前的延迟时间
3. 它是一个同步方法，不支持异步操作

### 响应体修改示例

以下是一个示例，展示如何使用 `response_body_filter` 方法将 JSON 响应转换为 YAML 格式：

```rust
struct Json2YamlContext {
    // 用于缓冲响应体的字段
    response_buffer: Vec<u8>,
    is_json_content: bool,
    content_checked: bool,
}

impl Json2YamlContext {
    fn new() -> Self {
        Self {
            response_buffer: Vec::new(),
            is_json_content: false,
            content_checked: false,
        }
    }
}

fn response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut Json2YamlContext,
) -> Result<Option<Duration>> {
    // 检查内容类型
    if !ctx.content_checked {
        ctx.content_checked = true;

        if let Some(resp) = session.response_written() {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            ctx.is_json_content = content_type.contains("application/json");

            // 如果是 JSON 且我们要转换为 YAML，需要修改内容类型
            if ctx.is_json_content && session.response_written_mut().is_some() {
                // 更新内容类型
                if let Some(resp) = session.response_written_mut() {
                    resp.insert_header(header::CONTENT_TYPE, "application/yaml")?;
                    // 由于我们要修改响应体，移除内容长度头
                    resp.remove_header(header::CONTENT_LENGTH);
                }
            }
        }
    }

    // 如果是 JSON 内容，缓冲响应体
    if ctx.is_json_content {
        if let Some(chunk) = body.as_ref() {
            ctx.response_buffer.extend_from_slice(chunk);

            // 清空当前块，避免发送原始数据
            if !chunk.is_empty() {
                *body = Some(Bytes::new());
            }
        }

        // 如果是最后一个块，处理完整的响应体
        if end_of_stream {
            // 尝试将 JSON 转换为 YAML
            match serde_json::from_slice::<serde_json::Value>(&ctx.response_buffer) {
                Ok(json_value) => {
                    match serde_yaml::to_string(&json_value) {
                        Ok(yaml_str) => {
                            // 替换响应体
                            *body = Some(Bytes::from(yaml_str));
                        }
                        Err(e) => {
                            // YAML 转换失败，返回原始 JSON
                            warn!("JSON 到 YAML 转换失败: {}", e);
                            *body = Some(Bytes::from(ctx.response_buffer.clone()));
                        }
                    }
                }
                Err(e) => {
                    // JSON 解析失败，返回原始数据
                    warn!("JSON 解析失败: {}", e);
                    *body = Some(Bytes::from(ctx.response_buffer.clone()));
                }
            }
        }
    }

    Ok(None) // 没有延迟
}
```

### 响应体修改的注意事项

在修改响应体时，需要注意以下几点：

1. **内容长度头部**：如果修改了响应体大小，需要移除 `Content-Length` 头部或更新为新的长度
2. **内容类型**：如果改变了内容格式，应同时更新 `Content-Type` 头部
3. **流式处理**：记住响应体是分片处理的，完整的内容可能跨多个调用
4. **编码处理**：响应可能被压缩（如 gzip），需要解压后再处理
5. **性能考虑**：处理大型响应体可能会消耗大量内存，尽量采用流式处理

## 实际示例：内容增强代理

以下是一个更完整的例子，结合了请求和响应体处理，实现一个内容增强代理：

```rust
use bytes::Bytes;
use pingora_core::protocols::http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// 内容增强代理的上下文
struct ContentEnhancerContext {
    // 请求相关
    request_body_buffer: Vec<u8>,
    request_is_json: bool,

    // 响应相关
    response_body_buffer: Vec<u8>,
    response_is_json: bool,

    // 其他状态
    enhancement_applied: bool,
}

impl ContentEnhancerContext {
    fn new() -> Self {
        Self {
            request_body_buffer: Vec::new(),
            request_is_json: false,
            response_body_buffer: Vec::new(),
            response_is_json: false,
            enhancement_applied: false,
        }
    }
}

// 内容增强代理
struct ContentEnhancer;

#[async_trait]
impl ProxyHttp for ContentEnhancer {
    type CTX = ContentEnhancerContext;

    fn new_ctx(&self) -> Self::CTX {
        ContentEnhancerContext::new()
    }

    // 实现上游选择等其他必要方法...

    // 请求处理：检查请求头，确定是否为 JSON
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        req: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 检查内容类型
        if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
            if let Ok(content_type_str) = content_type.to_str() {
                ctx.request_is_json = content_type_str.contains("application/json");
            }
        }

        Ok(())
    }

    // 请求体处理：如果是 JSON，缓冲并可能修改
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if ctx.request_is_json {
            // 缓冲请求体
            if let Some(chunk) = body.as_ref() {
                ctx.request_body_buffer.extend_from_slice(chunk);
            }

            // 如果是最后一个块，可以处理完整的请求体
            if end_of_stream && !ctx.request_body_buffer.is_empty() {
                // 这里可以根据需要修改请求 JSON
                // 例如，添加额外字段、验证结构等

                // 示例：简单地验证 JSON 格式
                if let Err(e) = serde_json::from_slice::<serde_json::Value>(&ctx.request_body_buffer) {
                    return Err(Error::msg(format!("无效的 JSON 请求体: {}", e)));
                }
            }
        }

        Ok(())
    }

    // 响应头处理：检查响应是否为 JSON
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // 检查内容类型
        if let Some(content_type) = resp.headers().get(header::CONTENT_TYPE) {
            if let Ok(content_type_str) = content_type.to_str() {
                ctx.response_is_json = content_type_str.contains("application/json");
            }
        }

        Ok(())
    }

    // 响应体处理：如果是 JSON，增强内容
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        if ctx.response_is_json {
            // 缓冲响应体
            if let Some(chunk) = body.as_ref() {
                ctx.response_body_buffer.extend_from_slice(chunk);

                // 清空当前块，我们会在最后一块时替换完整内容
                if !chunk.is_empty() {
                    *body = Some(Bytes::new());
                }
            }

            // 如果是最后一个块，处理完整的响应体
            if end_of_stream {
                // 尝试解析 JSON
                match serde_json::from_slice::<serde_json::Value>(&ctx.response_body_buffer) {
                    Ok(mut json_value) => {
                        // 增强 JSON 内容
                        if let Some(obj) = json_value.as_object_mut() {
                            // 添加额外的元数据
                            obj.insert(
                                "enhanced_by".to_string(),
                                serde_json::Value::String("pingora-enhancer".to_string()),
                            );
                            obj.insert(
                                "enhanced_at".to_string(),
                                serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
                            );

                            // 如果处理了请求 JSON，可以从请求中提取信息添加到响应
                            if ctx.request_is_json && !ctx.request_body_buffer.is_empty() {
                                if let Ok(req_json) = serde_json::from_slice::<serde_json::Value>(&ctx.request_body_buffer) {
                                    if let Some(req_obj) = req_json.as_object() {
                                        // 例如，添加请求中的一些元数据
                                        if let Some(user_id) = req_obj.get("user_id") {
                                            obj.insert(
                                                "requested_by".to_string(),
                                                user_id.clone(),
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        // 将增强后的 JSON 转换回字节
                        match serde_json::to_vec(&json_value) {
                            Ok(enhanced_json) => {
                                ctx.enhancement_applied = true;
                                *body = Some(Bytes::from(enhanced_json));
                            }
                            Err(e) => {
                                // 转换失败，使用原始响应
                                warn!("JSON 增强失败: {}", e);
                                *body = Some(Bytes::from(ctx.response_body_buffer.clone()));
                            }
                        }
                    }
                    Err(e) => {
                        // JSON 解析失败，使用原始响应
                        warn!("JSON 解析失败: {}", e);
                        *body = Some(Bytes::from(ctx.response_body_buffer.clone()));
                    }
                }
            }
        }

        Ok(None) // 没有延迟
    }

    // 记录处理状态到日志
    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&Error>,
        ctx: &mut Self::CTX,
    ) {
        // 记录内容增强情况
        if ctx.enhancement_applied {
            info!(
                "增强了响应内容: client={}, path={}",
                session.client_addr().map_or("unknown".to_string(), |addr| addr.to_string()),
                session.req_header().uri().path()
            );
        }

        // 记录错误
        if let Some(e) = error {
            error!(
                "处理请求时发生错误: {} client={}, path={}",
                e,
                session.client_addr().map_or("unknown".to_string(), |addr| addr.to_string()),
                session.req_header().uri().path()
            );
        }
    }
}
```

## 性能考虑

处理请求和响应体可能会对代理性能产生重大影响，尤其是在处理大型负载或高流量时。以下是一些性能优化建议：

1. **有选择地处理**：通过检查请求路径、方法或内容类型，只对需要处理的请求应用过滤器
2. **避免不必要的缓冲**：只在必要时缓冲整个请求/响应体
3. **流式处理**：尽可能进行流式处理，避免内存中累积大量数据
4. **异步处理**：利用 `request_body_filter` 的异步特性将耗时操作卸载到其他线程
5. **设置大小限制**：对缓冲区大小设置限制，防止恶意大型请求消耗过多资源

## 总结

在本章中，我们学习了如何使用 Pingora 的 `request_body_filter`、`upstream_response_body_filter` 和 `response_body_filter` 方法来处理 HTTP 请求和响应的主体内容。这些方法让我们能够：

1. 验证和转换 JSON 请求体
2. 限制请求大小和过滤恶意内容
3. 修改响应内容，例如将 JSON 转换为其他格式
4. 在响应中注入额外信息或元数据

需要特别注意的是，这些方法处理的是流式数据，每次只接收请求/响应体的一部分。如果需要处理完整的内容，需要手动缓冲所有部分，直到收到最后一块（`end_of_stream` 为 `true`）。

通过掌握这些请求和响应体处理技术，你可以构建功能强大的代理服务，如内容过滤器、格式转换器、数据验证网关等复杂应用。
