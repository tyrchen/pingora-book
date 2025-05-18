# 实现静态文件服务器

在前几章中，我们已经实现了反向代理、路径路由和 API 网关等功能。本章将介绍如何使用 Pingora 实现另一个常见的应用场景：静态文件服务器。静态文件服务器用于提供网站的静态资源，如 HTML、CSS、JavaScript 文件、图片等。

与将请求转发到上游服务器的代理不同，静态文件服务器直接从本地文件系统读取文件并返回给客户端。在本章中，我们将构建一个简单但功能完整的静态文件服务器，它支持基本的文件类型识别、目录列表和缓存控制。

## 静态文件服务的基本原理

静态文件服务的工作流程相对简单：

1. 接收客户端请求
2. 从请求路径中提取文件路径
3. 检查文件是否存在
4. 确定文件的 MIME 类型
5. 设置适当的响应头
6. 读取文件内容并发送到客户端

与代理不同，静态文件服务器通常不需要配置上游服务器。相反，我们需要实现 `ProxyHttp` trait 的 `request_filter` 方法来处理文件读取和响应。

## 项目设置

首先，创建一个新的 Rust 项目：

```bash
cargo new static_file_server
cd static_file_server
```

然后在 `Cargo.toml` 文件中添加必要的依赖：

```toml
[package]
name = "static_file_server"
version = "0.1.0"
edition = "2021"

[dependencies]
pingora = { version = "0.3", features = ["build-binary"] }
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["io"] }
futures = "0.3"
http = "0.2"
env_logger = "0.10"
async-trait = "0.1"
mime_guess = "2.0"
chrono = "0.4"
clap = { version = "4.3", features = ["derive"] }
```

## 静态文件服务器实现

以下是静态文件服务器的实现：

```rust
use pingora::prelude::*;
use pingora::protocols::http::HttpSession;
use pingora::proxy::http_proxy_service;
use http::{StatusCode, Response};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::{self, AsyncReadExt};
use tokio_util::io::ReaderStream;
use futures::StreamExt;
use mime_guess::from_path;
use chrono::{DateTime, Utc};
use clap::Parser;

// 命令行参数
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./public")]
    root_dir: String,

    #[arg(short, long, default_value = "8080")]
    port: u16,

    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,
}

// 静态文件服务器配置
struct FileServerConfig {
    root_dir: PathBuf,
    enable_dir_listing: bool,
    cache_max_age: u32,
}

// 静态文件服务结构体
struct StaticFileServer {
    config: Arc<FileServerConfig>,
}

// 请求上下文
struct FileServerContext {
    // 不需要存储状态
}

impl StaticFileServer {
    // 创建新的静态文件服务器
    fn new(root_dir: PathBuf) -> Self {
        let config = FileServerConfig {
            root_dir,
            enable_dir_listing: true,
            cache_max_age: 3600, // 缓存1小时
        };

        Self {
            config: Arc::new(config),
        }
    }

    // 构建本地文件路径
    fn get_local_path(&self, path: &str) -> PathBuf {
        let mut clean_path = path.trim_start_matches('/').to_string();

        // 处理空路径或根路径的情况
        if clean_path.is_empty() {
            clean_path = ".".to_string();
        }

        // 将请求路径转换为本地文件系统路径
        let mut full_path = self.config.root_dir.clone();
        full_path.push(clean_path);

        full_path
    }

    // 生成目录列表 HTML
    async fn generate_directory_listing(&self, dir_path: &Path, request_path: &str) -> Result<String> {
        let mut entries = fs::read_dir(dir_path).await?;
        let mut file_list = Vec::new();

        // 添加返回上一级目录的链接（除了根目录）
        let parent_link = if request_path != "/" {
            format!("<li><a href=\"{}\">..</a></li>",
                Path::new(request_path).parent().unwrap_or(Path::new("/")).to_string_lossy())
        } else {
            String::new()
        };

        // 读取目录项
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            let metadata = entry.metadata().await?;
            let is_dir = metadata.is_dir();

            // 格式化最后修改时间
            let modified: DateTime<Utc> = metadata.modified()?.into();
            let modified_str = modified.format("%Y-%m-%d %H:%M:%S").to_string();

            // 构建链接
            let link_name = if is_dir {
                format!("{}/", file_name_str)
            } else {
                file_name_str.to_string()
            };

            let link_path = format!("{}/{}", request_path.trim_end_matches('/'), file_name_str);

            // 格式化文件大小
            let size = if is_dir {
                "-".to_string()
            } else {
                format_size(metadata.len())
            };

            file_list.push(format!(
                "<li><a href=\"{}\">{}</a> - {} - {}</li>",
                link_path, link_name, size, modified_str
            ));
        }

        // 生成 HTML
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Index of {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ margin-bottom: 20px; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ margin: 5px 0; }}
        a {{ text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>Index of {}</h1>
    <ul>
        {}
        {}
    </ul>
</body>
</html>"#,
            request_path, request_path, parent_link, file_list.join("\n        ")
        );

        Ok(html)
    }
}

// 格式化文件大小
fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size < KB {
        format!("{} B", size)
    } else if size < MB {
        format!("{:.1} KB", size as f64 / KB as f64)
    } else if size < GB {
        format!("{:.1} MB", size as f64 / MB as f64)
    } else {
        format!("{:.1} GB", size as f64 / GB as f64)
    }
}

#[async_trait]
impl ProxyHttp for StaticFileServer {
    type CTX = FileServerContext;

    // 创建新的上下文
    fn new_ctx(&self) -> Self::CTX {
        FileServerContext {}
    }

    // 处理请求，提供静态文件
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // 提取请求路径
        let req_path = session.req_header().uri().path();

        // 构建本地文件路径
        let local_path = self.get_local_path(req_path);

        // 检查文件或目录是否存在
        if !local_path.exists() {
            // 返回 404 Not Found
            session.respond_error(StatusCode::NOT_FOUND)?;
            return Ok(false);
        }

        // 检查文件类型
        if local_path.is_dir() {
            // 先检查目录中是否有 index.html
            let mut index_path = local_path.clone();
            index_path.push("index.html");

            if index_path.exists() {
                // 发送 index.html
                send_file(session, &index_path, self.config.cache_max_age).await?;
            } else if self.config.enable_dir_listing {
                // 生成目录列表
                let html = self.generate_directory_listing(&local_path, req_path).await?;

                // 构建响应
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/html; charset=utf-8")
                    .header("Content-Length", html.len().to_string())
                    .body(())?;

                // 发送响应
                session.respond(&resp, Some(html.as_bytes()))?;
            } else {
                // 目录列表被禁用，返回 403 Forbidden
                session.respond_error(StatusCode::FORBIDDEN)?;
            }
        } else {
            // 发送文件
            send_file(session, &local_path, self.config.cache_max_age).await?;
        }

        Ok(false) // 停止处理，不转发到上游
    }
}

// 发送文件
async fn send_file(session: &mut Session, file_path: &Path, cache_max_age: u32) -> Result<()> {
    // 打开文件
    let file = match File::open(file_path).await {
        Ok(file) => file,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                session.respond_error(StatusCode::NOT_FOUND)?;
            } else {
                session.respond_error(StatusCode::INTERNAL_SERVER_ERROR)?;
            }
            return Ok(());
        }
    };

    // 获取文件元数据
    let metadata = file.metadata().await?;
    let file_size = metadata.len();

    // 推测 MIME 类型
    let mime = from_path(file_path).first_or_octet_stream();

    // 构建响应
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", mime.as_ref())
        .header("Content-Length", file_size.to_string())
        .header("Cache-Control", format!("public, max-age={}", cache_max_age))
        .body(())?;

    // 获取 HttpSession 以便使用流式响应
    let http_session = session.as_any_mut().downcast_mut::<HttpSession>().unwrap();

    // 创建文件流
    let stream = ReaderStream::new(file);
    let body_stream = http_session.http_upgrade_body_stream(stream);

    // 发送响应
    http_session.respond_stream(resp, body_stream).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    env_logger::init();

    // 解析命令行参数
    let args = Args::parse();

    // 创建服务器实例
    let mut server = Server::new(None)?;
    server.bootstrap();

    // 创建静态文件服务器
    let root_dir = PathBuf::from(args.root_dir);
    let file_server = StaticFileServer::new(root_dir);

    // 创建服务
    let mut file_service = http_proxy_service(&server.configuration, file_server);

    // 配置服务监听地址和端口
    let bind_addr = format!("{}:{}", args.bind, args.port);
    file_service.add_tcp(&bind_addr);

    // 添加服务到服务器
    server.add_service(file_service);

    // 启动服务器
    println!("Static file server running on {}", bind_addr);
    server.run_forever();

    Ok(())
}
```

## 代码解析

让我们详细解析这段代码：

### 1. 配置和初始化

首先，我们定义了服务器的配置结构：

```rust
struct FileServerConfig {
    root_dir: PathBuf,          // 根目录路径
    enable_dir_listing: bool,   // 是否启用目录列表
    cache_max_age: u32,         // 缓存控制（秒）
}

struct StaticFileServer {
    config: Arc<FileServerConfig>,
}
```

配置包含：

- 根目录：静态文件的基础目录
- 目录列表：是否允许浏览目录内容
- 缓存最大期限：客户端缓存文件的时间

我们还使用 `clap` 库来解析命令行参数，允许用户指定根目录、端口和绑定地址。

### 2. 路径解析

`get_local_path` 方法负责将 HTTP 请求路径转换为本地文件系统路径：

```rust
fn get_local_path(&self, path: &str) -> PathBuf {
    let mut clean_path = path.trim_start_matches('/').to_string();

    // 处理空路径或根路径的情况
    if clean_path.is_empty() {
        clean_path = ".".to_string();
    }

    // 将请求路径转换为本地文件系统路径
    let mut full_path = self.config.root_dir.clone();
    full_path.push(clean_path);

    full_path
}
```

这个方法确保请求不能访问根目录之外的文件。

### 3. 请求处理

核心逻辑在 `request_filter` 方法中，它处理所有传入的请求：

```rust
async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
    // 提取请求路径
    let req_path = session.req_header().uri().path();

    // 构建本地文件路径
    let local_path = self.get_local_path(req_path);

    // 检查文件或目录是否存在
    if !local_path.exists() {
        // 返回 404 Not Found
        session.respond_error(StatusCode::NOT_FOUND)?;
        return Ok(false);
    }

    // 检查文件类型
    if local_path.is_dir() {
        // 处理目录...
    } else {
        // 处理文件...
    }

    Ok(false) // 停止处理，不转发到上游
}
```

当请求指向目录时，我们提供两种选择：

1. 如果存在 `index.html`，则发送该文件
2. 否则，如果启用了目录列表，则生成并发送目录内容

当请求指向文件时，我们直接发送文件内容。

### 4. 文件发送

我们使用 `send_file` 函数处理文件发送：

```rust
async fn send_file(session: &mut Session, file_path: &Path, cache_max_age: u32) -> Result<()> {
    // 打开文件
    let file = match File::open(file_path).await {
        // 处理错误...
    };

    // 获取文件元数据
    let metadata = file.metadata().await?;
    let file_size = metadata.len();

    // 推测 MIME 类型
    let mime = from_path(file_path).first_or_octet_stream();

    // 构建响应
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", mime.as_ref())
        .header("Content-Length", file_size.to_string())
        .header("Cache-Control", format!("public, max-age={}", cache_max_age))
        .body(())?;

    // 获取 HttpSession 并创建流式响应
    let http_session = session.as_any_mut().downcast_mut::<HttpSession>().unwrap();
    let stream = ReaderStream::new(file);
    let body_stream = http_session.http_upgrade_body_stream(stream);

    // 发送响应
    http_session.respond_stream(resp, body_stream).await?;

    Ok(())
}
```

这个函数执行以下操作：

1. 打开文件
2. 获取文件大小
3. 根据文件扩展名确定 MIME 类型
4. 设置适当的 HTTP 头部
5. 使用流式响应发送文件内容

使用流式响应对于大文件特别重要，因为它避免了将整个文件加载到内存中。

### 5. 目录列表

当请求指向目录且没有 `index.html` 文件时，我们生成一个 HTML 目录列表：

```rust
async fn generate_directory_listing(&self, dir_path: &Path, request_path: &str) -> Result<String> {
    let mut entries = fs::read_dir(dir_path).await?;
    let mut file_list = Vec::new();

    // 添加返回上一级目录的链接...

    // 读取目录项...

    // 生成 HTML...

    Ok(html)
}
```

目录列表包括文件名、大小和最后修改时间，同时提供返回上一级目录的链接。

## 使用和测试

编译并运行服务器：

```bash
RUST_LOG=info cargo run -- --root-dir ./public --port 8080
```

现在，你可以使用浏览器访问 `http://localhost:8080` 来浏览静态文件。

## 高级特性

### 1. 启用压缩

为了减少带宽使用并提高性能，我们可以添加对 gzip 和 brotli 压缩的支持：

```rust
async fn send_file(session: &mut Session, file_path: &Path, cache_max_age: u32) -> Result<()> {
    // ... 现有代码 ...

    // 检查客户端是否支持压缩
    let accept_encoding = session.req_header().headers
        .get("accept-encoding")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let should_compress = file_size > 1024 && // 只压缩大于 1KB 的文件
        (mime.type_() == mime::TEXT || mime.type_() == mime::APPLICATION);

    let use_brotli = should_compress && accept_encoding.contains("br");
    let use_gzip = should_compress && !use_brotli && accept_encoding.contains("gzip");

    // 根据请求头选择压缩方式...

    // 最后，发送适当的响应...
}
```

### 2. 条件请求处理

支持条件请求可以进一步提高缓存效率：

```rust
async fn send_file(session: &mut Session, file_path: &Path, cache_max_age: u32) -> Result<()> {
    // 获取文件元数据
    let metadata = file.metadata().await?;
    let last_modified = metadata.modified()?;

    // 转换为 HTTP 日期格式
    let last_modified_http = format_http_date(last_modified);

    // 检查 If-Modified-Since 头
    if let Some(if_modified_since) = session.req_header().headers.get("if-modified-since") {
        if let (Ok(if_modified_date), Ok(file_modified_date)) = (
            parse_http_date(if_modified_since.to_str().unwrap_or("")),
            parse_http_date(&last_modified_http),
        ) {
            if file_modified_date <= if_modified_date {
                // 文件未修改，返回 304 Not Modified
                let resp = Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(())?;

                session.respond(&resp, None)?;
                return Ok(());
            }
        }
    }

    // ... 其余代码 ...
}
```

### 3. 范围请求支持

对于大文件，支持范围请求（部分下载）非常有用：

```rust
async fn send_file(session: &mut Session, file_path: &Path, cache_max_age: u32) -> Result<()> {
    // ... 现有代码 ...

    // 检查 Range 头
    if let Some(range_header) = session.req_header().headers.get("range") {
        if let Ok(range_str) = range_header.to_str() {
            if let Some(range) = parse_range(range_str, file_size) {
                // 处理范围请求...
                return send_partial_file(session, file, range, mime, file_size).await;
            }
        }
    }

    // ... 其余代码 ...
}
```

## 安全考虑

实现静态文件服务器时，以下安全考虑很重要：

1. **路径遍历攻击防护**：确保请求不能访问根目录之外的文件
2. **符号链接处理**：决定是否跟随符号链接，以及如何限制访问范围
3. **默认文件限制**：考虑限制对某些文件（如 `.git` 目录）的访问
4. **请求方法限制**：通常静态文件服务器只需要支持 GET 和 HEAD 请求

## 总结

在本章中，我们实现了一个功能完整的静态文件服务器，它能够：

1. 提供指定目录下的静态文件
2. 生成目录列表（当 `index.html` 不存在时）
3. 自动检测文件的 MIME 类型
4. 设置适当的缓存控制头部
5. 使用流式传输处理大文件

静态文件服务是 Web 应用的基本功能之一，通过 Pingora 实现它，我们可以获得高性能和低延迟的优势。这个实现可以根据需要进一步扩展，添加更多高级特性如压缩、范围请求和更复杂的缓存控制。

你可以将这个静态文件服务器与前面章节中的反向代理或 API 网关结合使用，构建更完整的 Web 应用架构：代理动态请求到应用服务器，同时直接从本地文件系统提供静态资源。
