//! `web_fetch`.
//!
//! CONTRACT (the body of `run` is a placeholder for the implementer; `spec` is fixed).
//!
//! - `url` must parse as `http` or `https` (else an error sentence showing what was received).
//! - The request goes through the session's egress proxy when `ctx.env` has `HTTPS_PROXY` /
//!   `HTTP_PROXY` (use that value, including its credentials, as the proxy for both schemes); with
//!   neither, it goes direct. Redirects are followed by hand, at most 10, so every hop passes the
//!   proxy's policy; the hops are listed in the result when there were any (`redirected: a → b → c`).
//! - Timeouts: `cfg.web_fetch_timeout_s` for the whole exchange; `ctx.cancel` aborts it (status
//!   `Interrupted`).
//! - The body is read up to `cfg.web_fetch_max_bytes`; if the response is larger, reading stops and
//!   the result has the fact `stopped at {limit} bytes — the response is larger` (never silently).
//! - Conversion happens on the complete downloaded body: `text/html` (or a body that starts with
//!   `<!doctype html`/`<html`, case-insensitive) is rendered to text with `html2text` at width 100
//!   unless `raw` is set; everything else is taken as is. The text shown is `Body::Raw` (stored
//!   whole, admitted). When conversion happened, the original bytes are also stored and meta
//!   `META_RAW_BLOB` names them, with the fact `html rendered as text (raw: out:{id})`.
//! - Outcome: `HTTP {status}`. Facts: final URL when it differs from the request, content type,
//!   `{bytes} bytes`. Status `Ok` for any HTTP response, including 4xx/5xx — a response is an
//!   observation; `Error` only when no response was obtained (the sentence names the stage: resolve,
//!   connect, TLS, proxy refusal with the proxy's message, timeout).
//! - A `407`/`403` from the proxy itself (header `X-Loom-Proxy: 1`) is reported as `denied` with the
//!   proxy's body as the message.
//!
//! Tests required (local `axum` server on loopback; no proxy): plain text; html rendered and raw
//! stored; `raw: true`; redirect chain reported; redirect loop stops at 10; 404 is `Ok` with the
//! body; size limit reported; timeout; cancel; bad URL; large html is converted completely (text
//! from the end of the document is present in the stored output).

use crate::{params, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{Map, Value};

pub struct WebFetch;

#[async_trait]
impl Tool for WebFetch {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "web_fetch",
            "Fetch a URL with an HTTP GET and return the response body. HTML pages are rendered as readable text (set `raw` to get the HTML source). The header gives the HTTP status; an error status such as 404 is still returned with its body. For anything other than a simple GET — other methods, headers, cookies — use `curl` through `bash`.",
            ToolClass::Read,
            &[
                params::req("url", "string", "The http:// or https:// URL."),
                params::opt("raw", "boolean", "Return the body exactly as served instead of rendering HTML as text (default false)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}
