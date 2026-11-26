//! Stateless MCP tool handler for a preauthorized, scoped Spaces session.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value as J};
use std::future::Future;

pub const VERSION: &str = "2025-06-18";
pub const VERSION_HEADER: &str = "mcp-protocol-version";
pub type ToolResult = Result<J, &'static str>;

/// One scoped conversation selected from verified server-side state. A
/// backend must enforce the authorized author and Space and retain stable,
/// create-only message IDs across retries.
pub trait ChatSession: Sync {
    fn conversation(&self) -> &str;
    fn start(&self) -> impl Future<Output = ToolResult> + Send;
    fn send(&self, message_id: &str, text: &str) -> impl Future<Output = ToolResult> + Send;
    fn history(&self) -> impl Future<Output = ToolResult> + Send;
}

pub const START: &str = "spaces_chat_start";
pub const SEND: &str = "spaces_chat_send";
pub const HISTORY: &str = "spaces_chat_history";

fn tools() -> J {
    let id = json!({"type": "string", "pattern": "^[a-z0-9]{1,64}$"});
    let text = json!({"type": "string", "minLength": 1, "maxLength": 4096});
    let tool = |name, description, properties: J, required: J| {
        json!({"name": name, "description": description, "inputSchema": {
            "type": "object", "properties": properties, "required": required, "additionalProperties": false
        }})
    };
    json!({"tools": [
        tool(START, "Start or reopen the approved conversation as its owner", json!({}), json!([])),
        tool(SEND, "Append one message using a stable client-generated ID",
            json!({"conversationId": id, "messageId": id, "text": text}),
            json!(["conversationId", "messageId", "text"])),
        tool(HISTORY, "Resume a conversation and read its messages",
            json!({"conversationId": id}), json!(["conversationId"])),
    ]})
}

fn id<'a>(input: &'a J, name: &str) -> Option<&'a str> {
    let value = input[name].as_str()?;
    if value.is_empty() || value.len() > 64 || !value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return None;
    }
    Some(value)
}

async fn call(session: &impl ChatSession, name: &str, input: J) -> J {
    let result = dispatch(session, name, input).await;
    let (value, is_error) = match result {
        Ok(value) => (value, false),
        Err(code) => (json!({"code": code}), true),
    };
    json!({
        "content": [{"type": "text", "text": value.to_string()}],
        "structuredContent": value,
        "isError": is_error,
    })
}

async fn dispatch(session: &impl ChatSession, name: &str, input: J) -> ToolResult {
    let count = input.as_object().ok_or("invalid_arguments")?.len();
    if name == START && count == 0 {
        return session.start().await;
    }
    let conversation = id(&input, "conversationId").ok_or("invalid_arguments")?;
    let tool = match name {
        HISTORY if count == 1 => None,
        SEND if count == 3 => Some((
            id(&input, "messageId").ok_or("invalid_arguments")?,
            input["text"].as_str().filter(|s| !s.is_empty() && s.chars().count() <= 4096).ok_or("invalid_arguments")?,
        )),
        _ => return Err("invalid_arguments"),
    };
    if conversation != session.conversation() {
        return Err("conversation_unavailable");
    }
    match tool {
        Some((id, text)) => session.send(id, text).await,
        None => session.history().await,
    }
}

fn error(id: J, code: i32, message: &str) -> Response {
    Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})).into_response()
}

/// Handle one signed request body after the caller has selected a session
/// from the approved binding. Tool arguments never select an owner or Space.
pub async fn handle(session: &impl ChatSession, body: &[u8]) -> Response {
    let Ok(body) = serde_json::from_slice::<J>(body) else {
        return error(J::Null, -32700, "Parse error");
    };
    let id = body["id"].clone();
    let method = body["method"].as_str();
    if body["jsonrpc"] != "2.0" || method.is_none() {
        return error(J::Null, -32600, "Invalid request");
    }
    if body.get("id").is_none() {
        // This stateless transport has no server-initiated requests.
        return StatusCode::ACCEPTED.into_response();
    }
    if !id.is_string() && !id.is_i64() && !id.is_u64() {
        return error(J::Null, -32600, "Invalid request ID");
    }

    let params = &body["params"];
    let result = match method {
        Some("initialize") => {
            if !params["protocolVersion"].is_string()
                || !params["capabilities"].is_object()
                || !params["clientInfo"]["name"].is_string()
                || !params["clientInfo"]["version"].is_string()
            {
                return error(id, -32602, "Invalid initialize parameters");
            }
            json!({
                "protocolVersion": VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vlpds-spaces-chat", "version": "0.1.0"}
            })
        }
        Some("ping") => json!({}),
        Some("tools/list") => tools(),
        Some("tools/call") => {
            let Some(name @ (START | SEND | HISTORY)) = params["name"].as_str() else {
                return error(id, -32602, "Unknown or missing tool name");
            };
            let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            call(session, name, arguments).await
        }
        _ => return error(id, -32601, "Method not found"),
    };
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}
