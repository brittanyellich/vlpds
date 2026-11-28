//! Stateless MCP tool handler for a preauthorized, scoped Spaces session.

pub mod credentials;
pub mod enrollment;

pub mod oauth_client;

pub mod rotation;
pub mod runtime;

use super::{agent_dispatch::Binding, agent_dispatch_auth::Admission, App};
use crate::oauth::scopes::{SpaceAccess, SpacePermission, SpaceTarget};
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

/// The exact account and Space a server-owned session provider may open.
/// Constructed only from an admitted dispatch binding.
pub struct SessionScope {
    binding: Binding,
    owner: String,
    space_type: String,
    conversation: String,
}

impl SessionScope {
    fn from_binding(binding: Binding) -> Option<Self> {
        let uri = vlatproto::syntax::parse_space_uri(&binding.space)?;
        let conversation = uri.skey;
        if uri.record.is_some() || !valid_id(conversation) {
            return None;
        }
        let (owner, space_type, conversation) = (uri.authority.into(), uri.space_type.into(), conversation.into());
        Some(Self { binding, owner, space_type, conversation })
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    pub fn conversation(&self) -> &str {
        &self.conversation
    }

    /// Use the PDS scope format to pin access to this authority and Space
    /// key, with create access confined to the two chat collections.
    pub fn oauth_scope(&self, thread: &str, message: &str) -> String {
        let target = SpaceTarget { authority: &self.owner, space_type: &self.space_type, skey: &self.conversation };
        [SpaceAccess::Read, SpaceAccess::Write("create", thread), SpaceAccess::Write("create", message)]
            .map(|access| SpacePermission::needed_for(&target, access))
            .join(" ")
    }
}

/// Server-owned backend obtained for a single approved binding.
pub trait ScopedSession: ChatSession {
    fn binding(&self) -> &Binding;
}

pub(super) async fn dispatch_scoped<S, F, Fut>(app: &App, open: &F, admission: Admission, body: &[u8]) -> Response
where
    S: ScopedSession,
    F: Fn(SessionScope) -> Fut,
    Fut: Future<Output = Option<S>>,
{
    let Some(scope) = SessionScope::from_binding(admission.binding.clone()) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let conversation = scope.conversation.clone();
    let Some(session) = open(scope).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if session.binding() != &admission.binding || session.conversation() != conversation {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !admission.is_current(app).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    handle(&session, body).await
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
    valid_id(value).then_some(value)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
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
