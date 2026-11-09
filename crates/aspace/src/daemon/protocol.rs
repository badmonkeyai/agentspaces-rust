// Copyright 2026 Bad Monkey, Inc.
// Author: Al Baker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The daemon protocol, version [`PROTOCOL`]: newline-delimited JSON over the local socket, one
//! request per connection (see the [module docs](super) for the exchange).
//!
//! Frames from the daemon are one JSON object per line, told apart by their one key:
//!
//! | Frame | Meaning |
//! |---|---|
//! | `{"hello": {...}}` | The first frame of every connection ([`Hello`]). |
//! | `{"out": <json>}` | A line the visitor prints on standard output, as it would have printed it. |
//! | `{"text": "..."}` | A line of text for standard output (`status` and `cards` without `--json`). |
//! | `{"note": "..."}` | A diagnostic for standard error (silenced by the visitor's `--quiet`). |
//! | `{"exit": n, "error": "..."}` | The last frame: the exit code to use and, unless 0, why. |
//!
//! The request is one object, `{"protocol": 1, "verb": "<verb>", "args": {...}}`, the arguments
//! of each verb as the `*Args` types of this module serialize them (camelCase keys).

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as Json, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol version a hello carries and a request names. A daemon answers a request of
/// another version with exit 2; a visitor that meets a daemon of another version joins itself.
pub const PROTOCOL: u32 = 1;

/// The longest request line the daemon reads: 9 MiB, room for the largest JSON object a command
/// reads ([`crate::io::MAX_JSON_INPUT`], 8 MiB) and its arguments. A longer one is refused.
pub const MAX_REQUEST: usize = 9 * 1024 * 1024;

/// The longest frame a visitor reads from the daemon: 64 MiB (an entry of an 8 MiB payload, as
/// JSON, with every byte escaped).
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// The longest hello a visitor reads.
pub const MAX_HELLO: usize = 64 * 1024;

/// The verbs a daemon serves.
pub const VERBS: [&str; 8] = [
    "status", "write", "read", "take", "complete", "watch", "cards", "call",
];

/// The daemon's first frame: who it is, so a visitor decides whether to use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    /// The protocol version ([`PROTOCOL`]).
    pub protocol: u32,
    /// The daemon's `aspace` version.
    pub version: String,
    /// The GroupID its peer joined.
    pub group: String,
    /// The group's name in the fleet file, when it has one.
    #[serde(default)]
    pub group_name: Option<String>,
    /// Its PeerID: a take through the daemon is held by `<peerId>/rust`.
    pub peer_id: String,
    /// Its keystore directory (absolute), or `None` for a fresh identity.
    #[serde(default)]
    pub keystore: Option<String>,
    /// Its security profile: `mtls` or `dev-local`.
    pub profile: String,
    /// Its process id.
    pub pid: u32,
    /// The socket it serves.
    pub socket: String,
    /// The verbs it serves.
    #[serde(default)]
    pub verbs: Vec<String>,
}

/// One frame from the daemon.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// The first frame.
    Hello(Hello),
    /// A JSON line for standard output.
    Out(Json),
    /// A text line for standard output.
    Text(String),
    /// A diagnostic for standard error.
    Note(String),
    /// The last frame: the exit code, and why when it is not 0.
    Exit {
        /// The exit code.
        code: u8,
        /// The message for standard error.
        error: Option<String>,
    },
}

impl Frame {
    /// The frame as its JSON object.
    pub fn to_json(&self) -> Json {
        match self {
            Frame::Hello(hello) => json!({ "hello": hello }),
            Frame::Out(value) => json!({ "out": value }),
            Frame::Text(text) => json!({ "text": text }),
            Frame::Note(note) => json!({ "note": note }),
            Frame::Exit { code, error } => match error {
                Some(error) => json!({ "exit": code, "error": error }),
                None => json!({ "exit": code }),
            },
        }
    }

    /// The frame a JSON object is, or why it is none.
    pub fn from_json(value: Json) -> Result<Frame, String> {
        let Json::Object(mut object) = value else {
            return Err("a frame is not a JSON object".to_owned());
        };
        if let Some(hello) = object.remove("hello") {
            return serde_json::from_value(hello)
                .map(Frame::Hello)
                .map_err(|error| format!("a hello that does not parse: {error}"));
        }
        if let Some(value) = object.remove("out") {
            return Ok(Frame::Out(value));
        }
        if let Some(text) = object.remove("text") {
            return match text {
                Json::String(text) => Ok(Frame::Text(text)),
                _ => Err("a text frame that is not a string".to_owned()),
            };
        }
        if let Some(note) = object.remove("note") {
            return match note {
                Json::String(note) => Ok(Frame::Note(note)),
                _ => Err("a note frame that is not a string".to_owned()),
            };
        }
        if let Some(code) = object.remove("exit") {
            let code = code
                .as_u64()
                .and_then(|code| u8::try_from(code).ok())
                .ok_or_else(|| "an exit frame whose code is not 0 to 255".to_owned())?;
            let error = match object.remove("error") {
                Some(Json::String(error)) => Some(error),
                _ => None,
            };
            return Ok(Frame::Exit { code, error });
        }
        Err("a frame of no known kind".to_owned())
    }
}

/// A request as it travels: the protocol, the verb, and its arguments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// The protocol version ([`PROTOCOL`]).
    pub protocol: u32,
    /// One of [`VERBS`].
    pub verb: String,
    /// The verb's arguments (`{}` when it takes none).
    #[serde(default)]
    pub args: Json,
}

impl Envelope {
    /// The envelope of `verb` with `args` at this protocol.
    pub fn new(verb: &str, args: &impl Serialize) -> Result<Envelope, String> {
        let args = serde_json::to_value(args)
            .map_err(|error| format!("the {verb} request does not serialize: {error}"))?;
        Ok(Envelope {
            protocol: PROTOCOL,
            verb: verb.to_owned(),
            args,
        })
    }

    /// The arguments as `T`, or why they are not.
    pub fn args<T: for<'de> Deserialize<'de>>(&self) -> Result<T, String> {
        serde_json::from_value(self.args.clone())
            .map_err(|error| format!("the {} request's arguments: {error}", self.verb))
    }
}

/// `status`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusArgs {
    /// One JSON object instead of text.
    #[serde(default)]
    pub json: bool,
    /// The visitor's MCP settings ([`crate::mcp::settings_json`]), reported as they are: the
    /// files are the visitor's environment's, not the daemon's (`null` from a visitor that sends
    /// none).
    #[serde(default)]
    pub mcp: Json,
}

/// `write`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteArgs {
    /// The entry's schema.
    pub schema: String,
    /// The entry's fields.
    pub entry: JsonMap<String, Json>,
    /// The space, resolved by the visitor.
    pub space: String,
    /// The write lease.
    pub lease_millis: i64,
    /// The tags, in order.
    #[serde(default)]
    pub tags: Vec<(String, String)>,
}

/// `read`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadArgs {
    /// The schema read.
    pub schema: String,
    /// The filter clauses.
    #[serde(default)]
    pub clauses: Vec<String>,
    /// The tags that must match.
    #[serde(default)]
    pub tags: Vec<(String, String)>,
    /// The most entries printed.
    pub limit: usize,
    /// How long to wait for a first match, when given.
    #[serde(default)]
    pub timeout_millis: Option<u64>,
    /// The space, resolved by the visitor.
    pub space: String,
}

/// `take`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeArgs {
    /// The schema taken.
    pub schema: String,
    /// The filter clauses.
    #[serde(default)]
    pub clauses: Vec<String>,
    /// The hold.
    pub lease_millis: i64,
    /// How long to wait for an entry, when given.
    #[serde(default)]
    pub timeout_millis: Option<u64>,
    /// The space, resolved by the visitor.
    pub space: String,
}

/// `complete`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteArgs {
    /// The entry id `take` printed.
    pub id: String,
    /// The result's schema, when there is a result.
    #[serde(default)]
    pub produces: Option<String>,
    /// The result's fields, when there is a result.
    #[serde(default)]
    pub result: Option<JsonMap<String, Json>>,
    /// The result lease.
    pub result_lease_millis: i64,
    /// The result's tags.
    #[serde(default)]
    pub tags: Vec<(String, String)>,
    /// How long to wait for the take to be found.
    pub timeout_millis: u64,
    /// The space, resolved by the visitor.
    pub space: String,
}

/// `watch`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchArgs {
    /// The schema watched.
    pub schema: String,
    /// The kinds printed (all when empty), by name.
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Stop after this many lines.
    #[serde(default)]
    pub count: Option<u64>,
    /// The filter clauses.
    #[serde(default)]
    pub clauses: Vec<String>,
    /// The space, resolved by the visitor.
    pub space: String,
}

/// `cards`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardsArgs {
    /// JSON Lines instead of text.
    #[serde(default)]
    pub json: bool,
    /// The `--only` patterns.
    #[serde(default)]
    pub only: Vec<String>,
    /// The spaces the visitor's configuration names (a card's other spaces are not followed
    /// when there are any).
    #[serde(default)]
    pub spaces: Vec<String>,
}

/// `call`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallArgs {
    /// The offering's name, or the schema it consumes.
    pub target: String,
    /// The input's fields.
    pub input: JsonMap<String, Json>,
    /// How long to wait for the result.
    pub timeout_millis: u64,
    /// How long to wait for the offering's card (the visitor's join timeout).
    pub wait_millis: u64,
    /// The spaces the visitor's configuration names.
    #[serde(default)]
    pub spaces: Vec<String>,
}

/// Why a line could not be read.
#[derive(Debug)]
pub enum LineError {
    /// The stream ended before any byte of the line.
    Closed,
    /// The line is longer than the limit.
    TooLong(usize),
    /// The line is not one JSON value.
    NotJson(String),
    /// The stream failed.
    Io(std::io::Error),
}

impl std::fmt::Display for LineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineError::Closed => f.write_str("the connection closed"),
            LineError::TooLong(limit) => write!(f, "a line longer than {limit} bytes"),
            LineError::NotJson(why) => write!(f, "a line that is not JSON ({why})"),
            LineError::Io(error) => write!(f, "{error}"),
        }
    }
}

/// Reads one line of at most `limit` bytes (its newline excluded) and parses it as JSON. A
/// stream that ends mid-line counts as the line's end.
pub async fn read_json<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Json, LineError> {
    let mut line = Vec::new();
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let read = (&mut *reader)
        .take(cap)
        .read_until(b'\n', &mut line)
        .await
        .map_err(LineError::Io)?;
    if read == 0 {
        return Err(LineError::Closed);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() > limit {
        return Err(LineError::TooLong(limit));
    }
    serde_json::from_slice(&line).map_err(|error| LineError::NotJson(error.to_string()))
}

/// Writes `value` as one line and flushes it.
pub async fn write_json<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Json,
) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(value).map_err(std::io::Error::from)?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Hello {
        Hello {
            protocol: PROTOCOL,
            version: "0.5.0".into(),
            group: "zGroup".into(),
            group_name: Some("research".into()),
            peer_id: "zPeer".into(),
            keystore: Some("/k".into()),
            profile: "mtls".into(),
            pid: 42,
            socket: "/run/aspace/daemon.sock".into(),
            verbs: VERBS.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn frames_round_trip_through_their_json() {
        for frame in [
            Frame::Hello(hello()),
            Frame::Out(json!({"id": "e1", "n": 1.5})),
            Frame::Text("peer     z".into()),
            Frame::Note("watching".into()),
            Frame::Exit {
                code: 0,
                error: None,
            },
            Frame::Exit {
                code: 3,
                error: Some("timed out".into()),
            },
        ] {
            let json = frame.to_json();
            assert_eq!(Frame::from_json(json.clone()), Ok(frame), "{json}");
        }
        assert_eq!(
            Frame::Exit {
                code: 2,
                error: Some("no".into())
            }
            .to_json(),
            json!({"exit": 2, "error": "no"})
        );
    }

    #[test]
    fn frames_of_no_known_shape_are_refused() {
        for bad in [
            json!([1]),
            json!({}),
            json!({"exit": 256}),
            json!({"exit": -1}),
            json!({"exit": "0"}),
            json!({"text": 1}),
            json!({"note": null}),
            json!({"hello": {"protocol": 1}}),
        ] {
            assert!(Frame::from_json(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_hello_tolerates_fields_it_does_not_know() {
        let mut json = serde_json::to_value(hello()).expect("serializes");
        json["later"] = json!("field");
        let parsed: Hello = serde_json::from_value(json).expect("parses");
        assert_eq!(parsed, hello());
    }

    #[test]
    fn requests_carry_the_protocol_the_verb_and_camel_case_arguments() {
        let args = TakeArgs {
            schema: "s.T#v1".into(),
            clauses: vec!["n>1".into()],
            lease_millis: 60_000,
            timeout_millis: None,
            space: "tasks".into(),
        };
        let envelope = Envelope::new("take", &args).expect("envelope");
        let json = serde_json::to_value(&envelope).expect("serializes");
        assert_eq!(json["protocol"], PROTOCOL);
        assert_eq!(json["verb"], "take");
        assert_eq!(json["args"]["leaseMillis"], 60_000);
        let back: Envelope = serde_json::from_value(json).expect("parses");
        assert_eq!(back.args::<TakeArgs>(), Ok(args));
        let error = back.args::<WriteArgs>().expect_err("not a write");
        assert!(error.contains("the take request's arguments"), "{error}");
    }

    #[tokio::test]
    async fn lines_are_bounded_and_parsed() {
        let mut input: &[u8] = b"{\"a\":1}\n{\"b\":2}";
        assert_eq!(read_json(&mut input, 64).await.ok(), Some(json!({"a": 1})));
        assert_eq!(read_json(&mut input, 64).await.ok(), Some(json!({"b": 2})));
        assert!(matches!(
            read_json(&mut input, 64).await,
            Err(LineError::Closed)
        ));
        let long = format!("\"{}\"\n", "x".repeat(100));
        let mut input = long.as_bytes();
        assert!(matches!(
            read_json(&mut input, 50).await,
            Err(LineError::TooLong(50))
        ));
        // Exactly the limit, then its newline, is read.
        let exact = format!("\"{}\"\n", "x".repeat(48));
        let mut input = exact.as_bytes();
        assert!(read_json(&mut input, 50).await.is_ok());
        let mut input: &[u8] = b"{nope\n";
        assert!(matches!(
            read_json(&mut input, 50).await,
            Err(LineError::NotJson(_))
        ));
        let mut out = Vec::new();
        write_json(&mut out, &json!({"k": "v"}))
            .await
            .expect("written");
        assert_eq!(out, b"{\"k\":\"v\"}\n");
    }
}
