//! The hub server: gRPC ingestion, REST API, auth, retention.
//!
//! See `HUB_PLAN.md` for the full architecture. Security model in one
//! line: every request authenticates with an `X-API-KEY`; the key row in
//! Postgres is the single source of truth for identity and permissions —
//! the wire protocol carries no identity fields at all.

/// Generated protobuf types for `sentinel.v1` (server + client).
pub mod pb {
    // Generated code; silence pedantic lints (tonic's output trips
    // doc_markdown / default_trait_access).
    #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
    tonic::include_proto!("sentinel.v1");
}

pub mod auth;
pub mod grpc;
pub mod keys_cli;
pub mod range;
pub mod rest;
pub mod retention;
pub mod run_hub;
pub mod validate;
