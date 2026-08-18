//! Endpoint Security event families consumed by the signed system extension.
//!
//! The extension owns the privileged subscription and sends versioned events
//! to the host over a signed XPC channel. Rust validates and ingests those
//! events through [`crate::EndpointSecurityIngestor`]. `eslogger` is retained
//! only as a diagnostic compatibility tool and is not the production sensor.

pub const EXEC_EVENT_TYPES: &[&str] = &["exec", "fork", "exit"];

pub const FILE_MUTATION_EVENT_TYPES: &[&str] = &[
    "create",
    "write",
    "rename",
    "unlink",
    "close",
    "truncate",
    "clone",
    "copyfile",
    "exchangedata",
    "setextattr",
    "deleteextattr",
    "setmode",
    "setowner",
    "setflags",
    "setacl",
];

pub const FILE_OPEN_EVENT_TYPES: &[&str] = &[
    "open",
    "lookup",
    "access",
    "stat",
    "getattrlist",
    "readlink",
    "readdir",
    "getextattr",
    "listextattr",
    "fsgetpath",
];
