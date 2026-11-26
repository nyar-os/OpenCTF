//! Operation bodies behind the exported Node-API entry points, grouped by
//! domain. Each function owns one orthogonal operation and keeps the JSON
//! contract the TypeScript layer expects.
//!
//! - [`binary`] owns the session and the native format projections.
//! - [`challenge`] owns the projections that classify a challenge artifact.
//! - [`solver`] owns the algorithm-level operations.

pub(crate) mod binary;
pub(crate) mod challenge;
pub(crate) mod solver;
