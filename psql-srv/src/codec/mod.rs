pub(crate) mod decoder;
mod encoder;
mod error;

use std::collections::HashMap;

pub use error::{DecodeError, EncodeError};
use postgres_types::Type;

/// A [`Decoder`] implementation that deserializes `FrontendMessage` and [`Encoder`] implementation
/// that serializes `BackendMessage`.
///
/// [`Decoder`]: https://docs.rs/tokio-util/0.2.0/tokio_util/codec/trait.Decoder.html
/// [`Encoder`]: https://docs.rs/tokio-util/0.2.0/tokio_util/codec/trait.Encoder.html
pub struct Codec {
    is_starting_up: bool,
    statement_param_types: HashMap<String, Vec<Type>>,
}

impl Codec {
    pub fn new() -> Codec {
        Codec {
            is_starting_up: true,
            statement_param_types: HashMap::new(),
        }
    }

    /// Set when the connection start up phase is complete. Indicates that regular mode messages
    /// will be parsed instead of startup messages.
    pub fn set_start_up_complete(&mut self) {
        self.is_starting_up = false;
    }

    /// Set the data types of a prepared statement's parameters. These data types must be set
    /// before the data values within a `FrontendMessage::Bind` message referencing the named
    /// pepared statement can be parsed.
    pub fn set_statement_param_types(&mut self, statement_name: &str, types: Vec<Type>) {
        self.statement_param_types
            .insert(statement_name.to_string(), types);
    }

    /// Clear the data types of a prepared statement's parameters. This is typically requested
    /// when the prepared statement is closed (ie deallocated).
    pub fn clear_statement_param_types(&mut self, statement_name: &str) {
        self.statement_param_types.remove(statement_name);
    }

    /// Clear the data types of all prepared statement parameters. This is typically requested
    /// when all prepared statements are closed (ie deallocated).
    pub fn clear_all_statement_param_types(&mut self) {
        self.statement_param_types.clear();
    }
}
