use futures::prelude::*;
use postgres_types::Type;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::codec::{Codec, DecodeError, EncodeError};
use crate::error::Error;
use crate::message::{FrontendMessage, PsqlSrvRow};
use crate::response::Response;

const CHANNEL_INITIAL_CAPACITY: usize = 4096;

/// A channel for PostgreSQL messages. The `Channel` wraps a byte stream implementing `AsyncRead`
/// and `AsyncWrite`. It uses a `Codec` to read `FrontendMessage`s from this byte stream. The same
/// `Codec` is used to write `Response`s (actually the `BackendMessage`s generated by these
/// `Response`s) to the byte stream.
///
/// The `Channel`'s `Codec` maintains state in order to decode `FrontendMessage`s with encodings
/// dependent upon on the frontend-backend communication state. Since `Channel` does not directly
/// expose a `Codec`, it provides functions for updating the frontend-backend communication state,
/// forwarding all updates to `Codec`.
pub struct Channel<C>(Framed<C, Codec>);

impl<C> Channel<C>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: C) -> Channel<C> {
        let codec = Codec::new();
        let mut framed = Framed::with_capacity(inner, codec, CHANNEL_INITIAL_CAPACITY);
        framed.set_backpressure_boundary(64 * 1024);
        Channel(framed)
    }

    /// Set when the connection start up phase is complete. Indicates that regular mode messages
    /// will be received and parsed instead of startup messages.
    pub fn set_start_up_complete(&mut self) {
        self.0.codec_mut().set_start_up_complete();
    }

    /// Set the data types of a prepared statement's parameters. These data types must be set
    /// before the data values within a `FrontendMessage::Bind` message referencing the named
    /// pepared statement can be parsed.
    pub fn set_statement_param_types(&mut self, statement_name: &str, types: Vec<Type>) {
        self.0
            .codec_mut()
            .set_statement_param_types(statement_name, types);
    }

    /// Clear the data types of a prepared statement's parameters. This is typically requested
    /// when the prepared statement is closed (ie deallocated).
    pub fn clear_statement_param_types(&mut self, statement_name: &str) {
        self.0
            .codec_mut()
            .clear_statement_param_types(statement_name);
    }

    /// Clear the data types of all prepared statements' parameters. This is typically requested
    /// when all prepared statements are closed (ie deallocated).
    pub fn clear_all_statement_param_types(&mut self) {
        self.0.codec_mut().clear_all_statement_param_types();
    }

    /// Read a `FrontendMessage` from the channel.
    pub async fn next(&mut self) -> Option<Result<FrontendMessage, DecodeError>> {
        self.0.next().await
    }

    /// Write a `Response` (actually the `BackendMessage`s generated a `Response`) to the channel.
    pub async fn send<S>(&mut self, item: Response<S>) -> Result<(), EncodeError>
    where
        S: Stream<Item = Result<PsqlSrvRow, Error>> + Unpin,
    {
        item.write(&mut self.0).await
    }

    pub async fn flush(&mut self) -> Result<(), EncodeError> {
        self.0.flush().await
    }

    pub fn into_inner(self) -> C {
        self.0.into_inner()
    }
}
