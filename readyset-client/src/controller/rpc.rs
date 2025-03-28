//! This needs to be its own module to work around the way type-alias-impl-trait gets inferred - see
//! <https://github.com/mit-pdos/noria/issues/189> for more information

use std::pin::Pin;
use std::time::Duration;

use futures::Future;
use readyset_errors::{rpc_err, rpc_err_no_downcast, ReadySetError, ReadySetResult};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tower::ServiceExt;
use tower_service::Service;

use crate::controller::ControllerRequest;
use crate::ReadySetHandle;

// this alias is needed to work around -> impl Trait capturing _all_ lifetimes by default
// the A parameter is needed so it gets captured into the impl Trait
pub(crate) type RpcFuture<'a, R> = Pin<Box<dyn Future<Output = ReadySetResult<R>> + Send + 'a>>;

impl ReadySetHandle {
    /// Perform a raw RPC request to the HTTP `path` provided, providing a request body `r`.
    pub fn rpc<'a, Q, R>(
        &'a mut self,
        path: &'static str,
        r: Q,
        timeout: Option<Duration>,
    ) -> RpcFuture<'a, R>
    where
        R: DeserializeOwned + Send + 'static,
        Q: Serialize,
    {
        // Needed b/c of https://github.com/rust-lang/rust/issues/65442
        async fn rpc_inner<R>(
            ch: &mut ReadySetHandle,
            req: ControllerRequest,
            path: &'static str,
        ) -> ReadySetResult<R>
        where
            R: DeserializeOwned,
        {
            let body: hyper::body::Bytes = ch
                .handle
                .ready()
                .await
                .map_err(rpc_err!(path))?
                .call(req)
                .await
                .map_err(rpc_err!(path))?;

            bincode::deserialize::<R>(&body)
                .map_err(ReadySetError::from)
                .map_err(|e| rpc_err_no_downcast(path, e))
        }

        match ControllerRequest::new(path, r, timeout) {
            Ok(req) => Box::pin(rpc_inner(self, req, path)) as Pin<Box<_>>,
            Err(e) => Box::pin(std::future::ready(Err(e))) as Pin<Box<_>>,
        }
    }
}
