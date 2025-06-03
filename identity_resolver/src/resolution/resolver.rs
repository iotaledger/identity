// Copyright 2020-2025 IOTA Stiftung, Fondazione LINKS
// SPDX-License-Identifier: Apache-2.0

use core::future::Future;
use futures::stream::FuturesUnordered;
use futures::TryStreamExt;
use identity_did::DIDCompositeJwk;
use identity_did::DIDJwk;
use identity_did::DID;
use std::collections::HashSet;

use identity_document::document::CoreDocument;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::Error;
use crate::ErrorCause;
use crate::Result;

use super::commands::Command;
use super::commands::SendSyncCommand;
use super::commands::SingleThreadedCommand;

/// Convenience type for resolving DID documents from different DID methods.   
///
/// # Configuration
///
/// The resolver will only be able to resolve DID documents for methods it has been configured for. This is done by
/// attaching method specific handlers with [`Self::attach_handler`](Self::attach_handler()).
pub struct Resolver<DOC = CoreDocument, CMD = SendSyncCommand<DOC>>
where
  CMD: for<'r> Command<'r, Result<DOC>>,
{
  command_map: HashMap<String, CMD>,
  _required: PhantomData<DOC>,
}

impl<M, DOC> Resolver<DOC, M>
where
  M: for<'r> Command<'r, Result<DOC>>,
{
  /// Constructs a new [`Resolver`].
  ///
  /// # Example
  ///
  /// Construct a `Resolver` that resolves DID documents of type
  /// [`CoreDocument`](::identity_document::document::CoreDocument).
  ///  ```
  /// # use identity_resolver::Resolver;
  /// # use identity_document::document::CoreDocument;
  ///
  /// let mut resolver = Resolver::<CoreDocument>::new();
  /// // Now attach some handlers whose output can be converted to a `CoreDocument`.
  /// ```
  pub fn new() -> Self {
    Self {
      command_map: HashMap::new(),
      _required: PhantomData::<DOC>,
    }
  }

  /// Fetches the DID Document of the given DID.
  ///
  /// # Errors
  ///
  /// Errors if the resolver has not been configured to handle the method corresponding to the given DID or the
  /// resolution process itself fails.
  ///
  /// ## Example
  ///
  /// ```
  /// # use identity_resolver::Resolver;
  /// # use identity_did::CoreDID;
  /// # use identity_document::document::CoreDocument;
  ///
  /// async fn configure_and_resolve(
  ///   did: CoreDID,
  /// ) -> std::result::Result<CoreDocument, Box<dyn std::error::Error>> {
  ///   let resolver: Resolver = configure_resolver(Resolver::new());
  ///   let resolved_doc: CoreDocument = resolver.resolve(&did).await?;
  ///   Ok(resolved_doc)
  /// }
  ///
  /// fn configure_resolver(mut resolver: Resolver) -> Resolver {
  ///   resolver.attach_handler("foo".to_owned(), resolve_foo);
  ///   // Attach handlers for other DID methods we are interested in.
  ///   resolver
  /// }
  ///
  /// async fn resolve_foo(did: CoreDID) -> std::result::Result<CoreDocument, std::io::Error> {
  ///   todo!()
  /// }
  /// ```
  pub async fn resolve<D: DID>(&self, did: &D) -> Result<DOC> {
    let method: &str = did.method();
    let delegate: &M = self
      .command_map
      .get(method)
      .ok_or_else(|| ErrorCause::UnsupportedMethodError {
        method: method.to_owned(),
      })
      .map_err(Error::new)?;

    delegate.apply(did.as_str()).await
  }

  /// Concurrently fetches the DID Documents of the multiple given DIDs.
  ///
  /// # Errors
  /// * If the resolver has not been configured to handle the method of any of the given DIDs.
  /// * If the resolution process of any DID fails.
  ///
  /// ## Note
  /// * If `dids` contains duplicates, these will be resolved only once.
  pub async fn resolve_multiple<D: DID>(&self, dids: &[D]) -> Result<HashMap<D, DOC>> {
    let futures = FuturesUnordered::new();

    // Create set to remove duplicates to avoid unnecessary resolution.
    let dids_set: HashSet<D> = dids.iter().cloned().collect();
    for did in dids_set {
      futures.push(async move {
        let doc = self.resolve(&did).await;
        doc.map(|doc| (did, doc))
      });
    }

    let documents: HashMap<D, DOC> = futures.try_collect().await?;

    Ok(documents)
  }
}

impl<DOC: 'static> Resolver<DOC, SendSyncCommand<DOC>> {
  /// Attach a new handler responsible for resolving DIDs of the given DID method.
  ///
  /// The `handler` is expected to be a closure taking an owned DID and asynchronously returning a DID Document
  /// which can be converted to the type this [`Resolver`] is parametrized over. The `handler` is required to be
  /// [`Clone`], [`Send`], [`Sync`] and `'static` hence all captured variables must satisfy these bounds. In this regard
  /// the `move` keyword and (possibly) wrapping values in an [`Arc`](std::sync::Arc) may come in handy (see the example
  /// below).
  ///
  /// NOTE: If there already exists a handler for this method then it will be replaced with the new handler.
  /// In the case where one would like to have a "backup handler" for the same DID method, one can achieve this with
  /// composition.
  ///
  /// # Example
  /// ```
  /// # use identity_resolver::Resolver;
  /// # use identity_did::CoreDID;
  /// # use identity_document::document::CoreDocument;
  ///
  ///    // A client that can resolve DIDs of our invented "foo" method.
  ///    struct Client;
  ///
  ///    impl Client {
  ///      // Resolves some of the DIDs we are interested in.
  ///      async fn resolve(&self, _did: &CoreDID) -> std::result::Result<CoreDocument, std::io::Error> {
  ///        todo!()
  ///      }
  ///    }
  ///
  ///    // This way we can essentially produce (cheap) clones of our client.
  ///    let client = std::sync::Arc::new(Client {});
  ///
  ///    // Get a clone we can move into a handler.
  ///    let client_clone = client.clone();
  ///
  ///    // Construct a resolver that resolves documents of type `CoreDocument`.
  ///    let mut resolver = Resolver::<CoreDocument>::new();
  ///
  ///    // Now we want to attach a handler that uses the client to resolve DIDs whose method is "foo".
  ///    resolver.attach_handler("foo".to_owned(), move |did: CoreDID| {
  ///      // We want to resolve the did asynchronously, but since we do not know when it will be awaited we
  ///      // let the future take ownership of the client by moving a clone into the asynchronous block.
  ///      let future_client = client_clone.clone();
  ///      async move { future_client.resolve(&did).await }
  ///    });
  /// ```
  pub fn attach_handler<D, F, Fut, DOCUMENT, E, DIDERR>(&mut self, method: String, handler: F)
  where
    D: DID + Send + for<'r> TryFrom<&'r str, Error = DIDERR> + 'static,
    DOCUMENT: 'static + Into<DOC>,
    F: Fn(D) -> Fut + 'static + Clone + Send + Sync,
    Fut: Future<Output = std::result::Result<DOCUMENT, E>> + Send,
    E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    DIDERR: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
  {
    let command = SendSyncCommand::new(handler);
    self.command_map.insert(method, command);
  }
}

impl<DOC: 'static> Resolver<DOC, SingleThreadedCommand<DOC>> {
  /// Attach a new handler responsible for resolving DIDs of the given DID method.
  ///
  /// The `handler` is expected to be a closure taking an owned DID and asynchronously returning a DID Document
  /// which can be converted to the type this [`Resolver`] is parametrized over. The `handler` is required to be
  /// [`Clone`] and `'static`  hence all captured variables must satisfy these bounds. In this regard the
  /// `move` keyword and (possibly) wrapping values in an [`std::rc::Rc`] may come in handy (see the example below).
  ///
  /// NOTE: If there already exists a handler for this method then it will be replaced with the new handler.
  /// In the case where one would like to have a "backup handler" for the same DID method, one can achieve this with
  /// composition.
  ///
  /// # Example
  /// ```
  /// # use identity_resolver::SingleThreadedResolver;
  /// # use identity_did::CoreDID;
  /// # use identity_document::document::CoreDocument;
  ///
  ///    // A client that can resolve DIDs of our invented "foo" method.
  ///    struct Client;
  ///
  ///    impl Client {
  ///      // Resolves some of the DIDs we are interested in.
  ///      async fn resolve(&self, _did: &CoreDID) -> std::result::Result<CoreDocument, std::io::Error> {
  ///        todo!()
  ///      }
  ///    }
  ///
  ///    // This way we can essentially produce (cheap) clones of our client.
  ///    let client = std::rc::Rc::new(Client {});
  ///
  ///    // Get a clone we can move into a handler.
  ///    let client_clone = client.clone();
  ///
  ///    // Construct a resolver that resolves documents of type `CoreDocument`.
  ///    let mut resolver = SingleThreadedResolver::<CoreDocument>::new();
  ///
  ///    // Now we want to attach a handler that uses the client to resolve DIDs whose method is "foo".
  ///    resolver.attach_handler("foo".to_owned(), move |did: CoreDID| {
  ///      // We want to resolve the did asynchronously, but since we do not know when it will be awaited we
  ///      // let the future take ownership of the client by moving a clone into the asynchronous block.
  ///      let future_client = client_clone.clone();
  ///      async move { future_client.resolve(&did).await }
  ///    });
  /// ```
  pub fn attach_handler<D, F, Fut, DOCUMENT, E, DIDERR>(&mut self, method: String, handler: F)
  where
    D: DID + for<'r> TryFrom<&'r str, Error = DIDERR> + 'static,
    DOCUMENT: 'static + Into<DOC>,
    F: Fn(D) -> Fut + 'static + Clone,
    Fut: Future<Output = std::result::Result<DOCUMENT, E>>,
    E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    DIDERR: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
  {
    let command = SingleThreadedCommand::new(handler);
    self.command_map.insert(method, command);
  }
}

impl<DOC: From<CoreDocument> + 'static> Resolver<DOC, SingleThreadedCommand<DOC>> {
  /// Attaches a handler capable of resolving `did:jwk` DIDs.
  pub fn attach_did_jwk_handler(&mut self) {
    let handler = |did_jwk: DIDJwk| async move { CoreDocument::expand_did_jwk(did_jwk) };
    self.attach_handler(DIDJwk::METHOD.to_string(), handler)
  }
}

impl<DOC: From<CoreDocument> + 'static> Resolver<DOC, SendSyncCommand<DOC>> {
  /// Attaches a handler capable of resolving `did:jwk` DIDs.
  pub fn attach_did_jwk_handler(&mut self) {
    let handler = |did_jwk: DIDJwk| async move { CoreDocument::expand_did_jwk(did_jwk) };
    self.attach_handler(DIDJwk::METHOD.to_string(), handler)
  }
}

impl<DOC: From<CoreDocument> + 'static> Resolver<DOC, SingleThreadedCommand<DOC>> {
  /// Attaches a handler capable of resolving `did:compositejwk` DIDs.
  pub fn attach_did_compositejwk_handler(&mut self) {
    let handler = |did_compositejwk: DIDCompositeJwk| async move { CoreDocument::expand_did_compositejwk(did_compositejwk) };
    self.attach_handler(DIDCompositeJwk::METHOD.to_string(), handler)
  }
}

impl<DOC: From<CoreDocument> + 'static> Resolver<DOC, SendSyncCommand<DOC>> {
  /// Attaches a handler capable of resolving `did:compositejwk` DIDs.
  pub fn attach_did_compositejwk_handler(&mut self) {
    let handler = |did_compositejwk: DIDCompositeJwk| async move { CoreDocument::expand_did_compositejwk(did_compositejwk) };
    self.attach_handler(DIDCompositeJwk::METHOD.to_string(), handler)
  }
}

#[cfg(feature = "iota")]
mod iota_handler {
  use crate::ErrorCause;

  use super::Resolver;
  use identity_document::document::CoreDocument;
  use identity_iota_core::IotaDID;
  use identity_iota_core::IotaDocument;
  use identity_iota_core::IotaIdentityClientExt;
  use std::collections::HashMap;
  use std::sync::Arc;

  impl<DOC> Resolver<DOC>
  where
    DOC: From<IotaDocument> + AsRef<CoreDocument> + 'static,
  {
    /// Convenience method for attaching a new handler responsible for resolving IOTA DIDs.
    ///
    /// See also [`attach_handler`](Self::attach_handler).
    pub fn attach_iota_handler<CLI>(&mut self, client: CLI)
    where
      CLI: IotaIdentityClientExt + Send + Sync + 'static,
    {
      let arc_client: Arc<CLI> = Arc::new(client);

      let handler = move |did: IotaDID| {
        let future_client = arc_client.clone();
        async move { future_client.resolve_did(&did).await }
      };

      self.attach_handler(IotaDID::METHOD.to_owned(), handler);
    }

    /// Convenience method for attaching multiple handlers responsible for resolving IOTA DIDs
    /// on multiple networks.
    ///
    ///
    /// # Arguments
    ///
    /// * `clients` - A collection of tuples where each tuple contains the name of the network name and its
    ///   corresponding client.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Assume `smr_client` and `iota_client` are instances IOTA clients `iota_sdk::client::Client`.
    /// attach_multiple_iota_handlers(vec![("smr", smr_client), ("iota", iota_client)]);
    /// ```
    ///
    /// # See Also
    /// - [`attach_handler`](Self::attach_handler).
    ///
    /// # Note
    ///
    /// - Using `attach_iota_handler` or `attach_handler` for the IOTA method would override all previously added
    ///   clients.
    /// - This function does not validate the provided configuration. Ensure that the provided network name corresponds
    ///   with the client, possibly by using `client.network_name()`.
    pub fn attach_multiple_iota_handlers<CLI, I>(&mut self, clients: I)
    where
      CLI: IotaIdentityClientExt + Send + Sync + 'static,
      I: IntoIterator<Item = (&'static str, CLI)>,
    {
      let arc_clients = Arc::new(clients.into_iter().collect::<HashMap<&'static str, CLI>>());

      let handler = move |did: IotaDID| {
        let future_client = arc_clients.clone();
        async move {
          let did_network = did.network_str();
          let client: &CLI =
            future_client
              .get(did_network)
              .ok_or(crate::Error::new(ErrorCause::UnsupportedNetwork(
                did_network.to_string(),
              )))?;
          client
            .resolve_did(&did)
            .await
            .map_err(|err| crate::Error::new(ErrorCause::HandlerError { source: Box::new(err) }))
        }
      };

      self.attach_handler(IotaDID::METHOD.to_owned(), handler);
    }
  }
}

impl<CMD, DOC> Default for Resolver<DOC, CMD>
where
  CMD: for<'r> Command<'r, Result<DOC>>,
  DOC: AsRef<CoreDocument>,
{
  fn default() -> Self {
    Self::new()
  }
}

impl<CMD, DOC> std::fmt::Debug for Resolver<DOC, CMD>
where
  CMD: for<'r> Command<'r, Result<DOC>>,
  DOC: AsRef<CoreDocument>,
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Resolver")
      .field("command_map", &self.command_map)
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use identity_iota_core::block::output::AliasId;
  use identity_iota_core::block::output::AliasOutput;
  use identity_iota_core::block::output::OutputId;
  use identity_iota_core::block::protocol::ProtocolParameters;
  use identity_iota_core::IotaDID;
  use identity_iota_core::IotaDocument;
  use identity_iota_core::IotaIdentityClient;
  use identity_iota_core::IotaIdentityClientExt;

  use super::*;

  struct DummyClient(IotaDocument);

  #[async_trait::async_trait]
  impl IotaIdentityClient for DummyClient {
    async fn get_alias_output(&self, _id: AliasId) -> identity_iota_core::Result<(OutputId, AliasOutput)> {
      unreachable!()
    }
    async fn get_protocol_parameters(&self) -> identity_iota_core::Result<ProtocolParameters> {
      unreachable!()
    }
  }

  #[async_trait::async_trait]
  impl IotaIdentityClientExt for DummyClient {
    async fn resolve_did(&self, did: &IotaDID) -> identity_iota_core::Result<IotaDocument> {
      if self.0.id().as_str() == did.as_str() {
        Ok(self.0.clone())
      } else {
        Err(identity_iota_core::Error::DIDResolutionError(
          iota_sdk::client::error::Error::NoOutput(did.to_string()),
        ))
      }
    }
  }

  #[tokio::test]
  async fn test_multiple_handlers() {
    let did1 =
      IotaDID::parse("did:iota:smr:0x0101010101010101010101010101010101010101010101010101010101010101").unwrap();
    let document = IotaDocument::new_with_id(did1.clone());
    let dummy_smr_client = DummyClient(document);

    let did2 = IotaDID::parse("did:iota:0x0101010101010101010101010101010101010101010101010101010101010101").unwrap();
    let document = IotaDocument::new_with_id(did2.clone());
    let dummy_iota_client = DummyClient(document);

    let mut resolver = Resolver::<IotaDocument>::new();
    resolver.attach_multiple_iota_handlers(vec![("iota", dummy_iota_client), ("smr", dummy_smr_client)]);

    let doc = resolver.resolve(&did1).await.unwrap();
    assert_eq!(doc.id(), &did1);

    let doc = resolver.resolve(&did2).await.unwrap();
    assert_eq!(doc.id(), &did2);
  }

  #[tokio::test]
  async fn test_did_jwk_resolution() {
    let mut resolver = Resolver::<CoreDocument>::new();
    resolver.attach_did_jwk_handler();

    let did_jwk = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9".parse::<DIDJwk>().unwrap();

    let doc = resolver.resolve(&did_jwk).await.unwrap();
    assert_eq!(doc.id(), did_jwk.as_ref());
  }
}
