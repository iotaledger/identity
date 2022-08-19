// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use identity_credential::credential::Credential;
use identity_credential::presentation::Presentation;
use identity_credential::validator::BorrowValidator;
use identity_credential::validator::CredentialValidator;
use identity_credential::validator::FailFast;
use identity_credential::validator::PresentationValidationOptions;
use identity_credential::validator::PresentationValidator;
use identity_credential::validator::ValidatorDocument;
use identity_did::did::CoreDID;
use identity_did::did::DID;
use identity_did::document::Document;
use serde::Serialize;

use crate::Error;
use crate::ResolutionHandler;
use crate::Result;

use super::resolver_delegate::AsyncFnPtr;
use super::resolver_delegate::ResolverDelegate;

type Inner<DOC> = AsyncFnPtr<str, Result<Option<DOC>>>;

///
pub struct HandlerIndex {
  method: String,
  id: usize,
}

/// Convenience type for resolving did documents from different did methods.   
///  
/// Also provides functions for resolving DID Documents associated with
/// verifiable [`Credentials`][Credential] and [`Presentations`][Presentation].
///
/// # Configuration
/// The resolver will only be able to resolve did documents corresponding to a certain method after it has been
/// configured to do so. This setup is achieved by implementing the [`MethodBoundedResolver`
/// trait](super::MethodBoundResolver) for your client and then attaching it with
/// [`Self::attach_method_handler`](`Resolver::attach_method_handler`).
pub struct Resolver<DOC = Box<dyn ValidatorDocument>>
where
  DOC: BorrowValidator,
{
  method_map: HashMap<String, Vec<Inner<DOC>>>,
}

impl<DOC> Resolver<DOC>
where
  DOC: BorrowValidator,
{
  /// Constructs a new [`Resolver`].
  pub fn new() -> Self {
    Self {
      method_map: HashMap::new(),
    }
  }

  /// Attach a [`ResolverHandler`] to this resolver.
  pub fn attach_method_handler<D, R>(&mut self, handler: Arc<R>)
  where
    D: DID + Send + for<'r> TryFrom<&'r str> + 'static,
    R: ResolutionHandler<D> + 'static,
    DOC: From<<R as ResolutionHandler<D>>::Resolved> + 'static,
  {
    let ResolverDelegate::<DOC> { method, handler } = ResolverDelegate::new(handler);
    self.attach_raw_internal(method, handler);
  }

  #[cfg(feature = "internals")]
  pub fn attach_raw(&mut self, method: String, handler: AsyncFnPtr<str, Result<Option<DOC>>>) {
    self.attach_raw_internal(method, handler);
  }

  fn attach_raw_internal(&mut self, method: String, handler: AsyncFnPtr<str, Result<Option<DOC>>>) {
    let method_handlers = self.method_map.entry(method).or_insert(Vec::new());
    method_handlers.push(handler);
  }

  /// Fetches the DID Document of the given DID and attempts to cast the result to the desired type.
  ///
  /// If this Resolver was constructed by the [`Resolver::new_dynamic`](Resolver::new_dynamic()) method, one may also
  /// want to consider [`Resolver::resolve_to`](Resolver::<Box<dyn ValidatorDocument>>::resolve_to()).
  ///
  /// # Errors
  /// Errors if the resolver has not been configured to handle the method corresponding to the given did or the
  /// resolution process itself fails.
  //TODO: Improve error handling.
  pub async fn resolve<D: DID>(&self, did: &D) -> Result<DOC> {
    self.delegate_resolution(did.method(), did.as_str()).await
  }

  /// Fetches all DID Documents of [`Credential`] issuers contained in a [`Presentation`].
  /// Issuer documents are returned in arbitrary order.
  ///
  /// # Errors
  ///
  /// Errors if any issuer URL cannot be parsed to a DID whose associated method is supported by this Resolver, or
  /// resolution fails.
  // TODO: Improve error handling.
  pub async fn resolve_presentation_issuers<U, V>(&self, presentation: &Presentation<U, V>) -> Result<Vec<DOC>> {
    // Extract unique issuers.
    //TODO: Improve error handling.
    let issuers: HashSet<CoreDID> = presentation
      .verifiable_credential
      .iter()
      .map(|credential| {
        CredentialValidator::extract_issuer::<CoreDID, V>(credential)
          .map_err(|_| Error::ResolutionProblem("Failed to parse the issuer's did from a credential".into()))
      })
      .collect::<Result<_>>()?;

    if let Some(unsupported_method) = issuers
      .iter()
      .find(|issuer| !self.method_map.contains_key(issuer.method()))
      .map(|issuer| issuer.method())
    {
      // The presentation contains did's whose methods are not attached to this Resolver.
      // TODO: Find a much better error!
      return Err(Error::ResolutionProblem(format!(
        "the presentation contains a credential issued with the following unsupported did method: {}",
        unsupported_method
      )));
    }
    // Resolve issuers concurrently.
    futures::future::try_join_all(
      issuers
        .iter()
        .map(|issuer| self.delegate_resolution(issuer.method(), issuer.as_str()))
        .collect::<Vec<_>>(),
    )
    .await
  }

  /// Fetches the DID Document of the holder of a [`Presentation`].
  ///
  /// # Errors
  ///
  /// Errors if the holder URL is missing, cannot be parsed to a valid DID whose method is supported by the resolver, or
  /// DID resolution fails.
  //TODO: Improve error handling
  pub async fn resolve_presentation_holder<U, V>(&self, presentation: &Presentation<U, V>) -> Result<DOC> {
    let holder: CoreDID = PresentationValidator::extract_holder(presentation)
      .map_err(|error| Error::ResolutionProblem(error.to_string()))?;
    self.delegate_resolution(holder.method(), holder.as_str()).await
  }

  /// Fetches the DID Document of the issuer of a [`Credential`].
  ///
  /// # Errors
  ///
  /// Errors if the issuer URL cannot be parsed to a DID with a method supported by the resolver, or resolution fails.
  // TODO: Improve errors!
  pub async fn resolve_credential_issuer<U: Serialize>(&self, credential: &Credential<U>) -> Result<DOC> {
    let issuer_did: CoreDID = CredentialValidator::extract_issuer(credential)
      .map_err(|_| Error::ResolutionProblem("failed to parse the issuer's did".into()))?;
    self.delegate_resolution(issuer_did.method(), issuer_did.as_str()).await
  }

  /// Verifies a [`Presentation`].
  ///
  /// # Important
  /// See [`PresentationValidator::validate`](PresentationValidator::validate()) for information about which properties
  /// get validated and what is expected of the optional arguments `holder` and `issuer`.
  ///
  /// # Resolution
  /// The DID Documents for the `holder` and `issuers` are optionally resolved if not given.
  /// If you already have up-to-date versions of these DID Documents, you may want
  /// to use [`PresentationValidator::validate`].
  /// See also [`Resolver::resolve_presentation_issuers`] and [`Resolver::resolve_presentation_holder`]. Note that
  /// DID Documents of a certain method can only be resolved if the resolver has been configured handle this method.
  /// See [Self::attach_method_handler].
  ///
  /// # Errors
  /// Errors from resolving the holder and issuer DID Documents, if not provided, will be returned immediately.
  /// Otherwise, errors from validating the presentation and its credentials will be returned
  /// according to the `fail_fast` parameter.
  pub async fn verify_presentation<U, V, HDOC, IDOC>(
    &self,
    presentation: &Presentation<U, V>,
    options: &PresentationValidationOptions,
    fail_fast: FailFast,
    holder: Option<&HDOC>,
    issuers: Option<&[IDOC]>,
  ) -> Result<()>
  where
    U: Serialize,
    V: Serialize,
    HDOC: BorrowValidator + ?Sized,
    IDOC: BorrowValidator,
  {
    match (holder, issuers) {
      (Some(holder), Some(issuers)) => {
        PresentationValidator::validate(presentation, holder, issuers, options, fail_fast)
      }
      (Some(holder), None) => {
        let issuers: Vec<DOC> = self.resolve_presentation_issuers(presentation).await?;
        PresentationValidator::validate(presentation, holder, issuers.as_slice(), options, fail_fast)
      }
      (None, Some(issuers)) => {
        let holder = self.resolve_presentation_holder(presentation).await?;
        PresentationValidator::validate(presentation, &holder, issuers, options, fail_fast)
      }
      (None, None) => {
        let (holder, issuers): (DOC, Vec<DOC>) = futures::future::try_join(
          self.resolve_presentation_holder(presentation),
          self.resolve_presentation_issuers(presentation),
        )
        .await?;

        PresentationValidator::validate(presentation, &holder, &issuers, options, fail_fast)
      }
    }
    .map_err(Into::into)
  }

  /// Delegates Resolution to the relevant attached [`ResolutionHandler`].
  ///
  /// The first input parameters `method` and `did` must be &str representations of the DID method name and the DID
  /// respectively.  
  async fn delegate_resolution(&self, method: &str, did: &str) -> Result<DOC> {
    let delegates = self
      .method_map
      .get(method)
      .ok_or_else(|| Error::ResolutionProblem("did method not supported".into()))?;

    let mut err: Option<Error> = None;

    for delegate in delegates {
      match delegate(did).await {
        Ok(Some(doc)) => {
          return Ok(doc);
        }
        Ok(None) => {
          // The resolver was not configured to resolve this did.
          continue;
        }
        Err(error) => {
          if let Error::ResolutionAttemptError(_) = error {
            return Err(error);
          } else {
            let _ = err.insert(error);
          }
        }
      }
    }

    if let Some(error) = err {
      Err(error)
    } else {
      Err(Error::NoCompatibleHandlerError)
    }
  }
}

impl Resolver<Box<dyn ValidatorDocument>> {
  /// Fetches the DID Document of the given DID and attempts to cast the result to the desired document type.
  ///
  ///
  /// # Errors
  /// Errors if the resolver has not been configured to handle the method corresponding to the given did, the resolution
  /// process itself fails, or the resolved document is of another type than the specified [`Document`] implementer.  
  //TODO: Improve error handling.
  pub async fn resolve_to<DOCUMENT, D>(&self, did: &D) -> Result<DOCUMENT>
  where
    D: DID,
    DOCUMENT: Document + 'static,
  {
    let validator_doc = self.delegate_resolution(did.method(), did.as_str()).await?;

    validator_doc
      .into_any()
      .downcast::<DOCUMENT>()
      .map(|boxed| *boxed)
      .map_err(|_| Error::ResolutionProblem("failed to convert the resolved document to the desired type".into()))
  }

  /// Constructs a new [`Resolver`] that operates with DID Documents abstractly.
  pub fn new_dynamic() -> Resolver<Box<dyn ValidatorDocument>> {
    Resolver::<Box<dyn ValidatorDocument>>::new()
  }
}

impl<DOC: BorrowValidator> Default for Resolver<DOC> {
  fn default() -> Self {
    Self::new()
  }
}
