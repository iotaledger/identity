// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::rc::Rc;

use identity_iota::did::CoreDID;
use identity_iota::did::DID;
use identity_iota::iota::DidResolutionHandler;
use identity_iota::iota::IotaDID;
use identity_iota::resolver::SingleThreadedResolver;
use js_sys::Array;
use js_sys::Function;
use js_sys::JsString;
use js_sys::Map;
use js_sys::Promise;
use wasm_bindgen_futures::JsFuture;

use crate::common::ArrayString;
use crate::error::JsValueResult;
use crate::iota::WasmIotaDID;
use crate::iota::WasmIotaDocument;
use crate::resolver::resolver_config::MapResolutionHandler;
use crate::resolver::resolver_config::ResolverConfig;
use crate::resolver::PromiseArrayIToCoreDocument;
use crate::resolver::WasmDidResolutionHandler;

use super::resolver_types::PromiseIToCoreDocument;
use product_common::bindings::wasm_error::Result;
use product_common::bindings::wasm_error::WasmResult;
use product_common::bindings::wasm_error::WasmError;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;

type JsDocumentResolver = SingleThreadedResolver<JsValue>;

/// Convenience type for resolving DID documents from different DID methods.   
///  
/// Also provides methods for resolving DID Documents associated with
/// verifiable {@link Credential}s and {@link Presentation}s.
///
/// # Configuration
///
/// The resolver will only be able to resolve DID documents for methods it has been configured for in the constructor.
#[wasm_bindgen(js_name = Resolver)]
pub struct WasmResolver(Rc<JsDocumentResolver>);

#[wasm_bindgen(js_class = Resolver)]
impl WasmResolver {
  /// Constructs a new {@link Resolver}.
  ///
  /// # Errors
  /// If both a `client` is given and the `handlers` map contains the "iota" key the construction process
  /// will throw an error because the handler for the "iota" method then becomes ambiguous.
  #[wasm_bindgen(constructor)]
  pub fn new(config: ResolverConfig) -> Result<WasmResolver> {
    let mut resolver: JsDocumentResolver = SingleThreadedResolver::new();

    let mut attached_iota_method = false;
    let resolution_handlers: Option<MapResolutionHandler> = config.handlers();
    let client: Option<WasmDidResolutionHandler> = config.client();

    if let Some(handlers) = resolution_handlers {
      let map: &Map = handlers.dyn_ref::<js_sys::Map>().ok_or_else(|| {
        WasmError::new(
          Cow::Borrowed("ResolverError::ConstructionError"),
          Cow::Borrowed(
            "could not construct resolver: the constructor did not receive a map of asynchronous functions",
          ),
        )
      })?;

      Self::attach_handlers(&mut resolver, map, &mut attached_iota_method)?;
    }

    if let Some(wasm_client) = client {
      if attached_iota_method {
        Err(WasmError::new(
          Cow::Borrowed("ResolverError::ConstructionError"),
          Cow::Borrowed("could not construct resolver: cannot attach the iota method twice"),
        ))?;
      }

      let rc_client: Rc<WasmDidResolutionHandler> = Rc::new(wasm_client);
      // Take CoreDID (instead of IotaDID) to avoid inconsistent error messages between the
      // cases when the iota handler is attached by passing a client or directly as a handler.
      let handler = move |did: CoreDID| {
        let rc_client_clone: Rc<WasmDidResolutionHandler> = rc_client.clone();
        async move {
          let iota_did: IotaDID = IotaDID::parse(did).map_err(identity_iota::iota::Error::DIDSyntaxError)?;
          Self::client_as_handler(rc_client_clone.as_ref(), iota_did.into()).await
        }
      };
      resolver.attach_handler(IotaDID::METHOD.to_owned(), handler);
    }

    Ok(Self(Rc::new(resolver)))
  }

  pub(crate) async fn client_as_handler<H>(
    client: &H,
    did: WasmIotaDID,
  ) -> std::result::Result<WasmIotaDocument, identity_iota::iota::Error>
  where
    H: DidResolutionHandler,
  {
    Ok(WasmIotaDocument::from(client.resolve_did(&did.0).await?))
  }

  /// attempts to extract (method, handler) pairs from the entries of a map and attaches them to the resolver.
  fn attach_handlers(resolver: &mut JsDocumentResolver, map: &Map, attached_iota_method: &mut bool) -> Result<()> {
    for key in map.keys() {
      if let Ok(js_method) = key {
        let js_handler: JsValue = map.get(&js_method);
        let did_method: String = js_method.as_string().ok_or_else(|| {
          WasmError::new(
            Cow::Borrowed("ResolverError::ConstructionError"),
            Cow::Borrowed("could not construct resolver: the handler map contains a key which is not a string"),
          )
        })?;
        let handler: Function = js_handler
          .dyn_into::<Function>()
          .map_err(|_| "could not construct resolver: the handler map contains a value which is not a function")?;

        if did_method == IotaDID::METHOD {
          *attached_iota_method = true;
        }

        WasmResolver::attach_handler(resolver, did_method, handler);
      } else {
        Err(WasmError::new(
          Cow::Borrowed("ResolverError::ConstructionError"),
          Cow::Borrowed(
            "could not construct resolver: invalid constructor arguments. Expected a map of asynchronous functions",
          ),
        ))?;
      }
    }

    Ok(())
  }

  /// Converts a JS handler to a Rust closure and attaches it to the given `resolver`.
  fn attach_handler(resolver: &mut JsDocumentResolver, method: String, handler: Function) {
    let fun = move |input: CoreDID| {
      let fun_clone: Function = handler.clone();
      async move {
        let closure_output_promise: Promise = Promise::resolve(
          &JsValueResult::from(fun_clone.call1(&JsValue::null(), &input.as_str().into())).stringify_error()?,
        );
        let awaited_output: JsValue =
          JsValueResult::from(JsFuture::from(closure_output_promise).await).stringify_error()?;

        std::result::Result::<_, String>::Ok(awaited_output)
      }
    };

    resolver.attach_handler(method, fun);
  }

  /// Fetches the DID Document of the given DID.
  ///
  /// ### Errors
  ///
  /// Errors if the resolver has not been configured to handle the method
  /// corresponding to the given DID or the resolution process itself fails.
  #[wasm_bindgen]
  pub fn resolve(&self, did: &str) -> Result<PromiseIToCoreDocument> {
    let resolver: Rc<JsDocumentResolver> = self.0.clone();
    let did: CoreDID = CoreDID::parse(did).wasm_result()?;

    let promise: Promise = future_to_promise(async move {
      resolver
        .resolve(&did)
        .await
        .map_err(WasmError::from)
        .map_err(JsValue::from)
    });

    Ok(promise.unchecked_into::<PromiseIToCoreDocument>())
  }

  /// Concurrently fetches the DID Documents of the multiple given DIDs.
  ///
  /// # Errors
  /// * If the resolver has not been configured to handle the method of any of the given DIDs.
  /// * If the resolution process of any DID fails.
  ///
  /// ## Note
  /// * The order of the documents in the returned array matches that in `dids`.
  /// * If `dids` contains duplicates, these will be resolved only once and the resolved document
  /// is copied into the returned array to match the order of `dids`.
  #[wasm_bindgen(js_name=resolveMultiple)]
  pub fn resolve_multiple(&self, dids: ArrayString) -> Result<PromiseArrayIToCoreDocument> {
    let dids: Vec<String> = dids
      .dyn_into::<Array>()?
      .iter()
      .map(|item| item.dyn_into::<JsString>().map(String::from))
      .collect::<Result<Vec<String>>>()?;
    let core_dids: Vec<CoreDID> = dids
      .iter()
      .map(CoreDID::parse)
      .collect::<std::result::Result<Vec<CoreDID>, identity_iota::did::Error>>()
      .wasm_result()?;

    let resolver: Rc<JsDocumentResolver> = self.0.clone();
    let promise: Promise = future_to_promise(async move {
      resolver
        .resolve_multiple(&core_dids)
        .await
        .map_err(WasmError::from)
        .map_err(JsValue::from)
        .map(|documents| {
          let mut ordered_documents: Vec<JsValue> = Vec::with_capacity(core_dids.len());
          // Reconstructs the order of `dids`.
          for did in core_dids {
            let doc: JsValue = documents.get(&did).cloned().unwrap();
            ordered_documents.push(doc);
          }
          ordered_documents
        })
        .map(|documents| {
          documents
            .into_iter()
            .collect::<js_sys::Array>()
            .unchecked_into::<JsValue>()
        })
    });

    Ok(promise.unchecked_into::<PromiseArrayIToCoreDocument>())
  }
}
