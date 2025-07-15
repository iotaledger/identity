// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::create_did_document;
use examples::get_funded_client;
use examples::get_memstorage;
use identity_iota::core::FromJson;
use identity_iota::core::ToJson;
use identity_iota::did::CoreDID;
use identity_iota::did::DID;
use identity_iota::document::CoreDocument;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;

/// Demonstrates how to set up a resolver using custom handlers.
///
/// NOTE: Since both `IotaDocument` and `FooDocument` implement `Into<CoreDocument>` we could have used
/// Resolver<CoreDocument> in this example and just worked with `CoreDocument` representations throughout.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // create new client to interact with chain and get funded account with keys
  let storage = get_memstorage()?;
  let identity_client = get_funded_client(&storage).await?;
  // create new DID document and publish it
  let (document, _) = create_did_document(&identity_client, &storage).await?;

  // Create a resolver returning an enum of the documents we are interested in and attach handlers for the "foo" and
  // "iota" methods.
  let mut resolver: Resolver<Document> = Resolver::new();

  // This is a convenience method for attaching a handler for the "iota" method by providing just a client.
  resolver.attach_iota_handler((*identity_client).clone());
  resolver.attach_handler("foo".to_owned(), resolve_did_foo);

  // A fake did:foo DID for demonstration purposes.
  let did_foo: CoreDID = "did:foo:0e9c8294eeafee326a4e96d65dbeaca0".parse()?;

  // Resolve did_foo to get an abstract document.
  let did_foo_doc: Document = resolver.resolve(&did_foo).await?;

  // Resolve iota_did to get an abstract document.
  let iota_doc: Document = resolver.resolve(&document.id().clone()).await?;

  // The Resolver is mainly meant for validating presentations, but here we will just
  // check that the resolved documents match our expectations.

  let Document::Foo(did_foo_document) = did_foo_doc else {
    anyhow::bail!("expected a foo DID document when resolving a foo DID");
  };

  println!(
    "Resolved DID foo document: {}",
    did_foo_document.as_ref().to_json_pretty()?
  );

  let Document::Iota(iota_document) = iota_doc else {
    anyhow::bail!("expected an IOTA DID document when resolving an IOTA DID")
  };

  println!("Resolved IOTA DID document: {}", iota_document.to_json_pretty()?);

  Ok(())
}

// Type safe representation of a document adhering to the imaginary "foo" method.
struct FooDocument(CoreDocument);
impl FooDocument {
  fn new(document: CoreDocument) -> anyhow::Result<Self> {
    if document.id().method() == "foo" {
      Ok(Self(document))
    } else {
      anyhow::bail!("cannot construct foo document: incorrect method")
    }
  }
}

impl AsRef<CoreDocument> for FooDocument {
  fn as_ref(&self) -> &CoreDocument {
    &self.0
  }
}

impl From<FooDocument> for CoreDocument {
  fn from(value: FooDocument) -> Self {
    value.0
  }
}

// Enum of the document types we want to handle.
enum Document {
  Foo(FooDocument),
  Iota(IotaDocument),
}

impl From<FooDocument> for Document {
  fn from(value: FooDocument) -> Self {
    Self::Foo(value)
  }
}

impl From<IotaDocument> for Document {
  fn from(value: IotaDocument) -> Self {
    Self::Iota(value)
  }
}

impl AsRef<CoreDocument> for Document {
  fn as_ref(&self) -> &CoreDocument {
    match self {
      Self::Foo(doc) => doc.as_ref(),
      Self::Iota(doc) => doc.as_ref(),
    }
  }
}

/// Resolve a did to a DID document if the did method is "foo".
async fn resolve_did_foo(did: CoreDID) -> anyhow::Result<FooDocument> {
  let doc = CoreDocument::from_json(&format!(
    r#"{{
      "id": "{did}",
      "verificationMethod": [
        {{
          "id": "{did}#key-1",
          "controller": "{did}",
          "type": "Ed25519VerificationKey2018",
          "publicKeyMultibase": "zGurPxZGpqnJ6j866DNBXYQJH2KzJjmQ9KBpCYp9oYJom"
        }}
      ]
      }}"#,
  ))
  .unwrap();
  FooDocument::new(doc)
}
