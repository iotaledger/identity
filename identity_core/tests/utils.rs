use identity_core::{
    did::DID,
    utils::{Context, KeyData, PublicKey, Service, ServiceEndpoint, Subject},
};

use std::str::FromStr;

const JSON_STR: &str = include_str!("utils.json");

fn setup_json(key: &str) -> String {
    let json_str = json::parse(JSON_STR).unwrap();

    json_str[key].to_string()
}

/// Test Context::new
#[test]
fn test_context() {
    let raw_str = r#"["https://w3id.org/did/v1","https://w3id.org/security/v1"]"#;
    let ctx = Context::new(vec![
        "https://w3id.org/did/v1".into(),
        "https://w3id.org/security/v1".into(),
    ]);

    let string = serde_json::to_string(&ctx).unwrap();

    assert_eq!(string, raw_str);
}

/// Test building a Subject from a did string.
#[test]
fn test_subject_from_string() {
    let raw_str = r#""did:iota:123456789abcdefghi""#;
    let subject = Subject::new("did:iota:123456789abcdefghi".into()).unwrap();

    let string = serde_json::to_string(&subject).unwrap();

    assert_eq!(string, raw_str);
}

/// Test building a subject from a DID structure.
#[test]
fn test_subject_from_did() {
    let did = DID {
        method_name: "iota".into(),
        id_segments: vec!["123456".into(), "789011".into()],
        query: Some(vec![("name".into(), Some("value".into())).into()]),
        ..Default::default()
    }
    .init()
    .unwrap();

    let string = format!("\"{}\"", did.to_string());

    let subject = Subject::from_did(did).unwrap();
    let res = serde_json::to_string(&subject).unwrap();

    assert_eq!(res, string);
}

/// Test Subject from a DID using the From Trait.
#[test]
fn test_subject_from() {
    let did = DID {
        method_name: "iota".into(),
        id_segments: vec!["123456".into(), "789011".into()],
        query: Some(vec![("name".into(), Some("value".into())).into()]),
        ..Default::default()
    }
    .init()
    .unwrap();

    let string = format!("\"{}\"", did.to_string());

    let subject: Subject = did.into();

    let res = serde_json::to_string(&subject).unwrap();

    assert_eq!(res, string);
}

/// Test public key structure from String and with PublicKey::new
#[test]
fn test_public_key() {
    let raw_str = setup_json("public");

    let pk_t = PublicKey::from_str(&raw_str).unwrap();

    let key_data = KeyData::Base58("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV".into());

    let public_key = PublicKey {
        id: "did:iota:123456789abcdefghi#keys-1".into(),
        key_type: "Ed25519VerificationKey2018".into(),
        controller: "did:iota:pqrstuvwxyz0987654321".into(),
        key_data,
        ..Default::default()
    };

    assert_eq!(public_key, pk_t);

    let res = serde_json::to_string(&public_key).unwrap();

    assert_eq!(res, pk_t.to_string());
}

/// Test service without ServiceEndpoint body.
#[test]
fn test_service_with_no_endpoint_body() {
    let raw_str = setup_json("service");

    let endpoint = ServiceEndpoint {
        context: "https://edv.example.com/".into(),
        ..Default::default()
    }
    .init();

    let service = Service {
        id: "did:into:123#edv".into(),
        service_type: "EncryptedDataVault".into(),
        endpoint,
    };

    let service_2: Service = Service::from_str(&raw_str).unwrap();

    assert_eq!(service, service_2);

    let res = serde_json::to_string(&service).unwrap();

    assert_eq!(res, service_2.to_string());
}

/// Test Service with a ServiceEndpoint Body.
#[test]
fn test_service_with_body() {
    let raw_str = setup_json("endpoint");

    let endpoint = ServiceEndpoint {
        context: "https://schema.identity.foundation/hub".into(),
        endpoint_type: Some("UserHubEndpoint".into()),
        instances: Some(vec!["did:example:456".into(), "did:example:789".into()]),
    }
    .init();

    let service = Service {
        id: "did:example:123456789abcdefghi#hub".into(),
        service_type: "IdentityHub".into(),
        endpoint,
    };

    let service_2: Service = Service::from_str(&raw_str).unwrap();

    assert_eq!(service, service_2);

    let res = serde_json::to_string(&service).unwrap();

    assert_eq!(res, service_2.to_string());
}
