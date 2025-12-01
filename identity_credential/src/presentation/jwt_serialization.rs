// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use serde::Deserialize;
use serde::Serialize;

use identity_core::common::Context;
use identity_core::common::Object;
use identity_core::common::OneOrMany;
use identity_core::common::Url;
use serde::de::DeserializeOwned;

use crate::credential::IssuanceDateClaims;
use crate::credential::Jwt;
use crate::credential::Policy;
use crate::credential::Proof;
use crate::credential::RefreshService;
use crate::presentation::Presentation;
#[cfg(feature = "validator")]
use crate::Error;
use crate::Result;

use super::JwtPresentationOptions;

#[derive(Serialize, Deserialize)]
pub(crate) struct PresentationJwtClaims<'presentation, CRED, T = Object>
where
  T: ToOwned + Serialize,
  CRED: ToOwned + Serialize + Clone,
  <CRED as ToOwned>::Owned: DeserializeOwned,
  <T as ToOwned>::Owned: DeserializeOwned,
{
  /// Represents the expirationDate encoded as a UNIX timestamp.  
  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) exp: Option<i64>,

  /// Represents the holder of the verifiable presentation.
  pub(crate) iss: Cow<'presentation, Url>,

  /// Represents the issuanceDate encoded as a UNIX timestamp.
  #[serde(flatten)]
  pub(crate) issuance_date: Option<IssuanceDateClaims>,

  /// Represents the id property of the credential.
  #[serde(skip_serializing_if = "Option::is_none")]
  jti: Option<Cow<'presentation, Url>>,

  #[serde(skip_serializing_if = "Option::is_none")]
  pub(crate) aud: Option<Url>,

  pub(crate) vp: InnerPresentation<'presentation, CRED, T>,

  #[serde(flatten, skip_serializing_if = "Option::is_none")]
  pub(crate) custom: Option<Object>,
}

impl<'presentation, CRED, T> PresentationJwtClaims<'presentation, CRED, T>
where
  T: ToOwned<Owned = T> + Serialize + DeserializeOwned,
  CRED: ToOwned<Owned = CRED> + Serialize + DeserializeOwned + Clone,
{
  pub(super) fn new(
    presentation: &'presentation Presentation<CRED, T>,
    options: &JwtPresentationOptions,
  ) -> Result<Self> {
    let Presentation {
      context,
      id,
      types,
      verifiable_credential,
      holder,
      refresh_service,
      terms_of_use,
      properties,
      proof,
    } = presentation;

    Ok(Self {
      iss: Cow::Borrowed(holder),
      jti: id.as_ref().map(Cow::Borrowed),
      vp: InnerPresentation {
        context: Cow::Borrowed(context),
        id: None,
        types: Cow::Borrowed(types),
        verifiable_credential: Cow::Borrowed(verifiable_credential),
        refresh_service: Cow::Borrowed(refresh_service),
        terms_of_use: Cow::Borrowed(terms_of_use),
        properties: Cow::Borrowed(properties),
        proof: proof.as_ref().map(Cow::Borrowed),
        holder: None,
      },
      exp: options.expiration_date.map(|expiration_date| expiration_date.to_unix()),
      issuance_date: options.issuance_date.map(IssuanceDateClaims::new),
      aud: options.audience.clone(),
      custom: options.custom_claims.clone(),
    })
  }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct InnerPresentation<'presentation, CRED = Jwt, T = Object>
where
  CRED: Clone + Serialize,
  T: ToOwned + Serialize,
  <T as ToOwned>::Owned: DeserializeOwned,
{
  /// The JSON-LD context(s) applicable to the `Presentation`.
  #[serde(rename = "@context")]
  context: Cow<'presentation, OneOrMany<Context>>,
  /// A unique `URI` that may be used to identify the `Presentation`.
  #[serde(skip_serializing_if = "Option::is_none")]
  id: Option<Url>,
  /// One or more URIs defining the type of the `Presentation`.
  #[serde(rename = "type")]
  types: Cow<'presentation, OneOrMany<String>>,
  /// Credential(s) expressing the claims of the `Presentation`.
  #[serde(default = "Default::default", rename = "verifiableCredential")]
  pub(crate) verifiable_credential: Cow<'presentation, [CRED]>,
  /// The entity that generated the `Presentation`.
  #[serde(skip_serializing_if = "Option::is_none")]
  holder: Option<Url>,
  /// Service(s) used to refresh an expired [`Credential`] in the `Presentation`.
  #[serde(default, rename = "refreshService", skip_serializing_if = "OneOrMany::is_empty")]
  refresh_service: Cow<'presentation, OneOrMany<RefreshService>>,
  /// Terms-of-use specified by the `Presentation` holder.
  #[serde(default, rename = "termsOfUse", skip_serializing_if = "OneOrMany::is_empty")]
  terms_of_use: Cow<'presentation, OneOrMany<Policy>>,
  /// Miscellaneous properties.
  #[serde(flatten)]
  properties: Cow<'presentation, T>,
  /// Proof(s) used to verify a `Presentation`
  #[serde(skip_serializing_if = "Option::is_none")]
  proof: Option<Cow<'presentation, Proof>>,
}

#[cfg(feature = "validator")]
impl<CRED, T> PresentationJwtClaims<'_, CRED, T>
where
  CRED: ToOwned<Owned = CRED> + Serialize + DeserializeOwned + Clone,
  T: ToOwned<Owned = T> + Serialize + DeserializeOwned,
{
  pub(crate) fn try_into_presentation(self) -> Result<Presentation<CRED, T>> {
    self.check_consistency()?;
    let Self {
      exp: _,
      iss,
      issuance_date: _,
      jti,
      aud: _,
      vp,
      custom: _,
    } = self;
    let InnerPresentation {
      context,
      id: _,
      types,
      verifiable_credential,
      refresh_service,
      terms_of_use,
      properties,
      proof,
      holder: _,
    } = vp;

    let presentation = Presentation {
      context: context.into_owned(),
      id: jti.map(Cow::into_owned),
      types: types.into_owned(),
      verifiable_credential: verifiable_credential.into_owned(),
      holder: iss.into_owned(),
      refresh_service: refresh_service.into_owned(),
      terms_of_use: terms_of_use.into_owned(),
      properties: properties.into_owned(),
      proof: proof.map(Cow::into_owned),
    };

    Ok(presentation)
  }

  fn check_consistency(&self) -> Result<()> {
    if !self
      .vp
      .id
      .as_ref()
      .map(|value| self.jti.as_ref().filter(|jti| jti.as_ref() == value).is_some())
      .unwrap_or(true)
    {
      return Err(Error::InconsistentPresentationJwtClaims("inconsistent presentation id"));
    };

    if !self
      .vp
      .holder
      .as_ref()
      .map(|value| self.iss.as_ref() == value)
      .unwrap_or(true)
    {
      return Err(Error::InconsistentPresentationJwtClaims(
        "inconsistent presentation holder",
      ));
    };

    Ok(())
  }
}

#[derive(Debug, Deserialize)]
#[serde(bound = "C: serde::de::DeserializeOwned, T: serde::de::DeserializeOwned")]
pub(crate) struct JwtPresentationV2Claims<C, T> {
  pub(crate) iat: Option<i64>,
  pub(crate) exp: Option<i64>,
  pub(crate) aud: Option<Url>,
  #[serde(flatten)]
  pub(crate) vp: Presentation<C, T>,
}

#[cfg(test)]
mod test {
  use super::PresentationJwtClaims;
  use crate::credential::Jwt;
  use crate::presentation::JwtPresentationOptions;
  use crate::presentation::Presentation;
  use crate::Error;
  use identity_core::common::Object;
  use identity_core::common::Timestamp;
  use identity_core::convert::FromJson;
  use identity_core::convert::ToJson;

  #[test]
  fn roundtrip() {
    let presentation_json: &str = r#"
    {
      "id": "http://example.edu/presentations/3732",
      "@context": "https://www.w3.org/2018/credentials/v1",
      "type": "VerifiablePresentation",
      "verifiableCredential": [
        "eyJraWQiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjI3NzQkJ6dGpDekhzanRac2xXZmJadWszeGJQOHQwU2JTIiwiYWxnIjoiRWREU0EifQ.eyJpc3MiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjIiwibmJmIjoxNjk0Njk1MTM1LCJqdGkiOiJodHRwczovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJzdWIiOiJkaWQ6aW90YTp0c3Q6MHg2YTU4YWExMmFmY2ZhNjk4YTViZjU5OTE4MzY5YzBhYTM5OTU1ZjFhZTVhN2U1MTZiYzZiZDRkYzI3MTJkNmM3IiwidmMiOnsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJHUEEiOiI0LjAiLCJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwibmFtZSI6IkFsaWNlIn19fQ.ADYZEltOt2S5j2z_lnfo1GK69zUI8ndgS4CWORZT_IUuNZ9PZPzhVXaXvJ07X8iYHa7I63urKXWZnzrmMQ7UBA"
      ],
      "holder": "did:iota:tst:0x6a58aa12afcfa698a5bf59918369c0aa39955f1ae5a7e516bc6bd4dc2712d6c7"
    }
    "#;
    let claims_json: &str = r#"
    {
      "jti": "http://example.edu/presentations/3732",
      "exp": 1694699551,
      "iss": "did:iota:tst:0x6a58aa12afcfa698a5bf59918369c0aa39955f1ae5a7e516bc6bd4dc2712d6c7",
      "nbf": 1694698951,
      "vp": {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "type": "VerifiablePresentation",
        "verifiableCredential": [
          "eyJraWQiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjI3NzQkJ6dGpDekhzanRac2xXZmJadWszeGJQOHQwU2JTIiwiYWxnIjoiRWREU0EifQ.eyJpc3MiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjIiwibmJmIjoxNjk0Njk1MTM1LCJqdGkiOiJodHRwczovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJzdWIiOiJkaWQ6aW90YTp0c3Q6MHg2YTU4YWExMmFmY2ZhNjk4YTViZjU5OTE4MzY5YzBhYTM5OTU1ZjFhZTVhN2U1MTZiYzZiZDRkYzI3MTJkNmM3IiwidmMiOnsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJHUEEiOiI0LjAiLCJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwibmFtZSI6IkFsaWNlIn19fQ.ADYZEltOt2S5j2z_lnfo1GK69zUI8ndgS4CWORZT_IUuNZ9PZPzhVXaXvJ07X8iYHa7I63urKXWZnzrmMQ7UBA"
        ]
      }
    }
    "#;

    let presentation: Presentation<Jwt> = Presentation::from_json(presentation_json).unwrap();
    let options = JwtPresentationOptions {
      expiration_date: Some(Timestamp::from_unix(1694699551).unwrap()),
      issuance_date: Some(Timestamp::from_unix(1694698951).unwrap()),
      audience: None,
      custom_claims: None,
    };
    let claims: PresentationJwtClaims<'_, Jwt> =
      PresentationJwtClaims::<'_, Jwt>::new(&presentation, &options).unwrap();
    let claims_serialized: String = claims.to_json().unwrap();
    assert_eq!(
      Object::from_json(&claims_serialized).unwrap(),
      Object::from_json(claims_json).unwrap()
    );
    let retrieved_presentation: Presentation<Jwt> = PresentationJwtClaims::<'_, Jwt>::from_json(&claims_serialized)
      .unwrap()
      .try_into_presentation()
      .unwrap();

    assert_eq!(presentation, retrieved_presentation);
  }

  #[test]
  fn claim_duplication() {
    let presentation_json: &str = r#"
    {
      "id": "http://example.edu/presentations/3732",
      "@context": "https://www.w3.org/2018/credentials/v1",
      "type": "VerifiablePresentation",
      "verifiableCredential": [
        "eyJraWQiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjI3NzQkJ6dGpDekhzanRac2xXZmJadWszeGJQOHQwU2JTIiwiYWxnIjoiRWREU0EifQ.eyJpc3MiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjIiwibmJmIjoxNjk0Njk1MTM1LCJqdGkiOiJodHRwczovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJzdWIiOiJkaWQ6aW90YTp0c3Q6MHg2YTU4YWExMmFmY2ZhNjk4YTViZjU5OTE4MzY5YzBhYTM5OTU1ZjFhZTVhN2U1MTZiYzZiZDRkYzI3MTJkNmM3IiwidmMiOnsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJHUEEiOiI0LjAiLCJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwibmFtZSI6IkFsaWNlIn19fQ.ADYZEltOt2S5j2z_lnfo1GK69zUI8ndgS4CWORZT_IUuNZ9PZPzhVXaXvJ07X8iYHa7I63urKXWZnzrmMQ7UBA"
      ],
      "holder": "did:iota:tst:0x6a58aa12afcfa698a5bf59918369c0aa39955f1ae5a7e516bc6bd4dc2712d6c7"
    }
    "#;
    let claims_json: &str = r#"
    {
      "jti": "http://example.edu/presentations/3732",
      "exp": 1694699551,
      "iss": "did:iota:tst:0x6a58aa12afcfa698a5bf59918369c0aa39955f1ae5a7e516bc6bd4dc2712d6c7",
      "nbf": 1694698951,
      "vp": {
        "id": "http://example.edu/presentations/3732",
        "holder": "did:iota:tst:0x6a58aa12afcfa698a5bf59918369c0aa39955f1ae5a7e516bc6bd4dc2712d6c7",
        "@context": "https://www.w3.org/2018/credentials/v1",
        "type": "VerifiablePresentation",
        "verifiableCredential": [
          "eyJraWQiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjI3NzQkJ6dGpDekhzanRac2xXZmJadWszeGJQOHQwU2JTIiwiYWxnIjoiRWREU0EifQ.eyJpc3MiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjIiwibmJmIjoxNjk0Njk1MTM1LCJqdGkiOiJodHRwczovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJzdWIiOiJkaWQ6aW90YTp0c3Q6MHg2YTU4YWExMmFmY2ZhNjk4YTViZjU5OTE4MzY5YzBhYTM5OTU1ZjFhZTVhN2U1MTZiYzZiZDRkYzI3MTJkNmM3IiwidmMiOnsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJHUEEiOiI0LjAiLCJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwibmFtZSI6IkFsaWNlIn19fQ.ADYZEltOt2S5j2z_lnfo1GK69zUI8ndgS4CWORZT_IUuNZ9PZPzhVXaXvJ07X8iYHa7I63urKXWZnzrmMQ7UBA"
        ]
      }
    }
    "#;

    let presentation: Presentation<Jwt> = Presentation::from_json(presentation_json).unwrap();
    let retrieved_presentation: Presentation<Jwt> = PresentationJwtClaims::<'_, Jwt>::from_json(&claims_json)
      .unwrap()
      .try_into_presentation()
      .unwrap();

    assert_eq!(presentation, retrieved_presentation);
  }

  #[test]
  fn inconsistent_holder() {
    let claims_json: &str = r#"
    {
      "jti": "http://example.edu/presentations/3732",
      "exp": 1694699551,
      "iss": "did:iota:tst:0x6a58aa12afcfa698a5bf59918369c0aa39955f1ae5a7e516bc6bd4dc2712d6c7",
      "nbf": 1694698951,
      "vp": {
        "id": "http://example.edu/presentations/3732",
        "@context": "https://www.w3.org/2018/credentials/v1",
        "holder": "did:iota:tst2:0x6a58aa12afcfa698a5bf59918369c0aa39955f1ae5a7e516bc6bd4dc2712d6c7",
        "type": "VerifiablePresentation",
        "verifiableCredential": [
          "eyJraWQiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjI3NzQkJ6dGpDekhzanRac2xXZmJadWszeGJQOHQwU2JTIiwiYWxnIjoiRWREU0EifQ.eyJpc3MiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjIiwibmJmIjoxNjk0Njk1MTM1LCJqdGkiOiJodHRwczovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJzdWIiOiJkaWQ6aW90YTp0c3Q6MHg2YTU4YWExMmFmY2ZhNjk4YTViZjU5OTE4MzY5YzBhYTM5OTU1ZjFhZTVhN2U1MTZiYzZiZDRkYzI3MTJkNmM3IiwidmMiOnsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJHUEEiOiI0LjAiLCJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwibmFtZSI6IkFsaWNlIn19fQ.ADYZEltOt2S5j2z_lnfo1GK69zUI8ndgS4CWORZT_IUuNZ9PZPzhVXaXvJ07X8iYHa7I63urKXWZnzrmMQ7UBA"
        ]
      }
    }
    "#;

    let presentation_from_claims_result: Result<Presentation<Jwt>, _> =
      PresentationJwtClaims::<'_, Jwt>::from_json(claims_json)
        .unwrap()
        .try_into_presentation();
    assert!(matches!(
      presentation_from_claims_result.unwrap_err(),
      Error::InconsistentPresentationJwtClaims("inconsistent presentation holder")
    ));
  }

  #[test]
  fn inconsistent_id() {
    let claims_json: &str = r#"
    {
      "jti": "http://example.edu/presentations/3732",
      "exp": 1694699551,
      "iss": "did:iota:tst:0x6a58aa12afcfa698a5bf59918369c0aa39955f1ae5a7e516bc6bd4dc2712d6c7",
      "nbf": 1694698951,
      "vp": {
        "id": "http://example.edu/presentations/1111",
        "@context": "https://www.w3.org/2018/credentials/v1",
        "type": "VerifiablePresentation",
        "verifiableCredential": [
          "eyJraWQiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjI3NzQkJ6dGpDekhzanRac2xXZmJadWszeGJQOHQwU2JTIiwiYWxnIjoiRWREU0EifQ.eyJpc3MiOiJkaWQ6aW90YTp0c3Q6MHgxOTg0NjdmNWUzNGQwYjNkMTA3MjRhYjY3NDNhZDQxNTdjNjdjYjJiYjNhNjU2ODYzYmY2YzBjMGFmMmM3ODJjIiwibmJmIjoxNjk0Njk1MTM1LCJqdGkiOiJodHRwczovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJzdWIiOiJkaWQ6aW90YTp0c3Q6MHg2YTU4YWExMmFmY2ZhNjk4YTViZjU5OTE4MzY5YzBhYTM5OTU1ZjFhZTVhN2U1MTZiYzZiZDRkYzI3MTJkNmM3IiwidmMiOnsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJHUEEiOiI0LjAiLCJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifSwibmFtZSI6IkFsaWNlIn19fQ.ADYZEltOt2S5j2z_lnfo1GK69zUI8ndgS4CWORZT_IUuNZ9PZPzhVXaXvJ07X8iYHa7I63urKXWZnzrmMQ7UBA"
        ]
      }
    }
    "#;

    let presentation_from_claims_result: Result<Presentation<Jwt>, _> =
      PresentationJwtClaims::<'_, Jwt>::from_json(claims_json)
        .unwrap()
        .try_into_presentation();
    assert!(matches!(
      presentation_from_claims_result.unwrap_err(),
      Error::InconsistentPresentationJwtClaims("inconsistent presentation id")
    ));
  }
}
