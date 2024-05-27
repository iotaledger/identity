use std::str::FromStr;

use serde;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sui_sdk::rpc_types::SuiObjectDataOptions;
use sui_sdk::rpc_types::SuiParsedData;
use sui_sdk::types::base_types::ObjectID;
use sui_sdk::types::id::UID;
use sui_sdk::SuiClient;

use crate::Error;

#[derive(Debug, Deserialize, Serialize)]
pub struct Document {
  pub id: UID,
  pub doc: Vec<u8>,
  pub iota: String,
  pub native_tokens: Value,
}

pub async fn get_identity_document(client: &SuiClient, object_id: &str) -> Result<Option<Document>, Error> {
  let object_id = ObjectID::from_str(object_id)
    .map_err(|err| Error::ObjectLookup(format!("Could not parse given object id {object_id}; {err}")))?;
  let options = SuiObjectDataOptions {
    show_type: true,
    show_owner: true,
    show_previous_transaction: true,
    show_display: true,
    show_content: true,
    show_bcs: true,
    show_storage_rebate: true,
  };
  let response = client
    .read_api()
    .get_object_with_options(object_id, options)
    .await
    .map_err(|err| {
      Error::ObjectLookup(format!(
        "Could not get object with options for this object_id {object_id}; {err}"
      ))
    })?;

  // no issues with call but
  let Some(data) = response.data else {
    // call was successful but not data for alias id
    return Ok(None);
  };

  let content = data
    .content
    .ok_or_else(|| Error::ObjectLookup(format!("no content in retrieved object in object id {object_id}")))?;

  let SuiParsedData::MoveObject(value) = content else {
    return Err(Error::ObjectLookup(format!(
      "found data at object id {object_id} is not an object"
    )));
  };
  dbg!(&value);

  let alias: Document = serde_json::from_value(value.fields.to_json_value()).unwrap();

  Ok(Some(alias))
}
