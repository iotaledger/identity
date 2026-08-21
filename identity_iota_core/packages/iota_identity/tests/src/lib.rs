use iota_sdk::types::ObjectId;
use std::sync::LazyLock;

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
  let identity_pkg_id = std::env::var("IOTA_IDENTITY_PKG_ID")
    .expect("IOTA_IDENTITY_PKG_ID environment variable not set")
    .parse()
    .expect("IOTA_IDENTITY_PKG_ID environment variable is not a valid ObjectId");
  let package_metadata_id = std::env::var("PKG_METADATA_ID")
    .expect("PKG_METADATA_ID environment variable not set")
    .parse()
    .expect("PKG_METADATA_ID environment variable is not a valid ObjectId");
  Config {
    identity_pkg_id,
    package_metadata_id,
  }
});

#[derive(Debug)]
pub struct Config {
  pub identity_pkg_id: ObjectId,
  pub package_metadata_id: ObjectId,
}

pub mod identity;

pub fn init() -> &'static Config {
  &CONFIG
}

trait FromMoveViewCallResult: Sized {
  fn from_move_view_call_result(result: &mut serde_json::Value) -> anyhow::Result<Self>;
}
