use crate::error::Result;
use crate::lib::*;

pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
  let mut bytes: Vec<u8> = vec![0; size];

  ::crypto::utils::rand::fill(&mut bytes)?;

  Ok(bytes)
}
