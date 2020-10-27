//! Publish new did document and read it from the tangle
//! cargo run --example publish

use identity_core::key::PublicKey;
use identity_crypto::KeyPair;
use identity_iota::{
    did::{IotaDID, IotaDocument},
    error::Result,
    helpers::create_ed25519_key,
    io::TangleWriter,
    network::{Network, NodeList},
};
use iota_conversion::Trinary as _;

#[smol_potat::main]
async fn main() -> Result<()> {
    let nodes = vec![
        "http://localhost:14265",
        "https://nodes.thetangle.org:443",
        "https://iotanode.us:14267",
        "https://pow.iota.community:443",
    ];
    let nodelist = NodeList::with_network_and_nodes(Network::Mainnet, nodes);

    let tangle_writer = TangleWriter::new(&nodelist)?;

    // Create keypair
    let keypair: KeyPair = IotaDocument::generate_ed25519_keypair();

    // Create DID and authentication method
    let did: IotaDID = IotaDID::new(keypair.public().as_ref())?;
    let key: PublicKey = create_ed25519_key(&did, keypair.public().as_ref())?;

    // Create a minimal DID document from the DID and authentication method
    let mut document: IotaDocument = IotaDocument::new(did, key)?;

    // Sign the document with the authentication method secret
    document.sign(keypair.secret())?;

    // Ensure the document proof is valid
    assert!(document.verify().is_ok());

    println!("DID: {}", document.did());

    let tail_transaction = tangle_writer.write_json(document.did(), &document).await?;

    println!(
        "DID document published: https://thetangle.org/transaction/{}",
        tail_transaction.as_i8_slice().trytes().expect("Couldn't get Trytes")
    );

    Ok(())
}
