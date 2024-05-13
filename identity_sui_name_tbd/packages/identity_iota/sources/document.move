module identity_iota::document {
    use sui::{balance::Balance, bag::Bag, sui::SUI, transfer::share_object};
    use stardust::alias_output::{AliasOutput, extract_assets};
    use identity_iota::{controller, controller::ControllerCap, migration_registry::MigrationRegistry};

    const ENotADidOutput: u64 = 1;
    const EInvalidCapability: u64 = 2;

    /// DID document.
    public struct Document has key {
        id: UID,
        doc: vector<u8>,
        iota: Balance<SUI>,
        native_tokens: Bag,
    }

    /// Creates a new `Document` from an Iota 1.0 legacy `AliasOutput`.
    public fun from_legacy_alias_output(
        alias_output: AliasOutput,
        migration_registry: &mut MigrationRegistry,
        ctx: &mut TxContext
    ): ControllerCap {
        // Extract required data from output.
        let (iota, native_tokens, alias_data) = extract_assets(alias_output);
        let (
            alias_id,
            _,
            _,
            mut state_metadata,
            _,
            _,
            _,
            _,
        ) = alias_data.destructure();
        // Check if `state_metadata` contains a DID document.
        assert!(is_did_output(state_metadata.borrow()), ENotADidOutput);
        let legacy_id = alias_id.to_inner();
        // Destroy alias.
        object::delete(alias_id);

        let id = object::new(ctx);
        let doc_id = id.to_inner();
        // Create a capability for the governor.
        let controller_capability = controller::new(doc_id, ctx);
        // Create and share the new DID document.
        let document = Document {
            id,
            iota,
            native_tokens,
            doc: state_metadata.extract()
        };
        share_object(document);

        // Add a migration record.
        migration_registry.add(legacy_id, doc_id);

        // Transfer the capability to the governor.
        controller_capability
    }

    /// Updates the DID document.
    public fun update(self: &mut Document, data: vector<u8>, controller_capability: &ControllerCap) {
        // Check the provided capability is for this document.
        assert!(self.id.to_inner() == controller_capability.did(), EInvalidCapability);
        // Check `data` is a DID document.
        assert!(is_did_output(&data), ENotADidOutput);
        self.doc = data;
    }

    /// Checks if `data` is a state matadata representing a DID.
    /// i.e. starts with the bytes b"DID".
    fun is_did_output(data: &vector<u8>): bool {
        data[0] == 0x44 &&      // b'D'
            data[1] == 0x49 &&  // b'I'
            data[2] == 0x44     // b'D'
    }
}