// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

module iota_identity::asset {
    public use fun delete_recipient_cap as RecipientCap.delete;

    const EImmutable: u64 = 0;
    const ENonTransferable: u64 = 1;
    const ENonDeletable: u64 = 2;
    const EInvalidRecipient: u64 = 3;
    const EInvalidSender: u64 = 4;
    const EInvalidAsset: u64 = 5;

    // ===== Events =====

    /// Event emitted when the owner of an `AuthenticatedAsset`
    /// proposes its transfer to a new address.
    public struct AssetTransferCreated has copy, drop {
        asset: ID,
        proposal: ID,
        sender: address,
        recipient: address,
    }

    /// Event emitted when an active transfer is concluded,
    /// either canceled or completed.
    public struct AssetTransferConcluded has copy, drop {
        asset: ID,
        proposal: ID,
        sender: address,
        recipient: address,
        concluded: bool,
    }

    /// Structures that couples some data `T` with well known
    /// ownership and origin, along configurable abilities e.g.
    /// transferability, mutability and deletability.
    public struct AuthenticatedAsset<T: store> has key {
        id: UID,
        inner: T,
        origin: address,
        owner: address,
        mutable: bool,
        transferable: bool,
        deletable: bool,
    }

    /// Creates a new `AuthenticatedAsset` with default configuration: immutable, non-transferable, non-deletable;
    /// and sends it to the tx's sender.
    public fun new<T: store>(inner: T, ctx: &mut TxContext) {
        new_with_address(inner, ctx.sender(), false, false, false, ctx);
    }

    /// Creates a new `AuthenticatedAsset` with configurable properties and sends it to the tx's sender.
    public fun new_with_config<T: store>(
        inner: T,
        mutable: bool,
        transferable: bool,
        deletable: bool,
        ctx: &mut TxContext,
    ) {
        new_with_address(inner, ctx.sender(), mutable, transferable, deletable, ctx);
    }

    /// Returns the address that created this `AuthenticatedAsset`.
    public fun origin<T: store>(self: &AuthenticatedAsset<T>): address {
        self.origin
    }

    /// Immutably borrow the content of an `AuthenticatedAsset`
    public fun borrow<T: store>(self: &AuthenticatedAsset<T>): &T {
        &self.inner
    }

    /// Mutably borrow the content of an `AuthenticatedAsset`.
    /// This operation will fail if `AuthenticatedAsset` is configured as non-mutable.
    public fun borrow_mut<T: store>(self: &mut AuthenticatedAsset<T>): &mut T {
        assert!(self.mutable, EImmutable);
        &mut self.inner
    }

    /// Updates the value of the stored content. Fails if this `AuthenticatedAsset` is immutable.
    public fun set_content<T: store + drop>(self: &mut AuthenticatedAsset<T>, new_content: T) {
        assert!(self.mutable, EImmutable);
        self.inner = new_content;
    }

    public fun delete<T: store + drop>(self: AuthenticatedAsset<T>) {
        assert!(self.deletable, ENonDeletable);
        let AuthenticatedAsset {
            id,
            inner: _,
            origin: _,
            owner: _,
            mutable: _,
            transferable: _,
            deletable: _,
        } = self;
        object::delete(id);
    }

    public(package) fun new_with_address<T: store>(
        inner: T,
        addr: address,
        mutable: bool,
        transferable: bool,
        deletable: bool,
        ctx: &mut TxContext,
    ) {
        let asset = AuthenticatedAsset {
            id: object::new(ctx),
            inner,
            origin: addr,
            owner: addr,
            mutable,
            transferable,
            deletable,
        };
        transfer::transfer(asset, addr);
    }

    public fun transfer<T: store>(
        asset: AuthenticatedAsset<T>,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        assert!(asset.transferable, ENonTransferable);
        let proposal_id = object::new(ctx);
        let sender_cap = SenderCap {
            id: object::new(ctx),
            transfer_id: proposal_id.to_inner(),
        };
        let recipient_cap = RecipientCap {
            id: object::new(ctx),
            transfer_id: proposal_id.to_inner(),
        };
        let proposal = TransferProposal {
            id: proposal_id,
            asset_id: object::id(&asset),
            sender_cap_id: object::id(&sender_cap),
            sender_address: asset.owner,
            recipient_cap_id: object::id(&recipient_cap),
            recipient_address: recipient,
            done: false,
        };

        iota::event::emit(AssetTransferCreated {
            proposal: object::id(&proposal),
            asset: object::id(&asset),
            sender: asset.owner,
            recipient,
        });

        transfer::transfer(sender_cap, asset.owner);
        transfer::transfer(recipient_cap, recipient);
        transfer::transfer(asset, proposal.id.to_address());

        transfer::share_object(proposal);
    }

    /// Structure that encodes the logic required to transfer an `AuthenticatedAsset`
    /// from one address to another. The transfer can be refused by the recipient.
    public struct TransferProposal has key {
        id: UID,
        asset_id: ID,
        sender_address: address,
        sender_cap_id: ID,
        recipient_address: address,
        recipient_cap_id: ID,
        done: bool,
    }

    public struct SenderCap has key {
        id: UID,
        transfer_id: ID,
    }

    public struct RecipientCap has key {
        id: UID,
        transfer_id: ID,
    }

    /// Accept the transfer of the asset.
    public fun accept<T: store>(
        self: &mut TransferProposal,
        cap: RecipientCap,
        asset: transfer::Receiving<AuthenticatedAsset<T>>,
    ) {
        assert!(self.recipient_cap_id == object::id(&cap), EInvalidRecipient);
        let mut asset = transfer::receive(&mut self.id, asset);
        assert!(self.asset_id == object::id(&asset), EInvalidAsset);

        asset.owner = self.recipient_address;
        transfer::transfer(asset, self.recipient_address);
        cap.delete();

        self.done = true;

        iota::event::emit(AssetTransferConcluded {
            proposal: self.id.to_inner(),
            asset: self.asset_id,
            sender: self.sender_address,
            recipient: self.recipient_address,
            concluded: true,
        })
    }

    /// The sender of the asset consumes the `TransferProposal` to either
    /// cancel it or to conclude it.
    public fun conclude_or_cancel<T: store>(
        mut proposal: TransferProposal,
        cap: SenderCap,
        asset: transfer::Receiving<AuthenticatedAsset<T>>,
    ) {
        assert!(proposal.sender_cap_id == object::id(&cap), EInvalidSender);
        if (!proposal.done) {
            let asset = transfer::receive(&mut proposal.id, asset);
            assert!(proposal.asset_id == object::id(&asset), EInvalidAsset);
            transfer::transfer(asset, proposal.sender_address);

            iota::event::emit(AssetTransferConcluded {
                proposal: proposal.id.to_inner(),
                asset: proposal.asset_id,
                sender: proposal.sender_address,
                recipient: proposal.recipient_address,
                concluded: false,
            })
        };

        delete_transfer(proposal);
        delete_sender_cap(cap);
    }

    public(package) fun delete_sender_cap(cap: SenderCap) {
        let SenderCap {
            id,
            ..,
        } = cap;
        object::delete(id);
    }

    public fun delete_recipient_cap(cap: RecipientCap) {
        let RecipientCap {
            id,
            ..,
        } = cap;
        object::delete(id);
    }

    public(package) fun delete_transfer(self: TransferProposal) {
        let TransferProposal {
            id,
            asset_id: _,
            sender_cap_id: _,
            recipient_cap_id: _,
            sender_address: _,
            recipient_address: _,
            done: _,
        } = self;
        object::delete(id);
    }
}

#[test_only]
module iota_identity::asset_tests {
    use iota::test_scenario;
    use iota_identity::asset::{
        Self,
        AuthenticatedAsset,
        EImmutable,
        ENonTransferable,
        ENonDeletable
    };

    const ALICE: address = @0x471c3;
    const BOB: address = @0xb0b;

    #[test, expected_failure(abort_code = EImmutable)]
    fun authenticated_asset_is_immutable_by_default() {
        // Alice creates a new asset with default a configuration.
        let mut scenario = test_scenario::begin(ALICE);
        asset::new<u32>(42, scenario.ctx());
        scenario.next_tx(ALICE);

        // Alice fetches her newly created asset and attempts to modify it.
        let mut asset = scenario.take_from_address<AuthenticatedAsset<u32>>(ALICE);
        *asset.borrow_mut() = 420;

        scenario.next_tx(ALICE);
        scenario.return_to_sender(asset);
        scenario.end();
    }

    #[test, expected_failure(abort_code = ENonTransferable)]
    fun authenticated_asset_is_non_transferable_by_default() {
        // Alice creates a new asset with default a configuration.
        let mut scenario = test_scenario::begin(ALICE);
        asset::new<u32>(42, scenario.ctx());
        scenario.next_tx(ALICE);

        // Alice fetches her newly created asset and attempts to send it to Bob.
        let asset = scenario.take_from_address<AuthenticatedAsset<u32>>(ALICE);
        asset.transfer(BOB, scenario.ctx());

        scenario.next_tx(ALICE);
        scenario.end();
    }

    #[test, expected_failure(abort_code = ENonDeletable)]
    fun authenticated_asset_is_non_deletable_by_default() {
        // Alice creates a new asset with default a configuration.
        let mut scenario = test_scenario::begin(ALICE);
        asset::new<u32>(42, scenario.ctx());
        scenario.next_tx(ALICE);

        // Alice fetches her newly created asset and attempts to delete it.
        let asset = scenario.take_from_address<AuthenticatedAsset<u32>>(ALICE);
        asset.delete();

        scenario.next_tx(ALICE);
        scenario.end();
    }
}
