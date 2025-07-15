import { CoreDID, CoreDocument, IotaDID, IotaDocument, IToCoreDID, IToCoreDocument } from "~identity_wasm";

type GetCoreDocument = (arg: IToCoreDocument) => CoreDocument;
type MaybeGetIotaDocument = (arg: IToCoreDocument) => IotaDocument | void;
type GetCoreDidClone = (arg: IToCoreDID) => CoreDID;

declare global {
    var _getCoreDocumentInternal: GetCoreDocument;
    var _maybeGetIotaDocumentInternal: MaybeGetIotaDocument;
    var _getCoreDidCloneInternal: GetCoreDidClone;
}

function _getCoreDocumentInternal(arg: IToCoreDocument): CoreDocument {
    if (arg instanceof CoreDocument) {
        return arg._shallowCloneInternal();
    } else {
        return arg.toCoreDocument()._shallowCloneInternal();
    }
}

function _maybeGetIotaDocumentInternal(arg: IToCoreDocument): IotaDocument | void {
    if (arg instanceof IotaDocument) {
        return arg._shallowCloneInternal();
    } else {
        return;
    }
}

function _getCoreDidCloneInternal(arg: IToCoreDID): CoreDID {
    if (arg instanceof IotaDID || arg instanceof CoreDID) {
        return arg.toCoreDid();
    } else {
        // Pass deep clone to avoid nulling out pointer.
        return arg.toCoreDid().clone();
    }
}

globalThis._getCoreDocumentInternal = _getCoreDocumentInternal;

globalThis._maybeGetIotaDocumentInternal = _maybeGetIotaDocumentInternal;

globalThis._getCoreDidCloneInternal = _getCoreDidCloneInternal;
