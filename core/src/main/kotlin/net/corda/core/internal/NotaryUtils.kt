package net.corda.core.internal

import net.corda.core.crypto.*
import net.corda.core.flows.NotarisationResponse
import net.corda.core.identity.Party
import net.corda.core.node.services.UniquenessProvider
import net.corda.core.serialization.serialize

/** Creates an empty signed UniquenessProvider.Conflict. Exists purely for backwards compatibility purposes. */
@Suppress("DEPRECATION")
internal val signedEmptyUniquenessConflict: SignedData<UniquenessProvider.Conflict> by lazy {
    val key = Crypto.generateKeyPair()
    val emptyConflict = UniquenessProvider.Conflict(emptyMap()).serialize()
    val signature = key.sign(emptyConflict)
    SignedData(emptyConflict, signature)
}

/**
 * Checks that there are sufficient signatures to satisfy the notary signing requirement and validates the signatures
 * against the given transaction id.
 */
fun NotarisationResponse.validateSignatures(txId: SecureHash, notary: Party) {
    val signingKeys = signatures.map { it.by }
    require(notary.owningKey.isFulfilledBy(signingKeys)) { "Insufficient signatures to fulfill the notary signing requirement for $notary" }
    signatures.forEach { it.verify(txId) }
}