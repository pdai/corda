package net.corda.core.internal

import net.corda.core.CordaException
import net.corda.core.crypto.Crypto
import net.corda.core.crypto.SignedData
import net.corda.core.crypto.sign
import net.corda.core.flows.DoubleSpendConflict
import net.corda.core.node.services.UniquenessProvider
import net.corda.core.serialization.serialize

/** Creates an empty signed UniquenessProvider.Conflict. Exists purely for backwards compatibility purposes. */
@Suppress("DEPRECATION")
internal val signedEmptyUniquenessConflict: SignedData<UniquenessProvider.Conflict> by lazy {
    val key = Crypto.generateKeyPair()
    val emptyConflict = UniquenessProvider.Conflict(emptyMap()).serialize()
    val signature = key.sign(emptyConflict.serialize())
    SignedData(emptyConflict, signature)
}

/** An internal exception used for propagating the error from the notary service to the notary flow. */
class DoubleSpendException(val error: DoubleSpendConflict) : CordaException(DoubleSpendException::class.java.name)