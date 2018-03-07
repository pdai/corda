package net.corda.core.flows

import net.corda.core.contracts.StateRef
import net.corda.core.crypto.*
import net.corda.core.identity.Party
import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.serialize
import net.corda.core.transactions.CoreTransaction
import net.corda.core.transactions.SignedTransaction
import java.security.InvalidKeyException
import java.security.SignatureException

/**
 * A notarisation request specifies a list of states to consume and the id of the consuming transaction. Its primary
 * purpose is for notarisation traceability – a signature over the notarisation request, [NotarisationRequestSignature],
 * allows a notary to prove that a certain party requested the consumption of a particular state.
 *
 * While the signature must be retained, the notarisation request does not need to be transferred or stored anywhere - it
 * can be built from a [SignedTransaction] or a [CoreTransaction]. The notary can recompute it from the committed states index.
 *
 * In case there is a need to prove that a party spent a particular state, the notary will:
 * 1) Locate the consuming transaction id in the index, along with all other states consumed in the same transaction.
 * 2) Build a [NotarisationRequest].
 * 3) Locate the [NotarisationRequestSignature] for the transaction id. The signature will contain the signing public key.
 * 4) Demonstrate the signature verifies against the serialized request. The provided states are always sorted internally,
 *    to ensure the serialization does not get affected by the order.
 */
@CordaSerializable
class NotarisationRequest(statesToConsume: List<StateRef>, val transactionId: SecureHash) {
    companion object {
        /** Sorts in ascending order first by transaction hash, then by output index. */
        private val stateRefComparator = compareBy<StateRef>({ it.txhash }, { it.index })
    }

    private val _statesToConsumeSorted = statesToConsume.sortedWith(stateRefComparator)

    /** States this request specifies to be consumed. Sorted to ensure the serialized form does not get affected by the state order. */
    val statesToConsume: List<StateRef> get() = _statesToConsumeSorted // Getter required for AMQP serialization

    /** Verifies the signature against this notarisation request. Checks that the signature is issued by the right party. */
    fun verifySignature(requestSignature: NotarisationRequestSignature, intendedSigner: Party) {
        val signature = requestSignature.digitalSignature
        if (intendedSigner.owningKey != signature.by) {
            val errorMessage = "Expected a signature by ${intendedSigner.owningKey}, but received by ${signature.by}}"
            throw InternalNotaryException(NotaryError.RequestSignatureInvalid(IllegalArgumentException(errorMessage)))
        }
        // TODO: if requestSignature was generated over an old version of NotarisationRequest, we need to be able to
        // reserialize it in that version to get the exact same bytes. Modify the serialization logic once that's
        // available.
        val expectedSignedBytes = this.serialize().bytes
        verifyCorrectBytesSigned(signature, expectedSignedBytes)
    }

    private fun verifyCorrectBytesSigned(signature: DigitalSignature.WithKey, bytes: ByteArray) {
        try {
            signature.verify(bytes)
        } catch (e: Exception) {
            when (e) {
                is InvalidKeyException, is SignatureException -> {
                    val error = NotaryError.RequestSignatureInvalid(e)
                    throw InternalNotaryException(error)
                }
                else -> throw e
            }
        }
    }
}

/**
 * A wrapper around a digital signature used for notarisation requests.
 *
 * The [platformVersion] is required so the notary can verify the signature against the right version of serialized
 * bytes of the [NotarisationRequest]. Otherwise, the request may be rejected.
 */
@CordaSerializable
data class NotarisationRequestSignature(val digitalSignature: DigitalSignature.WithKey, val platformVersion: Int)

/**
 * Container for the transaction and notarisation request signature.
 * This is the payload that gets sent by a client to a notary service for committing the input states of the [transaction].
 */
@CordaSerializable
data class NotarisationPayload(val transaction: Any, val requestSignature: NotarisationRequestSignature) {
    init {
        require(transaction is SignedTransaction || transaction is CoreTransaction) {
            "Unsupported transaction type in the notarisation payload: ${transaction.javaClass.simpleName}"
        }
    }

    /**
     * A helper for automatically casting the underlying [transaction] payload to a [SignedTransaction].
     * Should only be used by validating notaries.
     */
    val signedTransaction get() = transaction as SignedTransaction
    /**
     * A helper for automatically casting the underlying [transaction] payload to a [CoreTransaction].
     * Should only be used by non-validating notaries.
     */
    val coreTransaction get() = transaction as CoreTransaction
}

/** Payload returned by the notary service flow to the client. */
@CordaSerializable
data class NotarisationResponse(val signatures: List<TransactionSignature>)