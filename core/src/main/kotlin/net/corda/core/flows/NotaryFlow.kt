package net.corda.core.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.contracts.StateRef
import net.corda.core.contracts.TimeWindow
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.SignedData
import net.corda.core.crypto.TransactionSignature
import net.corda.core.crypto.isFulfilledBy
import net.corda.core.identity.Party
import net.corda.core.internal.FetchDataFlow
import net.corda.core.internal.generateSignature
import net.corda.core.internal.signedEmptyUniquenessConflict
import net.corda.core.internal.validateSignatures
import net.corda.core.node.services.NotaryService
import net.corda.core.node.services.TrustedAuthorityNotaryService
import net.corda.core.node.services.UniquenessProvider
import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.serialize
import net.corda.core.transactions.ContractUpgradeWireTransaction
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.WireTransaction
import net.corda.core.utilities.ProgressTracker
import net.corda.core.utilities.UntrustworthyData
import net.corda.core.utilities.unwrap
import java.time.Instant
import java.util.function.Predicate

class NotaryFlow {
    /**
     * A flow to be used by a party for obtaining signature(s) from a [NotaryService] ascertaining the transaction
     * time-window is correct and none of its inputs have been used in another completed transaction.
     *
     * In case of a single-node or Raft notary, the flow will return a single signature. For the BFT notary multiple
     * signatures will be returned – one from each replica that accepted the input state commit.
     *
     * @throws NotaryException in case the any of the inputs to the transaction have been consumed
     *                         by another transaction or the time-window is invalid.
     */
    @InitiatingFlow
    open class Client(private val stx: SignedTransaction,
                      override val progressTracker: ProgressTracker) : FlowLogic<List<TransactionSignature>>() {
        constructor(stx: SignedTransaction) : this(stx, tracker())

        companion object {
            object REQUESTING : ProgressTracker.Step("Requesting signature by Notary service")
            object VALIDATING : ProgressTracker.Step("Validating response from Notary service")

            fun tracker() = ProgressTracker(REQUESTING, VALIDATING)
        }

        @Suspendable
        @Throws(NotaryException::class)
        override fun call(): List<TransactionSignature> {
            val notaryParty = checkTransaction()
            progressTracker.currentStep = REQUESTING
            val response = notarise(notaryParty)
            progressTracker.currentStep = VALIDATING
            return validateResponse(response, notaryParty)
        }

        /**
         * Checks that the transaction specifies a valid notary, and verifies that it contains all required signatures
         * apart from the notary's.
         */
        protected fun checkTransaction(): Party {
            val notaryParty = stx.notary ?: throw IllegalStateException("Transaction does not specify a Notary")
            check(serviceHub.networkMapCache.isNotary(notaryParty)) { "$notaryParty is not a notary on the network" }
            check(serviceHub.loadStates(stx.inputs.toSet()).all { it.state.notary == notaryParty }) {
                "Input states must have the same Notary"
            }
            stx.resolveTransactionWithSignatures(serviceHub).verifySignaturesExcept(notaryParty.owningKey)
            return notaryParty
        }

        /** Notarises the transaction with the [notaryParty], obtains the notary's signature(s). */
        @Throws(NotaryException::class)
        @Suspendable
        protected fun notarise(notaryParty: Party): UntrustworthyData<NotarisationResponse> {
            return try {
                val session = initiateFlow(notaryParty)
                val requestSignature = NotarisationRequest(stx.inputs, stx.id).generateSignature(serviceHub)
                if (serviceHub.networkMapCache.isValidatingNotary(notaryParty)) {
                    sendAndReceiveValidating(session, requestSignature)
                } else {
                    sendAndReceiveNonValidating(notaryParty, session, requestSignature)
                }
            } catch (e: NotaryException) {
                validateException(e, notaryParty)
                throw e
            }
        }

        @Suspendable
        private fun sendAndReceiveValidating(session: FlowSession, signature: NotarisationRequestSignature): UntrustworthyData<NotarisationResponse> {
            val payload = NotarisationPayload(stx, signature)
            subFlow(NotarySendTransactionFlow(session, payload))
            return session.receive()
        }

        @Suspendable
        private fun sendAndReceiveNonValidating(notaryParty: Party, session: FlowSession, signature: NotarisationRequestSignature): UntrustworthyData<NotarisationResponse> {
            val ctx = stx.coreTransaction
            val tx = when (ctx) {
                is ContractUpgradeWireTransaction -> ctx.buildFilteredTransaction()
                is WireTransaction -> ctx.buildFilteredTransaction(Predicate { it is StateRef || it is TimeWindow || it == notaryParty })
                else -> ctx
            }
            return session.sendAndReceiveWithRetry(NotarisationPayload(tx, signature))
        }

        private fun validateException(e: NotaryException, notary: Party) {
            val signingKeys = e.signedErrorResponses.map { it.sig.by }
            require(notary.owningKey.isFulfilledBy(signingKeys)) {
                "Insufficient signatures to fulfill the notary signing requirement for $notary"
            }
            val errors = e.signedErrorResponses.map { it.verified() }
            // TODO: relax this requirement to tolerate malicious nodes
            // TODO: need to perform a deep comparison
            require(errors.all { it::class == e.error::class}) {
                "Errors reported by notary cluster members no not match"
            }
        }

        /** Checks that the notary's signature(s) is/are valid. */
        protected fun validateResponse(response: UntrustworthyData<NotarisationResponse>, notaryParty: Party): List<TransactionSignature> {
            return response.unwrap {
                it.validateSignatures(stx.id, notaryParty)
                it.signatures
            }
        }

        /**
         * The [NotarySendTransactionFlow] flow is similar to [SendTransactionFlow], but uses [NotarisationPayload] as the
         * initial message, and retries message delivery.
         */
        private class NotarySendTransactionFlow(otherSide: FlowSession, payload: NotarisationPayload) : DataVendingFlow(otherSide, payload) {
            @Suspendable
            override fun sendPayloadAndReceiveDataRequest(otherSideSession: FlowSession, payload: Any): UntrustworthyData<FetchDataFlow.Request> {
                return otherSideSession.sendAndReceiveWithRetry(payload)
            }
        }
    }

    /**
     * A flow run by a notary service that handles notarisation requests.
     *
     * It checks that the time-window command is valid (if present) and commits the input state, or returns a conflict
     * if any of the input states have been previously committed.
     *
     * Additional transaction validation logic can be added when implementing [receiveAndVerifyTx].
     */
    // See AbstractStateReplacementFlow.Acceptor for why it's Void?
    abstract class Service(val otherSideSession: FlowSession, val service: TrustedAuthorityNotaryService) : FlowLogic<Void?>() {

        @Suspendable
        override fun call(): Void? {
            check(serviceHub.myInfo.legalIdentities.any { serviceHub.networkMapCache.isNotary(it) }) {
                "We are not a notary on the network"
            }
            try {
                val (id, inputs, timeWindow, notary) = receiveAndVerifyTx()
                checkNotary(notary)
                service.validateTimeWindow(timeWindow)
                service.commitInputStates(inputs, id, otherSideSession.counterparty)
                signTransactionAndSendResponse(id)
            } catch (e: InternalNotaryException) {
                signErrorAndThrow(e.error)
            }
            return null
        }

        /**
         * Implement custom logic to receive the transaction to notarise, and perform verification based on validity and
         * privacy requirements.
         */
        @Suspendable
        abstract fun receiveAndVerifyTx(): TransactionParts

        /** Check if transaction is intended to be signed by this notary. */
        @Suspendable
        protected fun checkNotary(notary: Party?) {
            if (notary?.owningKey != service.notaryIdentityKey) {
                throw InternalNotaryException(NotaryError.WrongNotary)
            }
        }

        @Suspendable
        private fun signTransactionAndSendResponse(txId: SecureHash) {
            val signature = service.sign(txId)
            otherSideSession.send(NotarisationResponse(listOf(signature)))
        }

        @Suspendable
        private fun signErrorAndThrow(error: NotaryError) {
            val serializedError = error.serialize()
            val signedError = SignedData(serializedError, service.sign(serializedError.bytes))
            throw NotaryException(error, signedError)
        }
    }
}

/**
 * The minimum amount of information needed to notarise a transaction. Note that this does not include
 * any sensitive transaction details.
 */
data class TransactionParts(val id: SecureHash, val inputs: List<StateRef>, val timestamp: TimeWindow?, val notary: Party?)

/**
 * Exception thrown by the notary service if any issues are encountered while trying to commit a transaction. The
 * underlying [error] specifies the cause of failure.
 */
class NotaryException(
        val error: NotaryError,
        /**
         * Original signed responses from the notary cluster. This can be used as proof to counterparties for a particular
         * notary response.
         *
         * For crash fault-tolerant notaries, the list will only contain one element, since we trust all replicas.
         * For BFT case, it will contain signed error responses from the majority of the cluster.
         */
        val signedErrorResponses: List<SignedData<NotaryError>>
) : FlowException("Unable to notarise: $error") {
    constructor(error: NotaryError, signedErrorResponse: SignedData<NotaryError>) : this(error, listOf(signedErrorResponse))
}

/** Exception internal to the notary service. Does not get exposed to CorDapps and flows calling [NotaryFlow.Client]. */
class InternalNotaryException(val error: NotaryError) : FlowException("Unable to notarise: $error")

/** Specifies the cause for notarisation request failure. */
@CordaSerializable
sealed class NotaryError {
    /** Occurs when one or more input states of transaction with [txId] have already been consumed by another transaction. */
    data class Conflict(
            val txId: SecureHash,
            val doubleSpendConflict: DoubleSpendConflict
    ) : NotaryError() {
        override fun toString() = "One or more input states for transaction $txId have been used in another transaction"

        @Deprecated("No longer populated due to potential privacy issues", ReplaceWith("Use signedConflict property instead"))
        @Suppress("DEPRECATION")
        val conflict: SignedData<UniquenessProvider.Conflict>
            get() = signedEmptyUniquenessConflict
    }

    /** Occurs when time specified in the [TimeWindow] command is outside the allowed tolerance. */
    data class TimeWindowInvalid(val currentTime: Instant, val txTimeWindow: TimeWindow) : NotaryError() {
        override fun toString() = "Current time $currentTime is outside the time bounds specified by the transaction: $txTimeWindow"

        companion object {
            @JvmField
            @Deprecated("Here only for binary compatibility purposes, do not use.")
            val INSTANCE = TimeWindowInvalid(Instant.EPOCH, TimeWindow.fromOnly(Instant.EPOCH))
        }
    }

    /** Occurs when the provided transaction fails to verify. */
    data class TransactionInvalid(val cause: Throwable) : NotaryError() {
        override fun toString() = cause.toString()
    }

    /** Occurs when the transaction sent for notarisation is assigned to a different notary identity. */
    object WrongNotary : NotaryError()

    /** Occurs when the notarisation request signature does not verify for the provided transaction. */
    data class RequestSignatureInvalid(val cause: Throwable) : NotaryError() {
        override fun toString() = "Request signature invalid: $cause"
    }

    /** Occurs when the notary service encounters an unexpected issue or becomes temporarily unavailable. */
    data class General(val cause: Throwable) : NotaryError() {
        override fun toString() = cause.toString()
    }
}

/** Contains information about the cause of the double-spend conflict for each of the conflicting input states. */
@CordaSerializable
data class DoubleSpendConflict(val stateConflicts: Map<StateRef, Cause>) {
    @CordaSerializable
    data class Cause(
            /**
             * Hash of the consuming transaction id.
             *
             * Note that this is NOT the transaction id itself – revealing it could lead to privacy leaks.
             */
            val transactionIdHash: SecureHash
    )
}