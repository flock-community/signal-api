package community.flock.signal

import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.springframework.context.ApplicationContext
import org.springframework.core.io.WritableResource
import org.whispersystems.libsignal.ecc.Curve
import org.whispersystems.libsignal.state.PreKeyRecord
import org.whispersystems.libsignal.util.KeyHelper
import org.whispersystems.libsignal.util.Medium
import org.whispersystems.libsignal.util.guava.Optional
import org.whispersystems.signalservice.api.SignalServiceAccountManager
import org.whispersystems.signalservice.api.SignalServiceMessageReceiver
import org.whispersystems.signalservice.api.SignalServiceMessageSender
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccess
import org.whispersystems.signalservice.api.messages.SignalServiceContent
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope
import org.whispersystems.signalservice.api.push.SignalServiceAddress
import org.whispersystems.signalservice.api.util.UptimeSleepTimer
import org.whispersystems.signalservice.api.websocket.ConnectivityListener
import org.whispersystems.signalservice.internal.util.Util
import org.whispersystems.util.Base64
import java.security.SecureRandom
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.function.Consumer

@org.springframework.stereotype.Service
class SignalService(
        appContext: ApplicationContext,
        private val signalConfiguration: SignalConfiguration,
) {

    private val resource = appContext.getResource("gs://community-flock-office-signal/protocol/+31638862530.json") as WritableResource
    private val model = PersistentStore.load(resource)
    private val protocolStore = PersistentStore(model)
    private val accountManager = SignalServiceAccountManager(Constants.config, model?.uuid, signalConfiguration.username, signalConfiguration.password, Constants.USER_AGENT);

    fun genKeyPair() {
        val identityKeyPair = KeyHelper.generateIdentityKeyPair()
        println("identityKeyPair: ${Base64.encodeBytes(identityKeyPair.serialize())}")
    }

    fun register(type: Constants.RegistrationType, captcha: String) {
        println("Sending verification code to " + signalConfiguration.username + ".");

        val captchaToken = if (captcha != null && captcha.length > 0 && captcha.startsWith(Constants.SIGNAL_CAPTCHA_SCHEME)) {
            captcha.substring(Constants.SIGNAL_CAPTCHA_SCHEME.length)
        } else {
            throw error("Unknown captcha response supplied, please use raw response from ${Constants.SIGNAL_CAPTCHA_URL}, including the following prefix: ${Constants.SIGNAL_CAPTCHA_SCHEME}")
        }

        if (type === Constants.RegistrationType.PhoneCall) {
            accountManager.requestVoiceVerificationCode(Locale.getDefault(), Optional.fromNullable(captchaToken), Optional.absent())
        } else {
            accountManager.requestSmsVerificationCode(false, Optional.fromNullable(captchaToken), Optional.absent())
        }

    }

    fun verify(registrationId: Int, verificationCode: String): UUID {
        println("Verifying user ${signalConfiguration.username} with code $verificationCode...")
        val code = verificationCode.replace("-", "")
        val profileKey: ByteArray = Util.getSecretBytes(32)
        val unidentifiedAccessKey = UnidentifiedAccess.deriveAccessKeyFrom(profileKey)
        return accountManager.verifyAccountWithCode(code, null, registrationId, true, signalConfiguration.password, unidentifiedAccessKey, false);
    }

    fun refresh() {
        val initialPreKeyId: Int = SecureRandom().nextInt(Medium.MAX_VALUE)
        val records = KeyHelper.generatePreKeys(initialPreKeyId, Constants.BATCH_SIZE)
        records.forEach(Consumer { v: PreKeyRecord -> protocolStore.storePreKey(v.id, v) })
        val signedPreKey = KeyHelper.generateSignedPreKey(protocolStore.identityKeyPair, initialPreKeyId)
        protocolStore.storeSignedPreKey(signedPreKey.id, signedPreKey)
        accountManager.setPreKeys(protocolStore.identityKeyPair.publicKey, signedPreKey, records)
        PersistentStore.save(resource, model)
    }

    fun receive(): Optional<Message> {
        val messageReceiver = SignalServiceMessageReceiver(Constants.config, accountManager.ownUuid, signalConfiguration.username, signalConfiguration.password, null, Constants.USER_AGENT, PipeConnectivityListener(), UptimeSleepTimer())
        val messagePipe = messageReceiver.createMessagePipe()

        val validator = CertificateValidator(Curve.decodePoint(Base64.decode(Constants.UNIDENTIFIED_SENDER_TRUST_ROOT), 0));
        val cipher = SignalServiceCipher(SignalServiceAddress(accountManager.ownUuid, signalConfiguration.username), protocolStore, validator)

        try {
            val envelope: SignalServiceEnvelope = messagePipe.read(5, TimeUnit.SECONDS)
            val message: SignalServiceContent = cipher.decrypt(envelope)
            return if (message.dataMessage.isPresent) {
                if (message.dataMessage.get().body.isPresent) {
                    val body = message.dataMessage.get().body.get()
                    Optional.of(Message(
                            number = message.sender.number.get(),
                            text = body
                    ))
                } else {
                    Optional.absent()
                }
            } else {
                Optional.absent()
            }
        } catch (ex: Exception) {
            println(ex)
            return Optional.absent()
        } finally {
            messagePipe.shutdown()
            PersistentStore.save(resource, model)
        }
    }

    fun send(message: Message) {
        try {
            val messageSender = SignalServiceMessageSender(Constants.config, accountManager.ownUuid, signalConfiguration.username, signalConfiguration.password, protocolStore, Constants.USER_AGENT, false, Optional.absent(), Optional.absent(), Optional.absent())
            val sender = SignalServiceAddress(Optional.absent(), Optional.fromNullable(message.number))
            val responseData = SignalServiceDataMessage.newBuilder().withBody(message.text).build()
            messageSender.sendMessage(sender, Optional.absent(), responseData)
        } finally {
            PersistentStore.save(resource, model)
        }
    }
}

private class PipeConnectivityListener : ConnectivityListener {
    override fun onConnected() {
        println("Message pipe connected.")
    }

    override fun onConnecting() {
        println("Message pipe connecting...")
    }

    override fun onDisconnected() {
        println("Message pipe disconnected.")
    }

    override fun onAuthenticationFailure() {
        println("Message pipe failure!")
    }
}
