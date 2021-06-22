package community.flock.signal

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.core.io.WritableResource
import org.whispersystems.libsignal.IdentityKey
import org.whispersystems.libsignal.IdentityKeyPair
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.state.IdentityKeyStore
import org.whispersystems.libsignal.state.PreKeyRecord
import org.whispersystems.libsignal.state.SessionRecord
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.libsignal.state.SignedPreKeyRecord
import org.whispersystems.util.Base64


var objectMapper = jacksonObjectMapper()

class PersistentStore(val model: Model) : SignalProtocolStore {

    companion object {
        fun load(resource: WritableResource): Model = try {
            objectMapper.readValue(resource.inputStream, Model::class.java)
        } catch (ex: Exception) {
            print(ex)
            error("Cannot read model")
        }

        fun save(resource: WritableResource, model: Model) = try {
                objectMapper
                        .writerWithDefaultPrettyPrinter()
                        .writeValue(resource.outputStream, model)
        } catch (ex: Exception) {
            error("Could not write file")
        }
    }

    override fun getIdentityKeyPair(): IdentityKeyPair {
        return IdentityKeyPair(Base64.decode(model.identityKeyPair))
    }

    override fun getLocalRegistrationId(): Int {
        return model.registrationId ?: error("No registrationId")
    }

    override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): Boolean {
        val existing = model.trustedKeys[address.encodeBase64()]?.decodeIdentityKey()
        return if (identityKey != existing) {
            model.trustedKeys[address.encodeBase64()] = identityKey.encodeBase64()
            true
        } else {
            false
        }
    }

    override fun isTrustedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean {
        val trusted = model.trustedKeys[address.encodeBase64()]?.decodeIdentityKey()
        return trusted == null || trusted == identityKey
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? {
        return model.trustedKeys[address.encodeBase64()]?.decodeIdentityKey()
    }

    override fun loadPreKey(preKey: Int): PreKeyRecord? {
        return model.preKeys[preKey]
                ?.decodePreKeyRecord()
                ?: error("preKey not found")
    }

    override fun storePreKey(preKey: Int, preKeyRecord: PreKeyRecord) {
        model.preKeys[preKey] = preKeyRecord.encodeBase64()
    }

    override fun containsPreKey(preKey: Int): Boolean {
        return model.preKeys.containsKey(preKey)
    }

    override fun removePreKey(preKey: Int) {
        model.preKeys.remove(preKey)
    }

    override fun loadSession(signalProtocolAddress: SignalProtocolAddress): SessionRecord? {
        return if (containsSession(signalProtocolAddress))
            model.sessions[signalProtocolAddress.encodeBase64()]?.decodeSessionRecord()
        else
            SessionRecord()
    }

    @Synchronized
    override fun getSubDeviceSessions(name: String): List<Int> {
        return model.sessions.keys
                .map { it.decodeSignalProtocolAddress() }
                .filter { it.deviceId != 1 && it.name == name }
                .map { it.deviceId }
    }

    override fun storeSession(signalProtocolAddress: SignalProtocolAddress, sessionRecord: SessionRecord) {
        model.sessions[signalProtocolAddress.encodeBase64()] = sessionRecord.encodeBase64()
    }

    override fun containsSession(signalProtocolAddress: SignalProtocolAddress): Boolean {
        return model.sessions.contains(signalProtocolAddress.encodeBase64())
    }

    override fun deleteSession(signalProtocolAddress: SignalProtocolAddress) {
        model.sessions.remove(signalProtocolAddress.encodeBase64())
    }

    override fun deleteAllSessions(name: String) {
        model.sessions.keys
                .map { it.decodeSignalProtocolAddress() }
                .filter { it.deviceId != 1 && it.name == name }
                .forEach { model.sessions.remove(it.encodeBase64()) }
    }

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord? {
        return model.signedPreKeys[signedPreKeyId]
                ?.decodeSignedPreKeyRecord()
                ?: error("signedPreKey not found")
    }

    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> {
        return model.signedPreKeys.values
                .map { it.decodeSignedPreKeyRecord() }
    }

    override fun storeSignedPreKey(signedPreKeyId: Int, signedPreKeyRecord: SignedPreKeyRecord) {
        model.signedPreKeys[signedPreKeyId] = signedPreKeyRecord.encodeBase64()
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean {
        return model.signedPreKeys.containsKey(signedPreKeyId)
    }

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        model.signedPreKeys.remove(signedPreKeyId)
    }

    private fun String.decodeIdentityKey() = StoreUtil.decodeIdentityKey(this)
    private fun String.decodePreKeyRecord() = StoreUtil.decodePreKeyRecord(this)
    private fun String.decodeSessionRecord() = StoreUtil.decodeSessionRecord(this)
    private fun String.decodeSignalProtocolAddress() = StoreUtil.decodeSignalProtocolAddress(this)
    private fun String.decodeSignedPreKeyRecord() = StoreUtil.decodeSignedPreKeyRecord(this)

    private fun SignalProtocolAddress.encodeBase64() = StoreUtil.encodeSignalProtocolAddress(this)
    private fun PreKeyRecord.encodeBase64() = StoreUtil.encodePreKeyRecord(this)
    private fun IdentityKey.encodeBase64() = StoreUtil.encodeIdentityKey(this)
    private fun SessionRecord.encodeBase64() = StoreUtil.encodeSessionRecord(this)
    private fun SignedPreKeyRecord.encodeBase64() = StoreUtil.encodeSignedPreKeyRecord(this)

}

private object StoreUtil {

    private fun String.decodeBase64() = Base64.decode(this)
    private fun String.encodeBase64() = Base64.encodeBytes(this.encodeToByteArray())
    private fun ByteArray.encodeBase64() = Base64.encodeBytes(this)

    fun encodeSignalProtocolAddress(signalProtocolAddress: SignalProtocolAddress): String {
        return "${signalProtocolAddress.name.encodeBase64()}.${signalProtocolAddress.deviceId}"
    }

    fun decodeSignalProtocolAddress(signalProtocolAddress: String): SignalProtocolAddress {
        val (name, deviceId) = signalProtocolAddress.split(".")
        return SignalProtocolAddress(name.decodeBase64().decodeToString(), deviceId.toInt())
    }

    fun encodeIdentityKey(identityKey: IdentityKey): String {
        return identityKey.serialize().encodeBase64()
    }

    fun decodeIdentityKey(identityKey: String): IdentityKey {
        return IdentityKey(identityKey.decodeBase64(), 0)
    }

    fun encodePreKeyRecord(preKeyRecord: PreKeyRecord): String {
        return preKeyRecord.serialize().encodeBase64()
    }

    fun decodePreKeyRecord(preKeyRecord: String): PreKeyRecord {
        return PreKeyRecord(preKeyRecord.decodeBase64())
    }

    fun encodeSessionRecord(sessionRecord: SessionRecord): String {
        return sessionRecord.serialize().encodeBase64()
    }

    fun decodeSessionRecord(sessionRecord: String): SessionRecord {
        return SessionRecord(sessionRecord.decodeBase64())
    }

    fun encodeSignedPreKeyRecord(signedPreKeyRecord: SignedPreKeyRecord): String {
        return signedPreKeyRecord.serialize().encodeBase64()
    }

    fun decodeSignedPreKeyRecord(signedPreKeyRecord: String): SignedPreKeyRecord {
        return SignedPreKeyRecord(signedPreKeyRecord.decodeBase64())
    }
}