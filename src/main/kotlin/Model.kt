package community.flock.signal

import java.util.UUID

data class Model(
        val uuid: UUID,
        val registrationId:Int,
        val identityKeyPair:String,
        val trustedKeys: MutableMap<String, String> = mutableMapOf(),
        val preKeys: MutableMap<Int, String> = mutableMapOf(),
        val signedPreKeys: MutableMap<Int, String> = mutableMapOf(),
        val sessions: MutableMap<String, String> = mutableMapOf(),
)
