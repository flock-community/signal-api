package community.flock.signal

import org.whispersystems.signalservice.api.push.TrustStore
import org.whispersystems.signalservice.internal.configuration.SignalCdnUrl
import org.whispersystems.signalservice.internal.configuration.SignalContactDiscoveryUrl
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration
import org.whispersystems.signalservice.internal.configuration.SignalServiceUrl
import java.io.InputStream

object Constants {
    enum class RegistrationType {
        TextMessage, PhoneCall
    }

    const val BATCH_SIZE = 100
    const val UNIDENTIFIED_SENDER_TRUST_ROOT = "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF"
    const val SIGNAL_URL = "https://textsecure-service.whispersystems.org"
    const val SIGNAL_CDN_URL = "https://cdn.signal.org"
    const val SIGNAL_CDN2_URL = "https://cdn2.signal.org"
    const val SIGNAL_CONTACT_DISCOVERY_URL = "https://api.directory.signal.org"
    const val SIGNAL_KEY_BACKUP_URL = "https://api.backup.signal.org"
    const val STORAGE_URL = "https://storage.signal.org"
    const val USER_AGENT = "BOT"
    const val SIGNAL_CAPTCHA_URL = "https://signalcaptchas.org/registration/generate.html"
    const val SIGNAL_CAPTCHA_SCHEME = "signalcaptcha://"

    val TRUST_STORE: TrustStore = object : TrustStore {
        override fun getKeyStoreInputStream(): InputStream {
            return javaClass.getResourceAsStream("/whisper.store")
        }

        override fun getKeyStorePassword(): String {
            return "whisper"
        }
    }

    val config = SignalServiceConfiguration(
            arrayOf(SignalServiceUrl(SIGNAL_URL, TRUST_STORE)),
            arrayOf(SignalCdnUrl(SIGNAL_CDN_URL, TRUST_STORE)),
            arrayOf(SignalContactDiscoveryUrl(SIGNAL_CONTACT_DISCOVERY_URL, TRUST_STORE))
    )
}