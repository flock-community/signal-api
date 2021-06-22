package community.flock.signal

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding

@ConstructorBinding
@ConfigurationProperties(prefix = "signal")
data class SignalConfiguration(
        val username: String,
        val password: String,
)