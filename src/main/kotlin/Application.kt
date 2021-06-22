package community.flock.signal

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import java.security.Security

@SpringBootApplication
@EnableConfigurationProperties(SignalConfiguration::class)
class Application

fun main(args: Array<String>) {
    Security.addProvider(BouncyCastleProvider())
    runApplication<Application>(*args)
}
