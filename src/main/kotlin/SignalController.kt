package community.flock.signal

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController("/api")
class Controllers(
       private val signalSignalService: SignalService
) {

    @PostMapping("/send")
    fun send(@RequestBody message: Message) {
        signalSignalService.send(message)
    }

    @GetMapping("/receive")
    fun receive(): List<Message> {
        return signalSignalService.receive()
    }

    @GetMapping("/refresh")
    fun refresh() {
        return signalSignalService.refresh()
    }

}