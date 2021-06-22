package community.flock.signal

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class SignalFilter(
        @Value("\${security.token}") private val token: String
) : Filter {

    override fun doFilter(request: ServletRequest, response: ServletResponse, filterchain: FilterChain) {
        val httpServletRequest = request as HttpServletRequest
        val response = response as HttpServletResponse
        val auth = httpServletRequest.getHeader("Authorization")
        if (auth == "TOKEN $token") {
            filterchain.doFilter(request, response);
        } else {
            response.sendError(401, "Invalid Authorization code")
        }
    }

}