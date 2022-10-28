/*-
 * ========================LICENSE_START=================================
 * camel-multipart-processor
 * %%
 * Copyright (C) 2019 Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */
package de.fhg.aisec.ids.clearinghouse

import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.AUTH_HEADER
import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.BEARER
import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.IDS_MESSAGE_HEADER
import de.fhg.aisec.ids.idscp2.defaultdrivers.daps.aisecdaps.AisecDapsDriver
import de.fraunhofer.iais.eis.Message
import org.apache.camel.Exchange
import org.apache.camel.Processor
import org.eclipse.jetty.server.Request
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession

/**
 * This processor validates the JWT token in the IDS header
 */
class TokenValidationProcessor : Processor {
    override fun process(exchange: Exchange) {
        val eIn = exchange.getIn()
        val headers = eIn.headers

        if (LOG.isTraceEnabled) {
            LOG.trace("[IN] ${TokenValidationProcessor::class.java.simpleName}")
            for (header in headers.keys) {
                LOG.trace("Found header '{}':'{}'", header, headers[header])
            }
        }

        val request = exchange.message.headers["CamelHttpServletRequest"] as Request
        val sslSession = request.getAttribute("org.eclipse.jetty.servlet.request.ssl_session") as SSLSession
        val peerCertificates: Array<Certificate>
        try {
            peerCertificates = sslSession.peerCertificates
            if (LOG.isDebugEnabled) {
                LOG.debug("Peer Certificates: {}", peerCertificates)
            }
        } catch (e: SSLPeerUnverifiedException) {
            LOG.error("Client didn't provide a certificate!")
            throw e
        }

        val idsHeader = exchange.getProperty(IDS_MESSAGE_HEADER, Message::class.java)
            ?: throw RuntimeException("No IDS header provided!")
        val dat = idsHeader.securityToken?.tokenValue ?: throw RuntimeException("No DAT provided!")
        try {
            DAPS_DRIVER.verifyToken(dat.toByteArray(), peerCertificates[0] as X509Certificate)
        } catch (e: Exception) {
            throw SecurityException("Access Token did not match presented certificate!", e)
        }

        // Extract DAT from IDS header and assemble auth header
        val token = BEARER + dat
        exchange.getIn().setHeader(AUTH_HEADER, token)
    }

    companion object {
        val LOG: Logger = LoggerFactory.getLogger(TokenValidationProcessor::class.java)
        val DAPS_DRIVER = AisecDapsDriver(Configuration.createDapsConfig())
    }
}
