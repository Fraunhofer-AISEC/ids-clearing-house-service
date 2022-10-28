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

import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.IDSCP2_IDS_HEADER
import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.IDSCP_ID_HEADER
import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.IDSCP_PID_HEADER
import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.IDS_MESSAGE_HEADER
import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.IDS_PROTOCOL
import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.PROTO_IDSCP2
import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.TYPE_HEADER
import de.fhg.aisec.ids.idscp2.defaultdrivers.daps.aisecdaps.AisecDapsDriver
import de.fraunhofer.iais.eis.DynamicAttributeTokenBuilder
import de.fraunhofer.iais.eis.Message
import de.fraunhofer.iais.eis.RejectionMessageBuilder
import de.fraunhofer.iais.eis.TokenFormat
import org.apache.camel.Exchange
import org.apache.camel.Processor
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URI
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import javax.xml.datatype.DatatypeFactory

class ClearingHouseExceptionProcessor : Processor {
    override fun process(exchange: Exchange) {
        val egetIn = exchange.getIn()
        val headers = egetIn.headers

        if (LOG.isTraceEnabled) {
            LOG.trace("[ERR] ${ClearingHouseExceptionProcessor::class.java.simpleName}")
            for (header in headers.keys) {
                LOG.trace("Found header '{}':'{}'", header, headers[header])
            }
        }

        // Get DAPS token
        val dapsDriver = AisecDapsDriver(Configuration.createDapsConfig())
        val dapsToken = DynamicAttributeTokenBuilder()
            ._tokenFormat_(TokenFormat.JWT)
            ._tokenValue_(String(dapsDriver.token, StandardCharsets.UTF_8))
            .build()

        // If this property is null, most likely the routes are not defined correctly!
        // There is only a very small chance that the IDSCP2 Input Processor ran into
        // an exception before storing the originalRequest
        val originalRequest = exchange.getProperty(IDS_MESSAGE_HEADER, Message::class.java)

        val message = RejectionMessageBuilder()
            ._issued_(
                DatatypeFactory.newInstance().newXMLGregorianCalendar(LocalDateTime.now().toString())
            )
            ._modelVersion_(Configuration.infomodelVersion)
            ._issuerConnector_(URI(Configuration.issuerConnector))
            ._senderAgent_(URI(Configuration.senderAgent))
            ._correlationMessage_(originalRequest.id)
            ._recipientAgent_(listOf(originalRequest.senderAgent))
            ._recipientConnector_(listOf(originalRequest.issuerConnector))
            ._securityToken_(dapsToken).build()

        val caused = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Throwable::class.java)

        exchange.getIn().body = caused.message

        // remove original header before setting it anew. Does make a difference!
        egetIn.removeHeader(IDSCP2_IDS_HEADER)
        // set the IDS header
        when (headers[IDS_PROTOCOL] as String) {
            PROTO_IDSCP2 -> egetIn.setHeader(IDSCP2_IDS_HEADER, message)
            // PROTO_MULTIPART -> egetIn.setHeader(CAMEL_MULTIPART_HEADER, ClearingHouseOutputProcessor.SERIALIZER.serialize(responseMessage))
        }

        // clean up headers
        egetIn.removeHeader(IDS_PROTOCOL)
        egetIn.removeHeader(IDSCP_ID_HEADER)
        egetIn.removeHeader(IDSCP_PID_HEADER)
        egetIn.removeHeader(TYPE_HEADER)
    }

    companion object {
        private val LOG: Logger = LoggerFactory.getLogger(ClearingHouseExceptionProcessor::class.java)
    }
}
