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

import de.fhg.aisec.ids.clearinghouse.ClearingHouseConstants.*
import de.fraunhofer.iais.eis.Message
import de.fraunhofer.iais.eis.QueryMessage
import de.fraunhofer.iais.eis.RequestMessage
import de.fraunhofer.iais.eis.ids.jsonld.Serializer
import org.apache.camel.Exchange
import org.apache.camel.Processor
import org.apache.http.entity.ContentType
import org.slf4j.LoggerFactory
import java.io.IOException
import java.io.InputStream

/**
 * This processor parses the previously extracted IDS header and creates an InfoModel class.
 * It also checks that the payload type matches the expected payload type and prepares
 * the body of the message for the Clearing House Service API
 */
class ClearingHouseInfomodelParsingProcessor : Processor {
    override fun process(exchange: Exchange) {
        val egetIn = exchange.getIn()
        val headers = egetIn.headers

        if (LOG.isTraceEnabled) {
            LOG.trace("[IN] ${ClearingHouseInfomodelParsingProcessor::class.java.simpleName}")
            for (header in headers.keys) {
                LOG.trace("Found header '{}':'{}'", header, headers[header])
            }
        }

        exchange.getIn().setHeader(IDS_PROTOCOL, PROTO_MULTIPART)

        // parse IDS header
        val idsHeader: Message?
        try {
            idsHeader = SERIALIZER.deserialize(headers[CAMEL_MULTIPART_HEADER] as String?,
                Message::class.java)
        }
        catch (exception: IOException){
            LOG.warn("Invalid Infomodel Message!")
            throw IOException("Invalid InfoModel Message!")
        }

        // Prepare compound message for Clearing House Service API
        val contentTypeHeader = (headers[TYPE_HEADER] as String?)
        val converted = ClearingHouseMessage(idsHeader, contentTypeHeader, (exchange.message.body as InputStream).readBytes())

        if (LOG.isTraceEnabled) {
            LOG.trace("Received payload: {}", converted.payload)
        }

        // Input validation: check that payload type of create pid message is application/json
        if (converted.header is RequestMessage && converted.header !is QueryMessage) {
            val expectedContentType = ContentType.create("application/json")
            if (converted.payload != null && converted.payload!!.isNotEmpty() && expectedContentType.mimeType != converted.payloadType) {
                LOG.warn("Expected application/json, got {}", converted.payloadType)
                throw IllegalArgumentException("Expected content-type application/json")
            }
        }

        // Store ids header for response processor
        exchange.setProperty(IDS_MESSAGE_HEADER, idsHeader)

        // Set Content-Type from payload part of compound message and populate body with new payload
        exchange.getIn().setHeader(TYPE_HEADER, TYPE_JSON)
        exchange.getIn().body = converted.toJson()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(ClearingHouseInfomodelParsingProcessor::class.java)
        private val SERIALIZER = Serializer()
    }
}
