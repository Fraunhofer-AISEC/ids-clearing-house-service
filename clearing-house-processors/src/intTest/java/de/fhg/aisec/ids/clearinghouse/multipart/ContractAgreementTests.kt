package de.fhg.aisec.ids.clearinghouse.multipart

import de.fhg.aisec.ids.clearinghouse.ChJwt
import de.fhg.aisec.ids.clearinghouse.Utility
import de.fhg.aisec.ids.clearinghouse.Utility.Companion.formatId
import de.fhg.aisec.ids.clearinghouse.multipart.CreatePidTests.Companion.succCreatePid
import de.fhg.aisec.ids.clearinghouse.multipart.MultipartEndpointTest.Companion.client
import de.fhg.aisec.ids.clearinghouse.multipart.MultipartEndpointTest.Companion.otherClient
import de.fraunhofer.iais.eis.MessageProcessedNotificationMessage
import de.fraunhofer.iais.eis.RejectionMessage
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import okhttp3.MultipartReader
import org.junit.Assert
import org.junit.jupiter.api.Test

class ContractAgreementTests {
    @Test
    fun contractMessage1(){
        val pid = formatId("mp-cnt1")
        val payload = buildJsonObject {
            put("data", NEGOTIATION_JWT)
        }

        // test: Logging a contract
        succContractMessage(pid, payload.toString())
    }


    companion object{
        private val NEGOTIATION_JWT = "eyJhbGciOiJQUzUxMiIsImtpZCI6IlFyYS8vMjlGcnhiajVoaDVBemVmK0czNlNlaU9tOXE3czgrdzh1R0xEMjgifQ.eyJpZCI6IjEyMyIsInRpbWVzdGFtcCI6MTY4NjkyODA2NSwicGF5bG9hZCI6IlRoaXMgaXMgdGhlIGNvbnRyYWN0IiwiY2xpZW50X2lkIjoiRnJvbSB0aGlzIGNsaWVudCIsImNsZWFyaW5nX2hvdXNlX3ZlcnNpb24iOiIwLjE3Iiwib3duZXJzIjpbXX0.RiI8fzboKnU2Mnk3FQWlpc90-W6NYv22eXJArFm2QdmwIfdrxMB96V7DvbJrbJ77coVfG9byZlF9ggq3tow2NJnj-W-w2TX8rmojkjbRLgpaaSoZLYksMPRnICr41RGefEwRoq7c80Ny_qWNwppkryf2-feDkWGGw2VvClxPMlTm1xLgcOOs29taVDJsfljo8RGwjYhYqHau1Vxt9avsyEVY1mw9W84FuO1O1kxxgqzZvUoJCXeo_Oa639l3NlYiYdTr6zqWAvcISfbj2G4P9QZp951Krb5h7NW3ozd7rlCs4FEkP-Rp58iP-76bn7zodDDZjC_5LdS8yJrrEpq4hUdLHqSaalZoIs-lxr4xdifkJz1GqBuQm48T5uxWde2graYKmmWaWVJorw7327voF6DByrXQgT6QVKSaQVaahg_P1cexdIFcUqPKy4S49U5WaVPYM21RNkPMOqvR_U18TOoxkpBnXdL36v-Vv8_K65eJ5j41QUUsTwOc_ygBb-qleQ_i8UwAkqyz5EHeERfI1qSrntz62S3Ki6slfYBFcoCuh94CnuGjAuRN001Q0E5I0qgw8G3PZ5Xwy4vApzwEKqhS-iurdQ14Kc24fWq9SebPHG-FRdimijGzXBW3wd5jiSSu-ck8A5LJ7mECEzTt-tYl2mtYHJ0qIx4jSajIB5g";


        fun failEarlyContractMessage(pid: String, payload: String, code: Int){
            val call = client.newCall(MultipartClient.contractMessage(pid, payload, client=2))
            val response = call.execute()
            // check http status code and message
            Assert.assertEquals("Unexpected http status code!", code, response.code)
            Assert.assertEquals("Unexpected message", "Unauthorized", response.message)
        }

        fun failContractMessage(pid: String, payload: String, code: Int){
            val call = client.newCall(MultipartClient.contractMessage(pid, payload))
            val response = call.execute()
            // check http status code
            Assert.assertEquals("Unexpected http status code!", code, response.code)
            // check IDS message type
            val parts = Utility.getParts(MultipartReader(response.body!!))
            Utility.checkIdsMessage(parts.first, RejectionMessage::class.java)
        }

        fun succContractMessage(pid: String, payload: String, c: Int = 1): ChJwt {
            val call = when (c) {
                1 -> client.newCall(MultipartClient.contractMessage(pid, payload, client=c))
                else -> otherClient.newCall(MultipartClient.contractMessage(pid, payload, client=c))
            }
            val response = call.execute()
            // check http status code
            Assert.assertEquals("Unexpected http status code!", 201, response.code)
            // check IDS message type
            val parts = Utility.getParts(MultipartReader(response.body!!))
            Utility.checkIdsMessage(parts.first, MessageProcessedNotificationMessage::class.java)
            // check the pid from receipt in the payload. Does pid match with the given pid?
            val receipt = Utility.parseJwt(parts.second)
            Assert.assertEquals("Returned PID does not match given PID!", pid, receipt.process_id)
            response.close()
            return receipt
        }

    }

}
