package de.fhg.aisec.ids.clearinghouse

import de.fhg.aisec.ids.idscp2.defaultdrivers.daps.aisecdaps.AisecDapsDriverConfig
import org.slf4j.LoggerFactory
import java.nio.file.Paths

internal object Configuration {
    private val LOG = LoggerFactory.getLogger(Configuration::class.java)
    private const val DEFAULT_PASSWORD = "password"
    private const val DAPS_ENV_VARIABLE = "TC_DAPS_URL"
    private const val KEY_PASS_ENV_VARIABLE = "TC_KEY_PW"
    private const val KEYSTORE_PASS_ENV_VARIABLE = "TC_KEYSTORE_PW"
    private const val TRUSTSTORE_PASS_ENV_VARIABLE = "TC_TRUSTSTORE_PW"

    // keep this in sync with libraryVersions.yaml
    const val infomodelVersion = "4.1.0"
    private const val SENDER_AGENT = "TC_CH_AGENT"
    private const val ISSUER_CONNECTOR = "TC_CH_ISSUER_CONNECTOR"

    fun createDapsConfig(): AisecDapsDriverConfig {
        val dapsUrl = System.getenv(DAPS_ENV_VARIABLE) ?: "https://daps.aisec.fraunhofer.de"
        val keyPassword = System.getenv(KEY_PASS_ENV_VARIABLE) ?: DEFAULT_PASSWORD
        val keystorePassword = System.getenv(KEYSTORE_PASS_ENV_VARIABLE) ?: DEFAULT_PASSWORD
        val truststorePassword = System.getenv(TRUSTSTORE_PASS_ENV_VARIABLE) ?: DEFAULT_PASSWORD
        return AisecDapsDriverConfig.Builder()
            .setKeyPassword(keyPassword.toCharArray())
            .setKeyStorePath(Paths.get("/root/etc/keystore.p12"))
            .setKeyStorePassword(keystorePassword.toCharArray())
            .setKeyAlias("1")
            .setTrustStorePath(Paths.get("/root/etc/truststore.p12"))
            .setDapsUrl(dapsUrl)
            .setTrustStorePassword(truststorePassword.toCharArray())
            .build()
    }

    val senderAgent: String
        get() = getEnvVariable(SENDER_AGENT)
    val issuerConnector: String
        get() = getEnvVariable(ISSUER_CONNECTOR)

    private fun getEnvVariable(envVariable: String): String {
        val value = System.getenv(envVariable)
        return if (value == null) {
            LOG.error("Configuration invalid: Missing {}", envVariable)
            ""
        } else {
            value
        }
    }
}
