package one.wabbit.rc4

import kotlin.test.Test
import kotlin.test.assertContentEquals

@OptIn(ExperimentalStdlibApi::class)
class RC4Spec {
    // TRUFFLEHOG
    val triples = listOf(
        Triple("Key", "Plaintext", "BBF316E8D940AF0AD3"),
        Triple("Wiki", "pedia", "1021BF0420"),
        Triple("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5")
    )

    @Test fun test() {
        for ((key, plaintext, expected) in triples) {
            val keyBytes = key.toByteArray(Charsets.UTF_8)
            val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
            val expectedBytes = expected.hexToByteArray()

            val ciphertext = RC4.fromKey(keyBytes).encrypt(plaintextBytes)
            assertContentEquals(expectedBytes, ciphertext)
            val decrypted = RC4.fromKey(keyBytes).decrypt(ciphertext)
            assertContentEquals(plaintextBytes, decrypted)
        }
    }
}
