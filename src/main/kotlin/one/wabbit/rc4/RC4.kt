package one.wabbit.rc4

import kotlin.experimental.xor

class RC4(val S: ByteArray) {
    init {
        require(S.size == 256) { "S must be 256 bytes" }
    }

    fun copy(): RC4 = RC4(S.copyOf())

    fun encrypt(plaintext: ByteArray): ByteArray {
        val ciphertext = ByteArray(plaintext.size)
        var i = 0
        var j = 0
        for (counter in plaintext.indices) {
            i = i + 1 and 0xFF
            j = j + S[i] and 0xFF
            val tmp = S[j]
            S[j] = S[i]
            S[i] = tmp
            val t = S[i] + S[j] and 0xFF
            val k = S[t].toInt()
            ciphertext[counter] = plaintext[counter] xor k.toByte()
        }
        return ciphertext
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        return encrypt(ciphertext)
    }

    companion object {
        fun fromKey(key: ByteArray): RC4 {
            require(!(key.size < 1 || key.size > 256)) { "key must be between 1 and 256 bytes" }

            val S = ByteArray(256)
            val T = ByteArray(256)

            val keylen = key.size
            for (i in 0..255) {
                S[i] = i.toByte()
                T[i] = key[i % keylen]
            }
            var j = 0
            for (i in 0..255) {
                j = j + S[i] + T[i] and 0xFF
                val tmp = S[j]
                S[j] = S[i]
                S[i] = tmp
            }

            return RC4(S)
        }
    }
}
