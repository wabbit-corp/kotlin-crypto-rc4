package one.wabbit.rc4

import kotlin.experimental.xor

/**
 * The RC4 class is an implementation of the RC4 stream cipher algorithm.
 *
 * @property S A 256-byte state array used in the RC4 algorithm. Must be initialized with exactly 256 bytes.
 */
class RC4(val S: ByteArray) {
    init {
        require(S.size == 256) { "S must be 256 bytes" }
    }

    /**
     * Creates a copy of the current RC4 instance, duplicating its state array (S).
     *
     * @return A new RC4 instance with an identical state array to the original.
     */
    fun copy(): RC4 = RC4(S.copyOf())

    /**
     * Encrypts the given plaintext using the RC4 stream cipher algorithm.
     * This implementation modifies the internal state of the RC4 object during encryption.
     *
     * @param plaintext The input byte array to be encrypted.
     * @return A byte array containing the encrypted ciphertext.
     */
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

    /**
     * Decrypts the given ciphertext using the RC4 stream cipher algorithm.
     * This operation is typically the reverse of encryption, but in RC4,
     * encryption and decryption processes are identical.
     *
     * @param ciphertext The input byte array to be decrypted.
     * @return A byte array containing the decrypted plaintext.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        return encrypt(ciphertext)
    }

    companion object {
        /**
         * Initializes an RC4 cipher instance using the provided key.
         *
         * @param key A byte array representing the key. The key size must be between 1 and 256 bytes.
         * @return An instance of the RC4 cipher with the initialized state array.
         * @throws IllegalArgumentException If the key size is not within the allowed range (1 to 256 bytes).
         */
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
