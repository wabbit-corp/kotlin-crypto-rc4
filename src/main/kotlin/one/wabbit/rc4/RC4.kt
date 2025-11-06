package one.wabbit.rc4

import kotlin.experimental.xor

/**
 * The RC4 class is an implementation of the RC4 stream cipher algorithm.
 *
 * @property s A 256-byte state array used in the RC4 algorithm. Must be initialized with exactly
 *   256 bytes.
 */
class RC4(val s: ByteArray) {
    init {
        require(s.size == 256) { "S must be 256 bytes" }
    }

    /**
     * Creates a copy of the current RC4 instance, duplicating its state array (S).
     *
     * @return A new RC4 instance with an identical state array to the original.
     */
    fun copy(): RC4 = RC4(s.copyOf())

    /**
     * Encrypts the given plaintext using the RC4 stream cipher algorithm. This implementation
     * modifies the internal state of the RC4 object during encryption.
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
            j = j + s[i] and 0xFF
            val tmp = s[j]
            s[j] = s[i]
            s[i] = tmp
            val t = s[i] + s[j] and 0xFF
            val k = s[t].toInt()
            ciphertext[counter] = plaintext[counter] xor k.toByte()
        }
        return ciphertext
    }

    /**
     * Decrypts the given ciphertext using the RC4 stream cipher algorithm. This operation is
     * typically the reverse of encryption, but in RC4, encryption and decryption processes are
     * identical.
     *
     * @param ciphertext The input byte array to be decrypted.
     * @return A byte array containing the decrypted plaintext.
     */
    fun decrypt(ciphertext: ByteArray): ByteArray = encrypt(ciphertext)

    companion object {
        /**
         * Initializes an RC4 cipher instance using the provided key.
         *
         * @param key A byte array representing the key. The key size must be between 1 and 256
         *   bytes.
         * @return An instance of the RC4 cipher with the initialized state array.
         * @throws IllegalArgumentException If the key size is not within the allowed range (1 to
         *   256 bytes).
         */
        fun fromKey(key: ByteArray): RC4 {
            require(!(key.size < 1 || key.size > 256)) { "key must be between 1 and 256 bytes" }

            val s = ByteArray(256)
            val t = ByteArray(256)

            val keylen = key.size
            for (i in 0..255) {
                s[i] = i.toByte()
                t[i] = key[i % keylen]
            }
            var j = 0
            for (i in 0..255) {
                j = j + s[i] + t[i] and 0xFF
                val tmp = s[j]
                s[j] = s[i]
                s[i] = tmp
            }

            return RC4(s)
        }
    }
}
