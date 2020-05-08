package com.example.encrypit
import android.media.tv.TvContract.Programs.Genres.encode
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.io.FileOutputStream
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.ShortBufferException
import java.security.NoSuchAlgorithmException
import javax.crypto.NoSuchPaddingException
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import java.io.UnsupportedEncodingException
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import java.security.InvalidKeyException
import java.security.Security

class MainActivity2 : AppCompatActivity() {

    fun encryptme(plaintext: String, secret_key: String): String? {
        Security.addProvider(BouncyCastleProvider())
        var keyBytes: ByteArray

        try {
            keyBytes = secret_key.toByteArray(charset("UTF8"))
            val skey = SecretKeySpec(keyBytes, "AES")
            val input = plaintext.toByteArray(charset("UTF8"))

            synchronized(Cipher::class.java) {
                val cipher = Cipher.getInstance("AES/ECB/PKCS7Padding")
                cipher.init(Cipher.ENCRYPT_MODE, skey)

                val cipherText = ByteArray(cipher.getOutputSize(input.size))
                var ctLength = cipher.update(
                    input, 0, input.size,
                    cipherText, 0
                )
                ctLength += cipher.doFinal(cipherText, ctLength)
                return String(
                    Base64.encode(cipherText)
                )
            }
        } catch (uee: UnsupportedEncodingException) {
            uee.printStackTrace()
        } catch (ibse: IllegalBlockSizeException) {
            ibse.printStackTrace()
        } catch (bpe: BadPaddingException) {
            bpe.printStackTrace()
        } catch (ike: InvalidKeyException) {
            ike.printStackTrace()
        } catch (nspe: NoSuchPaddingException) {
            nspe.printStackTrace()
        } catch (nsae: NoSuchAlgorithmException) {
            nsae.printStackTrace()
        } catch (e: ShortBufferException) {
            e.printStackTrace()
        }

        return null
    }

    fun decryptme(key: String, ciphertext: String?): String? {
        Security.addProvider(BouncyCastleProvider())
        var keyBytes: ByteArray

        try {
            keyBytes = key.toByteArray(charset("UTF8"))
            val skey = SecretKeySpec(keyBytes, "AES")
            val input = org.bouncycastle.util.encoders.Base64
                .decode(ciphertext?.trim { it <= ' ' }?.toByteArray(charset("UTF8")))

            synchronized(Cipher::class.java) {
                val cipher = Cipher.getInstance("AES/ECB/PKCS7Padding")
                cipher.init(Cipher.DECRYPT_MODE, skey)

                val plainText = ByteArray(cipher.getOutputSize(input.size))
                var ptLength = cipher.update(input, 0, input.size, plainText, 0)
                ptLength += cipher.doFinal(plainText, ptLength)
                val decryptedString = String(plainText)
                return decryptedString.trim { it <= ' ' }
            }
        } catch (uee: UnsupportedEncodingException) {
            uee.printStackTrace()
        } catch (ibse: IllegalBlockSizeException) {
            ibse.printStackTrace()
        } catch (bpe: BadPaddingException) {
            bpe.printStackTrace()
        } catch (ike: InvalidKeyException) {
            ike.printStackTrace()
        } catch (nspe: NoSuchPaddingException) {
            nspe.printStackTrace()
        } catch (nsae: NoSuchAlgorithmException) {
            nsae.printStackTrace()
        } catch (e: ShortBufferException) {
            e.printStackTrace()
        }
        return null
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main2)

        val context = applicationContext
        val path = context.filesDir
        val plaintext= "secret stuff"
        val password = "password"
        var encryptor: AESEncryptor = AESEncryptor()


        // ENCRYPT BUTTON
        val encryptBut = findViewById<View>(R.id.Encrypt) as Button
        encryptBut.setOnClickListener {
            try {
                // TODO do something like this
                var ciphertext: String? = encryptme(plaintext, password)
                println(ciphertext)
            } catch (e: Exception) {
                e.printStackTrace()
                // Exception prints failure
                Toast.makeText(this@MainActivity2, "Encryption Failure!", Toast.LENGTH_LONG).show()
            }
        }

        // DECRYPT BUTTON
        val decBut = findViewById<View>(R.id.Decrypt) as Button
        decBut.setOnClickListener {
            try {
                var plaintext = decryptme(password, ciphertext)
                println(plaintext)
            } catch (e: Exception) {
                e.printStackTrace()
                // Exception prints failure
                Toast.makeText(this@MainActivity2, "Decryption Failed!", Toast.LENGTH_LONG).show()
            }
        }
    }

    companion object {
        val TAG = MainActivity2::class.java.name

        // generate key from password using AES
        fun generateKey(password: CharArray?): SecretKey {
            val iterations = 1000

            // Generate a 256-bit key with SHA256
            val outputKeyLength = 256
            val salt = ByteArray(20)
            val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256")
            val keySpec: KeySpec = PBEKeySpec(password, salt, iterations, outputKeyLength)
            return secretKeyFactory.generateSecret(keySpec)
        }

        // encrypt with AES
        @Throws(Exception::class)
        fun encrypt(key: SecretKey?, fileData: ByteArray?): ByteArray? {
            val cipher = Cipher.getInstance("AES")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return cipher.doFinal(fileData)
        }

        // decrypt with AES
        @Throws(Exception::class)
        fun decrypt(key: SecretKey?, fileData: ByteArray?): ByteArray {
            val cipher = Cipher.getInstance("AES")
            cipher.init(Cipher.DECRYPT_MODE, key)
            return cipher.doFinal(fileData)
        }
    }
}