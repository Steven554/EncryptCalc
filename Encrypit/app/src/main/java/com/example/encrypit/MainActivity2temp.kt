package com.example.encrypit

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.encrypit.MainActivity2.Companion.generateKey
import java.io.File
import java.io.UnsupportedEncodingException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.Security
import java.util.*
import javax.crypto.*
import javax.crypto.spec.SecretKeySpec

class MainActivity2temp : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main2)

        val context = applicationContext
        val path = context.filesDir


        // Create new file
        val fileName = "data.txt"
        var testfile = File(path, fileName)
        testfile.createNewFile()

        // Read user message field
        val messageField = findViewById<View>(R.id.messageField) as EditText

        // Read password field
        val passwordField = findViewById<View>(R.id.passwordField) as EditText

        // Create new file
        val encFileName = "encryptedFile.txt"
        var encFile = File(path, encFileName)
        encFile.createNewFile()

        // ENCRYPT BUTTON
        val encryptBut = findViewById<View>(R.id.Encrypt) as Button
        encryptBut.setOnClickListener {
            try {
                // Write text in message field to file
                testfile.writeText(messageField.text.toString())
                println("message field: " + testfile.readText())

                val byteArray = testfile.readBytes()
                println("byteArray: " + testfile.readBytes())

                // Read in password
                val currentPass = passwordField.text.toString()

                // Generate a key from password, encrypt text with it
                val key = generateKey(currentPass.toCharArray())
                val cipher = encrypt(key, byteArray)

                // Write cipher text to encrypted file
                encFile.writeBytes(cipher!!)

                println("ENCRYPTED (string)" + encFile.readText())
//
//                // Write out encrypted file
//                val stream = FileOutputStream("$path/encrypted.txt")
//
//                try {
//
////                    stream.write(cipher!!)
//                    Toast.makeText(this@MainActivity2, "Encryption Success!", Toast.LENGTH_LONG)
//                        .show()
//                } finally {
//                    stream.flush()
//                    stream.close()
//                }
            } catch (e: Exception) {
                e.printStackTrace()
                // Exception prints failure
                Toast.makeText(this@MainActivity2temp, "Encryption Failure!", Toast.LENGTH_LONG).show()
            }
        }

        // DECRYPT BUTTON
        val decBut = findViewById<View>(R.id.Decrypt) as Button
        decBut.setOnClickListener {
//            var data: ByteArray? = ByteArray(0)
            try {
                // Read in encrypted text and password field

//                data = (File("$path/encryptedFile.txt")).readBytes()

                val currentPass = passwordField.text.toString()

                // Generate a key from password, decrypt zip with it
                val key = generateKey(currentPass.toCharArray())
                val plainText = decrypt(key, encFile.readBytes())

                testfile.writeText(plainText.toString())

                println("DECRYPTED: " + testfile.readText())

//                // Write out decrypted file
//                val stream = FileOutputStream("$path/decrypted.txt")
//                try {
//                    stream.write(plainText)
//                    Toast.makeText(this@MainActivity2, "Decryption Success!", Toast.LENGTH_LONG)
//                        .show()
//                } finally {
//                    stream.flush()
//                    stream.close()
//                }
            } catch (e: Exception) {
                e.printStackTrace()

                // Exception prints failure
                Toast.makeText(this@MainActivity2temp, "Decryption Failed!", Toast.LENGTH_LONG).show()

            }
        }
    }

    companion object {
        val TAG = MainActivity2temp::class.java.name
        fun encryptme(plaintext: String, secret_key: String): String? {
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
    }
}
