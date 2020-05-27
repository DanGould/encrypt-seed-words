using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace pwEnc
{
    public static class SeedWordsCrypto
    {
        public static void Main(string[] args)
        {
            // should have made a .NET Standard 2.1 Library but this is a POC
        }

        // use Authenticated Encryption, no Associated Data
        public static byte[] EncryptSeedWords(string seedWords, byte[] masterSecretBytes)
        {
            var salt = Concat(new UTF8Encoding(false).GetBytes("masterSecret"), masterSecretBytes);

			using Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(masterSecretBytes, salt, 2048, HashAlgorithmName.SHA512);
            var k1_masterSecret = derive.GetBytes(32); // for 256 bit aes
            var iv = salt.SafeSubarray(0, 16); // aes has 128 bit blocks

            var encSeedWords = EncryptStringToBytes_Aes(seedWords, k1_masterSecret, iv);

            // somewhat arbitrary but matching k1 keysize for HMAC
            var k2_masterSecret = derive.GetBytes(32);
            using HMACSHA512 hmac = new HMACSHA512(k2_masterSecret);
            byte[] tag = new byte[hmac.HashSize / 8];
            tag = hmac.ComputeHash(Concat(iv, encSeedWords));
            return Concat(tag, encSeedWords);
        }

        public static string DecryptSeedWords(byte[] encSeedWords, byte[] masterSecretBytes)
        {
            var salt = Concat(new UTF8Encoding(false).GetBytes("masterSecret"), masterSecretBytes);

            using Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(masterSecretBytes, salt, 2048, HashAlgorithmName.SHA512);
            var k1_masterSecret = derive.GetBytes(32); // for 256 bit aes
            var iv = salt.SafeSubarray(0,16); // aes is 128 bit blocks
            var k2_masterSecret = derive.GetBytes(32);
            using HMACSHA512 hmac = new HMACSHA512(k2_masterSecret);
            VerifyEncSeedWordsMAC(k2_masterSecret, encSeedWords);
            return DecryptStringFromBytes_Aes(encSeedWords.SafeSubarray(hmac.HashSize / 8), k1_masterSecret, iv);
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        // Compares the key in the source file with a new key created for the data portion of the file. If the keys
        // compare the data has not been tampered with.
        public static bool VerifyEncSeedWordsMAC(byte[] key, byte[] storedEncSeed)
        {
            bool err = false;
            // Initialize the keyed hash object.
            using (HMACSHA512 hmac = new HMACSHA512(key))
            {
                // Create an array to hold the keyed hash value read from the file.
                byte[] storedTag = new byte[hmac.HashSize / 8];
                storedTag = storedEncSeed.SafeSubarray(0, storedTag.Length);

                // Compute the hash of the remaining contents of the file.
                // The stream is properly positioned at the beginning of the content,
                // immediately after the stored hash value.
                var encSeedWords = storedEncSeed.SafeSubarray(storedTag.Length);
                byte[] computedHash = hmac.ComputeHash(encSeedWords);
                // compare the computed hash with the stored value

                for (int i = 0; i < storedTag.Length; i++)
                {
                    if (computedHash[i] != storedTag[i])
                    {
                        err = true;
                    }
                }

            }
            if (err)
            {
                Console.WriteLine("Hash values differ! Signed ciphertext has been tampered with!");
                return false;
            }
            else
            {
                Console.WriteLine("Hash values agree -- no tampering occurred.");
                return true;
            }
        } //end VerifyFile

        static Byte[] Concat(Byte[] source1, Byte[] source2)
        {
            //Most efficient way to merge two arrays this according to http://stackoverflow.com/questions/415291/best-way-to-combine-two-or-more-byte-arrays-in-c-sharp
            Byte[] buffer = new Byte[source1.Length + source2.Length];
            System.Buffer.BlockCopy(source1, 0, buffer, 0, source1.Length);
            System.Buffer.BlockCopy(source2, 0, buffer, source1.Length, source2.Length);

            return buffer;
        }
	}

	internal static class ByteArrayExtensions
	{
		internal static byte[] SafeSubarray(this byte[] array, int offset, int count)
		{
			if (array == null)
				throw new ArgumentNullException(nameof(array));
			if (offset < 0 || offset > array.Length)
				throw new ArgumentOutOfRangeException("offset");
			if (count < 0 || offset + count > array.Length)
				throw new ArgumentOutOfRangeException("count");
			if (offset == 0 && array.Length == count)
				return array;
			var data = new byte[count];
			Buffer.BlockCopy(array, offset, data, 0, count);
			return data;
		}

		internal static byte[] SafeSubarray(this byte[] array, int offset)
		{
			if (array == null)
				throw new ArgumentNullException(nameof(array));
			if (offset < 0 || offset > array.Length)
				throw new ArgumentOutOfRangeException("offset");

			var count = array.Length - offset;
			var data = new byte[count];
			Buffer.BlockCopy(array, offset, data, 0, count);
			return data;
		}
	}
}
