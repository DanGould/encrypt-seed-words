using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Secp256k1;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace pwEnc
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            string passphrase = "margaretthatcheris110%sexy";
            string seedWords = "keep coach tower bacon you scout easy velvet cube tennis reject uphold dynamic mystery zebra";
            Network network = Network.Main;

            // What Wasabi does now
            var mnemonic = new Mnemonic(seedWords);
            var extKey = mnemonic.DeriveExtKey(passphrase);
            var encMasterSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(passphrase, network); // BIP38 @NBitcoin

            // The solution to do the most good likely is the easiest to use
            // and so often used
            var encSeedWords = EncryptSeedWords(extKey.PrivateKey, seedWords, encMasterSecret.ToBytes(), network);
           
        }


        private static string EncryptSeedWords(Key key, string seedWords, byte[] encMasterSecretBytes, Network network)
        {
            var wordsBytes = Encoding.UTF8.GetBytes(seedWords);

            // Compute the Bitcoin address (ASCII),
            var addressBytes = Encoders.ASCII.DecodeData(key.PubKey.GetAddress(ScriptPubKeyType.Legacy, network).ToString());
            // and take the first four bytes of SHA256(SHA256()) of it. Let's call this "addresshash".
            var addresshash = Hashes.Hash256(addressBytes).ToBytes().SafeSubarray(0, 4);
            // TODO @ethan This is the salt for SCypt. Should be unique for each encryption, yes?
            // and take the first four bytes of SHA256(SHA256()) of it. Let's call this "addresshashhash".
            var addresshashhash = Hashes.Hash256(addresshash).ToBytes().SafeSubarray(0, 4);

            var derived = SCrypt.BitcoinComputeDerivedKey(encMasterSecretBytes, addresshashhash);

            var encrypted = EncryptKey(vch, derived);



            var version = network.GetVersionBytes(Base58Type.ENCRYPTED_SECRET_KEY_NO_EC, true);
            byte flagByte = 0;
            flagByte |= 0x0C0;
            flagByte |= (key.IsCompressed ? (byte)0x20 : (byte)0x00);

            var bytes = version
                            .Concat(new[] { flagByte })
                            .Concat(addresshash)
                            .Concat(encrypted).ToArray();
            return network.NetworkStringParser.GetBase58CheckEncoder().EncodeData(bytes);
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

#if USEBC || WINDOWS_UWP
		internal static PaddedBufferedBlockCipher CreateAES256(bool encryption, byte[] key)
		{
			var aes = new PaddedBufferedBlockCipher(new AesFastEngine(), new Pkcs7Padding());
			aes.Init(encryption, new KeyParameter(key));
			aes.ProcessBytes(new byte[16], 0, 16, new byte[16], 0);
			return aes;
		}
#else
		internal static Aes CreateAES256()
		{
			var aes = Aes.Create();
			aes.KeySize = 256;
			aes.Mode = CipherMode.ECB;
			aes.IV = new byte[16];
			return aes;
		}
#endif
		internal static byte[] EncryptKey(byte[] key, byte[] derived)
		{
			var keyhalf1 = key.SafeSubarray(0, 16);
			var keyhalf2 = key.SafeSubarray(16, 16);
			return EncryptKey(keyhalf1, keyhalf2, derived);
		}

		private static byte[] EncryptKey(byte[] keyhalf1, byte[] keyhalf2, byte[] derived)
		{
			var derivedhalf1 = derived.SafeSubarray(0, 32);
			var derivedhalf2 = derived.SafeSubarray(32, 32);

			var encryptedhalf1 = new byte[16];
			var encryptedhalf2 = new byte[16];
#if USEBC || WINDOWS_UWP
			var aes = BitcoinEncryptedSecret.CreateAES256(true, derivedhalf2);
#else
			var aes = CreateAES256();
			aes.Key = derivedhalf2;
			var encrypt = aes.CreateEncryptor();
#endif

			for (int i = 0; i < 16; i++)
			{
				derivedhalf1[i] = (byte)(keyhalf1[i] ^ derivedhalf1[i]);
			}
#if USEBC || WINDOWS_UWP
			aes.ProcessBytes(derivedhalf1, 0, 16, encryptedhalf1, 0);
			aes.ProcessBytes(derivedhalf1, 0, 16, encryptedhalf1, 0);
#else
			encrypt.TransformBlock(derivedhalf1, 0, 16, encryptedhalf1, 0);
#endif
			for (int i = 0; i < 16; i++)
			{
				derivedhalf1[16 + i] = (byte)(keyhalf2[i] ^ derivedhalf1[16 + i]);
			}
#if USEBC || WINDOWS_UWP
			aes.ProcessBytes(derivedhalf1, 16, 16, encryptedhalf2, 0);
			aes.ProcessBytes(derivedhalf1, 16, 16, encryptedhalf2, 0);
#else
			encrypt.TransformBlock(derivedhalf1, 16, 16, encryptedhalf2, 0);
#endif
			return encryptedhalf1.Concat(encryptedhalf2).ToArray();
		}

		internal static byte[] DecryptKey(byte[] encrypted, byte[] derived)
		{
			var derivedhalf1 = derived.SafeSubarray(0, 32);
			var derivedhalf2 = derived.SafeSubarray(32, 32);

			var encryptedHalf1 = encrypted.SafeSubarray(0, 16);
			var encryptedHalf2 = encrypted.SafeSubarray(16, 16);

			byte[] bitcoinprivkey1 = new byte[16];
			byte[] bitcoinprivkey2 = new byte[16];

#if USEBC || WINDOWS_UWP
			var aes = CreateAES256(false, derivedhalf2);
			aes.ProcessBytes(encryptedHalf1, 0, 16, bitcoinprivkey1, 0);
			aes.ProcessBytes(encryptedHalf1, 0, 16, bitcoinprivkey1, 0);
#else
			var aes = CreateAES256();
			aes.Key = derivedhalf2;
			var decrypt = aes.CreateDecryptor();
			//Need to call that two time, seems AES bug
			decrypt.TransformBlock(encryptedHalf1, 0, 16, bitcoinprivkey1, 0);
			decrypt.TransformBlock(encryptedHalf1, 0, 16, bitcoinprivkey1, 0);
#endif



			for (int i = 0; i < 16; i++)
			{
				bitcoinprivkey1[i] ^= derivedhalf1[i];
			}
#if USEBC || WINDOWS_UWP
			aes.ProcessBytes(encryptedHalf2, 0, 16, bitcoinprivkey2, 0);
			aes.ProcessBytes(encryptedHalf2, 0, 16, bitcoinprivkey2, 0);
#else
			//Need to call that two time, seems AES bug
			decrypt.TransformBlock(encryptedHalf2, 0, 16, bitcoinprivkey2, 0);
			decrypt.TransformBlock(encryptedHalf2, 0, 16, bitcoinprivkey2, 0);
#endif
			for (int i = 0; i < 16; i++)
			{
				bitcoinprivkey2[i] ^= derivedhalf1[16 + i];
			}

			return bitcoinprivkey1.Concat(bitcoinprivkey2).ToArray();
		}
	}


}
