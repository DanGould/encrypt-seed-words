using System;
using NBitcoin;
using Xunit;
using static pwEnc.SeedWordsCrypto;

namespace pwEnc.Tests
{
    public class EncSeedWordsTests
    {
        [Fact]
        [Trait("UnitTest", "UnitTest")]
        public void CanRoundTripKeyEncryption()
        {
            //Test easily debuggable
            string passphrase = "margaretthatcheris110%sexy";
            string seedWords = "keep coach tower bacon you scout easy velvet cube tennis reject uphold dynamic mystery zebra";

            Network network = Network.Main;

            // Wasabi does now
            var mnemonic = new Mnemonic(seedWords);
            var extKey = mnemonic.DeriveExtKey(passphrase);
            var encMasterSecret = extKey.PrivateKey.GetEncryptedBitcoinSecret(passphrase, network); // BIP38 @NBitcoin


            var masterSecretBytes = extKey.PrivateKey.ToBytes();
            var decMasterSecretBytes = encMasterSecret.GetKey(passphrase).ToBytes();
            Assert.Equal(masterSecretBytes, decMasterSecretBytes);
            // The solution to do the most good likely is the easiest to use
            // and so, often used
            (byte[] encSeedWords, byte[] iv, byte[] salt) = AuthEncString(seedWords, masterSecretBytes);
            var decSeedWords = AuthDec(encSeedWords, masterSecretBytes, iv, salt);
            Assert.Equal(seedWords, decSeedWords);

            //The real deal
            for (int i = 0; i < 5; i++)
            {
                // FIXME: random passphrases of various lenghts as well?
                passphrase = "";
                mnemonic = new Mnemonic(Wordlist.English, WordCount.Twelve);
                seedWords = mnemonic.ToString();
                extKey = mnemonic.DeriveExtKey(passphrase);
                masterSecretBytes = extKey.PrivateKey.ToBytes();
                (encSeedWords, iv, salt) = AuthEncString(seedWords, masterSecretBytes);
                decSeedWords = AuthDec(encSeedWords, masterSecretBytes, iv, salt);
                Assert.Equal(seedWords, decSeedWords);
            }
        }
    }
}
