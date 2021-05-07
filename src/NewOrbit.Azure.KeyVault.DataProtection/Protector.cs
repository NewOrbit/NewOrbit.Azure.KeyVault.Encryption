namespace NewOrbit.Azure.KeyVault.DataProtection
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography;

    /// <summary>
    /// A class.
    /// </summary>
    public class Protector
    {
        private ISymmetricKeyWrapper symmetricKeyWrapper;
        private IDigestSigner digestSigner;

        //// TODO:
        //// - accept string with encodings
        //// - optionally return base64
        //// - accept a stream, ideally with a length and read it in chunks
        //// - write to a stream "on the fly" to reduce memory consumption
        //// - maybe support ICryptoStream (how the hell does that handle the whole "final block" thing?? Not that it will help me as I want to pre-allocate the byte array)

        public Protector(ISymmetricKeyWrapper symmetricKeyWrapper, IDigestSigner digestSigner)
        {
            this.symmetricKeyWrapper = symmetricKeyWrapper;
            this.digestSigner = digestSigner;
        }

        /// <summary>
        /// Encrypt and sign the input byte array.
        /// </summary>
        /// <param name="input">A byte array of data to be encrypted.</param>
        /// <returns>Encrypted and signed data with key identifiers.</returns>
        public byte[] Protect(byte[] input)
        {
            //// add signature to output

            var positions = ArrayPositionsV1.Get(input.Length);

            var output = new byte[positions.TotalLength];

            var key = this.EncryptWithAES(
                input,
                positions.EncryptedContent.GetSpan(output),
                positions.InitialisationVector.GetSpan(output));

            this.symmetricKeyWrapper.Wrap(
                key,
                positions.WrappedSymmetricKey.GetSpan(output),
                positions.AsymmetricWrapperKeyIdentifier.GetSpan(output));

            return output;
        }

        /// <summary>
        /// Decrypt and check the signature.
        /// </summary>
        /// <param name="encryptedData">Data previously encrypted with this lib.</param>
        /// <returns>Decrypted data.</returns>
        public byte[] Unprotect(byte[] encryptedData)
        {
            var positions = ArrayPositionsV1.Get(encryptedData);

            var iv = positions.InitialisationVector.GetSpan(encryptedData).ToArray();

            var symmetricKey = this.symmetricKeyWrapper.UnWrap(
                positions.WrappedSymmetricKey.GetSpan(encryptedData),
                positions.AsymmetricWrapperKeyIdentifier.GetSpan(encryptedData));

            Debug.Assert(symmetricKey.Length == 32, "The key length is not 32");
            Debug.Assert(iv.Length == 16, "the iv length is not 16");

            using (var aes = Aes.Create())
            {
                var decryptor = aes.CreateDecryptor(symmetricKey, iv);
                return decryptor.TransformFinalBlock(encryptedData, positions.EncryptedContent.Position, positions.EncryptedContent.Length);
            }
        }

        /// <summary>
        /// Encrypt the input and stores the encrypted content and the iv.
        /// Returns the used encryption key.
        /// </summary>
        /// <returns>The used encryption key.</returns>
        private ReadOnlySpan<byte> EncryptWithAES(byte[] input, Span<byte> encryptedContentDestination, Span<byte> ivDestination)
        {
            // AES cannot directly work with Span so need some gymnastics...
            using (var aes = Aes.Create())
            {
                Debug.Assert(aes.Key.Length == 32, "AES key length is not 32");
                Debug.Assert(aes.IV.Length == 16, "IV length is not 16");
                var encryptor = aes.CreateEncryptor();

                var inputLength = input.Length;
                var initialBlocks = (inputLength - 1) / 16;  // Some WETnes here with ArrayPositions
                byte[] buffer = new byte[16];
                for (int i = 0; i < initialBlocks; i++)
                {
                    var position = i * 16;
                    encryptor.TransformBlock(input, position, 16, buffer, 0);
                    buffer.CopyTo(encryptedContentDestination[position..]);
                    Array.Clear(buffer, 0, 16);
                }

                var finalBlockStart = initialBlocks * 16;
                var finalBlockLength = inputLength - (initialBlocks * 16);
                var finalBlock = encryptor.TransformFinalBlock(input, finalBlockStart, finalBlockLength);

                finalBlock.CopyTo(encryptedContentDestination[finalBlockStart..]);

                aes.IV.CopyTo(ivDestination);

                return aes.Key;
            }
        }
    }
}