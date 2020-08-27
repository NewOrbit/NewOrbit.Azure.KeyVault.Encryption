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
            // Encrypt
            // add IV
            // add encrypted version of the symmetric key
            // add signature to output
            //// add key identifier for signature verification

            var positions = ArrayPositionsV1.Get(input.Length);

            var output = new byte[positions.TotalLength];

            using (var aes = Aes.Create())
            {
                Debug.Assert(aes.Key.Length == 32, "AES key length is not 32");
                Debug.Assert(aes.IV.Length == 16, "IV length is not 16");
                var encryptor = aes.CreateEncryptor();

                var inputLength = input.Length;
                var initialBlocks = (inputLength - 1) / 16;  // Some WETnes here with ArrayPositions

                for (int i = 0; i < initialBlocks; i++)
                {
                    var inputPos = i * 16;
                    var outputPos = inputPos + positions.EncryptedContent.Position;
                    encryptor.TransformBlock(input, inputPos, 16, output, outputPos);
                }

                var finalBlockStart = initialBlocks * 16;
                var finalBlockLength = inputLength - (initialBlocks * 16);
                var finalBlock = encryptor.TransformFinalBlock(input, finalBlockStart, finalBlockLength);
                finalBlock.CopyTo(output, finalBlockStart + positions.EncryptedContent.Position);

                aes.IV.CopyTo(output, positions.InitialisationVector.Position);

                var sliceForTheWrappedKey = output.AsSpan().Slice(positions.WrappedSymmetricKey.Position, positions.WrappedSymmetricKey.Length);
                var sliceForTheKeyIdentifier = output.AsSpan().Slice(positions.AsymmetricWrapperKeyIdentifier.Position, positions.AsymmetricWrapperKeyIdentifier.Length);
                this.symmetricKeyWrapper.Wrap(aes.Key, sliceForTheWrappedKey, sliceForTheKeyIdentifier);
            }

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

            var iv = encryptedData.AsSpan().Slice(positions.InitialisationVector.Position, positions.InitialisationVector.Length).ToArray();
            ReadOnlySpan<byte> encryptedSymmetricKey = encryptedData.AsSpan().Slice(positions.WrappedSymmetricKey.Position, positions.WrappedSymmetricKey.Length);
            ReadOnlySpan<byte> wrappingKeyIdentifier = encryptedData.AsSpan().Slice(positions.AsymmetricWrapperKeyIdentifier.Position, positions.AsymmetricWrapperKeyIdentifier.Length);

            var symmetricKey = this.symmetricKeyWrapper.UnWrap(encryptedSymmetricKey, wrappingKeyIdentifier);

            Debug.Assert(symmetricKey.Length == 32, "The key length is not 32");
            Debug.Assert(iv.Length == 16, "the iv length is not 16");

            using (var aes = Aes.Create())
            {
                var decryptor = aes.CreateDecryptor(symmetricKey, iv);
                return decryptor.TransformFinalBlock(encryptedData, positions.EncryptedContent.Position, positions.EncryptedContent.Length);
            }
        }
    }
}