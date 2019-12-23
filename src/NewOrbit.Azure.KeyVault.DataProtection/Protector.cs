namespace NewOrbit.Azure.KeyVault.DataProtection
{
    using System;

    /// <summary>
    /// A class.
    /// </summary>
    public class Protector
    {
        // TODO:
        // - accept string with encodings
        // - optionally return base64
        // - accept a stream, ideally with a length and read it in chunks
        // - write to a stream "on the fly" to reduce memory consumption
        //// - maybe support ICryptoStream (how the hell does that handle the whole "final block" thing?? Not that it will help me as I want to pre-allocate the byte array)

        /// <summary>
        /// Encrypt and sign the input byte array.
        /// </summary>
        /// <param name="input">A byte array of data to be encrypted.</param>
        /// <returns>Encrypted and signed data with key identifiers.</returns>
        public byte[] Protect(byte[] input)
        {
            return input;
            //// var positions = CalculateArrayPositionsFromInputLength(input.Length);

            //// byte[] output = new byte[positions.TotalLength];

            //// return output;
        }

        /// <summary>
        /// Decrypt and check the signature.
        /// </summary>
        /// <param name="encryptedData">Data previously encrypted with this lib.</param>
        /// <returns>Decrypted data.</returns>
        public byte[] Unprotect(byte[] encryptedData)
        {
            return encryptedData;
        }
    }
}
