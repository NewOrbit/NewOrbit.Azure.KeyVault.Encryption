using System;

namespace NewOrbit.Azure.KeyVault.DataProtection
{
    /// <summary>
    /// A class.
    /// </summary>
    public class Protector
    {
        // Encrypted array format
        // version: 0
        
        // Key identifier for asymmetric key used to encrypt symmetric key
        
        // encrypted symmetric key
        // IV: (next to encrypted content to make it easy to authenticate the encryption)
        // encrypted content
        // key identifier for asymmetric key used to sign encrypted content
        // signature of encrypted content


        // TODO:
        // - accept string with encodings
        // - optionally return base64
        // - accept a stream, ideally with a length and read it in chunks
        // - write to a stream "on the fly" to reduce memory consumption
        // - maybe support ICryptoStream (how the hell does that handle the whole "final block" thing?? Not that it will help me as I want to pre-allocate the byte array)

        public byte[] Protect(byte[] input)
        {
            return input;
            // var positions = CalculateArrayPositionsFromInputLength(input.Length);

            // byte[] output = new byte[positions.TotalLength];


            // return output;
        }

        public byte[] Unprotect(byte[] encryptedData)
        {
            return encryptedData;
        }

        private ArrayPositions CalculateArrayPositionsFromInputLength(int inputArrayLength) 
        {
            var positions = new ArrayPositions();
            positions.EncryptedContentStart = 0;
            positions.EncryptedContentLength = (inputArrayLength / 16 + 1) * 16;

            // Add all the other bits of the file format.
            // Probably add an overload that takes the encrypted array with all the data?

            return positions;
        }
    }

    internal struct ArrayPositions
    {
        public int TotalLength;
        public int EncryptedContentStart;

        public int EncryptedContentLength;
        
    }
}
