using System;

namespace NewOrbit.Azure.KeyVault.DataProtection
{
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

    }
}
