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

        private ArrayPositions CalculateArrayPositionsFromInputLength(int inputArrayLength) 
        {
            // Encrypted array format
            // version: 0
            
            // Key identifier for asymmetric key used to encrypt symmetric key
            
            // encrypted symmetric key
            // IV: (next to encrypted content to make it easy to authenticate the encryption)
            // encrypted content
            // key identifier for asymmetric key used to sign encrypted content
            // signature of encrypted content

            var positions = new ArrayPositions();
            positions.EncryptedContentStart = 0;
            positions.EncryptedContentLength = (inputArrayLength / 16 + 1) * 16;

            // Add all the other bits of the file format.
            // Probably add an overload that takes the encrypted array with all the data?

            return positions;
        }
    }

    internal readonly struct ArrayPositions
    {
        private const int RSAKeyLengthBits = 2048;
        private const int InitialisationVectorLengthBytes = 10; // TODO: Change
        private const int KeyVersionByteLength = 32; // TODO: Change

        public ArrayPositions(int inputArrayLength)
        {
            Version              = new Item(0, 1);
            EncryptingKeyVersion = new Item(Version, KeyVersionByteLength);
            EncryptingKey        = new Item(EncryptingKeyVersion, RSAKeyLengthBits / 8);
            InitialisationVector = new Item(EncryptingKey, InitialisationVectorLengthBytes);
            EncryptedContent     = new Item(10, (inputArrayLength / 16 + 1) * 16);
            SigningKeyVersion    = new Item(EncryptedContent, KeyVersionByteLength);
            Signature            = new Item(SigningKeyVersion, RSAKeyLengthBits / 8);

        }
        // public readonly int TotalLength;
        public readonly Item Version;

        public readonly Item EncryptingKeyVersion;

        public readonly Item EncryptingKey;

        public readonly Item InitialisationVector;

        public readonly Item EncryptedContent;

        public readonly Item SigningKeyVersion;

        public readonly Item Signature;
    }

    internal readonly struct Item
    {
        public Item(int position, int length)
        {
            this.Position = position;
            this.Length = length;
        }

        public Item (Item previousItem, int length) 
           : this(previousItem.Position + previousItem.Length, length)
        {}

        public readonly int Position;

        public readonly int Length;
    }
}
