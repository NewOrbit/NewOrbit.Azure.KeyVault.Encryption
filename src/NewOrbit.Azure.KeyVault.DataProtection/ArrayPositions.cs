using System;

namespace NewOrbit.Azure.KeyVault.DataProtection
{
    public readonly struct ArrayPositionsV1
    {
        private const int RSAKeyLengthBits = 2048;
        private const int InitialisationVectorLengthBytes = 16; 
        private const int KeyVersionByteLength = 32; 

        public ArrayPositionsV1(int inputArrayLength)
            : this((inputArrayLength / 16 + 1) * 16, true)
        {
        }

        public ArrayPositionsV1(in ReadOnlySpan<byte> encryptedContent)
            : this(GetEncryptedContentLengthFromFullPackage(encryptedContent), true)
        {         
        }

        private ArrayPositionsV1(int encryptedContentLength, bool dummyForOverloadOnly)
        {
            Version              = new Item(0, 1);
            EncryptingKeyVersion = new Item(Version, KeyVersionByteLength);
            EncryptingKey        = new Item(EncryptingKeyVersion, RSAKeyLengthBits / 8);
            InitialisationVector = new Item(EncryptingKey, InitialisationVectorLengthBytes);
            EncryptedContent     = new Item(InitialisationVector, encryptedContentLength);
            SigningKeyVersion    = new Item(EncryptedContent, KeyVersionByteLength);
            Signature            = new Item(SigningKeyVersion, RSAKeyLengthBits / 8);
            TotalLength          = Signature.Position + Signature.Length;  // Reminder: this is one higher than the last position in the array
        }

        private static int GetEncryptedContentLengthFromFullPackage(in ReadOnlySpan<byte> encryptedContent)
        {
            var overheadLength = 1 + (2 * KeyVersionByteLength) + (2 * (RSAKeyLengthBits / 8)) + InitialisationVectorLengthBytes;
            var encryptedContentLength = encryptedContent.Length - overheadLength; 
            if (encryptedContentLength < 16) 
            {
                throw new ArgumentException("The encrypted content is shorter than the minimum it can logically be. It must be invalid.", nameof(encryptedContent));
            }
            
            if (encryptedContentLength % 16 != 0)
            {
                throw new ArgumentException("The encrypted content is not a multiple of 16. The passed-in data must be invalid.");
            }

            return encryptedContentLength;
        }

        public readonly int TotalLength;
        public readonly Item Version;

        public readonly Item EncryptingKeyVersion;

        public readonly Item EncryptingKey;

        public readonly Item InitialisationVector;

        public readonly Item EncryptedContent;

        public readonly Item SigningKeyVersion;

        public readonly Item Signature;
    }
}
