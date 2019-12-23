namespace NewOrbit.Azure.KeyVault.DataProtection
{
    using System;

    public readonly struct ArrayPositionsV1 : IEquatable<ArrayPositionsV1>
    {
        public readonly int TotalLength;

        public readonly Item Version;

        public readonly Item EncryptingKeyVersion;

        public readonly Item EncryptingKey;

        public readonly Item InitialisationVector;

        public readonly Item EncryptedContent;

        public readonly Item SigningKeyVersion;

        public readonly Item Signature;

        private const int RSAKeyLengthBits = 2048;
        private const int InitialisationVectorLengthBytes = 16;
        private const int KeyVersionByteLength = 32;

        public ArrayPositionsV1(int inputArrayLength)
            : this(((inputArrayLength / 16) + 1) * 16, true)
        {
        }

        public ArrayPositionsV1(in ReadOnlySpan<byte> encryptedContent)
            : this(GetEncryptedContentLengthFromFullPackage(encryptedContent), true)
        {
        }

        private ArrayPositionsV1(int encryptedContentLength, bool dummyForOverloadOnly)
        {
            this.Version              = new Item(0, 1);
            this.EncryptingKeyVersion = new Item(this.Version, KeyVersionByteLength);
            this.EncryptingKey        = new Item(this.EncryptingKeyVersion, RSAKeyLengthBits / 8);
            this.InitialisationVector = new Item(this.EncryptingKey, InitialisationVectorLengthBytes);
            this.EncryptedContent     = new Item(this.InitialisationVector, encryptedContentLength);
            this.SigningKeyVersion    = new Item(this.EncryptedContent, KeyVersionByteLength);
            this.Signature            = new Item(this.SigningKeyVersion, RSAKeyLengthBits / 8);
            this.TotalLength          = this.Signature.Position + this.Signature.Length;  // Reminder: this is one higher than the last position in the array
        }

        // All the equality overrides are irrelevant, it's just because structs. Probably easier to make this an object :)
        public static bool operator ==(ArrayPositionsV1 left, ArrayPositionsV1 right) => left.Equals(right);

        public static bool operator !=(ArrayPositionsV1 left, ArrayPositionsV1 right) => !left.Equals(right);

        public bool Equals(ArrayPositionsV1 other) => other.TotalLength == this.TotalLength;

        public override bool Equals(object other) => other is ArrayPositionsV1 o && this.Equals(o);

        public override int GetHashCode() => this.TotalLength;

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
    }
}