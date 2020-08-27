namespace NewOrbit.Azure.KeyVault.DataProtection
{
    using System;

    public readonly struct ArrayPositionsV1 : IEquatable<ArrayPositionsV1>
    {
        public readonly int TotalLength;

        public readonly Item Version;

        public readonly Item AsymmetricWrapperKeyIdentifier;

        public readonly Item WrappedSymmetricKey;

        public readonly Item InitialisationVector;

        //// Consider adding a text encoding identifier

        public readonly Item EncryptedContent;

        public readonly Item SigningKeyIdentifier;

        public readonly Item Signature;

        private const int RSAKeyLengthBits = Constants.RSAKeySize;
        private const int InitialisationVectorLengthBytes = 16;
        private const int KeyVersionByteLength = 32;

        private ArrayPositionsV1(int encryptedContentLength)
        {
            this.Version              = new Item(0, 1);
            this.AsymmetricWrapperKeyIdentifier = new Item(this.Version, KeyVersionByteLength);
            this.WrappedSymmetricKey        = new Item(this.AsymmetricWrapperKeyIdentifier, RSAKeyLengthBits / 8);
            this.InitialisationVector = new Item(this.WrappedSymmetricKey, InitialisationVectorLengthBytes);
            this.EncryptedContent     = new Item(this.InitialisationVector, encryptedContentLength);
            this.SigningKeyIdentifier    = new Item(this.EncryptedContent, KeyVersionByteLength);
            this.Signature            = new Item(this.SigningKeyIdentifier, RSAKeyLengthBits / 8);
            this.TotalLength          = this.Signature.Position + this.Signature.Length;  // Reminder: this is one higher than the last position in the array
        }

        // All the equality overrides are irrelevant, it's just because structs. Probably easier to make this an object :)
        public static bool operator ==(ArrayPositionsV1 left, ArrayPositionsV1 right) => left.Equals(right);

        public static bool operator !=(ArrayPositionsV1 left, ArrayPositionsV1 right) => !left.Equals(right);

        public static ArrayPositionsV1 Get(int inputArrayLength)
            => new ArrayPositionsV1(((inputArrayLength / 16) + 1) * 16);

        public static ArrayPositionsV1 Get(in ReadOnlySpan<byte> encryptedContent)
            => new ArrayPositionsV1(GetEncryptedContentLengthFromFullPackage(encryptedContent));

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
