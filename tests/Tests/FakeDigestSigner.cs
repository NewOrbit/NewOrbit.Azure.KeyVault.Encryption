namespace NewOrbit.DataProtection.Tests
{
    using System;
    using System.Security.Cryptography;
    using Moq;
    using NewOrbit.DataProtection;
    using Shouldly;
    using Xunit;

    public class FakeDigestSigner : IDigestSigner
    {
        private static byte[] staticKeyIdentifier;

        static FakeDigestSigner()
        {
            staticKeyIdentifier = System.Text.Encoding.ASCII.GetBytes("ABCdefghijklmnopqrstuvwxyzABCdeg");
        }

        public void Sign(in ReadOnlySpan<byte> digest, string algorithm, in Span<byte> writeSignatureToThisSpan)
        {
            digest.Length.ShouldBe(64);
            algorithm.ShouldBe("RS512");
            writeSignatureToThisSpan.Length.ShouldBe(128 / 8);

            // TODO: Fix the size mismatch
            digest.CopyTo(writeSignatureToThisSpan);

            writeSignatureToThisSpan.Reverse();
        }

        public bool Verify(in ReadOnlySpan<byte> digest, string algorithm, in ReadOnlySpan<byte> signature)
        {
            digest.Length.ShouldBe(64);
            algorithm.ShouldBe("RS512");
            signature.Length.ShouldBe(128 / 8);

            var temp = signature.ToArray().AsSpan();
            temp.Reverse();
            var recoveredSignature = temp.Slice(0, 64);

            return digest.SequenceEqual(recoveredSignature);
        }
    }
}
