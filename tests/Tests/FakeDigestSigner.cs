namespace NewOrbit.DataProtection.Tests
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using Moq;
    using NewOrbit.DataProtection;
    using Shouldly;
    using Xunit;

    public class FakeDigestSigner : IDigestSigner
    {
        private static byte[] staticKeyIdentifier = System.Text.Encoding.ASCII.GetBytes("ABCdefghijklmnopqrstuvwxyzABCdeg");

        public void Sign(in ReadOnlySpan<byte> digest, string algorithm, in Span<byte> writeSignatureToThisSpan, in Span<byte> writeKeyIdentifierToThisSpan)
        {
            digest.Length.ShouldBe(64);
            algorithm.ShouldBe("RS512");
            writeSignatureToThisSpan.Length.ShouldBe(128 / 8);
            writeKeyIdentifierToThisSpan.Length.ShouldBe(32);

            staticKeyIdentifier.CopyTo(writeKeyIdentifierToThisSpan);

            digest[..writeSignatureToThisSpan.Length].CopyTo(writeSignatureToThisSpan);

            writeSignatureToThisSpan.Reverse();
        }

        public bool Verify(in ReadOnlySpan<byte> digest, string algorithm, in ReadOnlySpan<byte> signature, in ReadOnlySpan<byte> keyIdentifier)
        {
            digest.Length.ShouldBe(64);
            algorithm.ShouldBe("RS512");
            signature.Length.ShouldBe(128 / 8);
            keyIdentifier.Length.ShouldBe(32);
            keyIdentifier.SequenceEqual(staticKeyIdentifier).ShouldBeTrue();

            var temp = digest[..signature.Length].ToArray().AsSpan();
            temp.Reverse();

            return temp.SequenceEqual(signature);
        }
    }
}
