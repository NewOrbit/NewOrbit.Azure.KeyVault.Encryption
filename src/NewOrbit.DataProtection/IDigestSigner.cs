namespace NewOrbit.DataProtection;
using System;

public interface IDigestSigner
{
    public void Sign(in ReadOnlySpan<byte> digest, string algorithm, in Span<byte> writeSignatureToThisSpan, in Span<byte> writeKeyIdentifierToThisSpan);

    public bool Verify(in ReadOnlySpan<byte> digest, string algorithm, in ReadOnlySpan<byte> signature, in ReadOnlySpan<byte> keyIdentifier);
}
