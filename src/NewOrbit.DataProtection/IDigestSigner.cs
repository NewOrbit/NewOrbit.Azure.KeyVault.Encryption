namespace NewOrbit.DataProtection;
using System;

public interface IDigestSigner
{
    public void Sign(in ReadOnlySpan<byte> digest, string algorithm, in Span<byte> writeSignatureToThisSpan);

    public bool Verify(in ReadOnlySpan<byte> digest, string algorithm, in ReadOnlySpan<byte> signature);
}
