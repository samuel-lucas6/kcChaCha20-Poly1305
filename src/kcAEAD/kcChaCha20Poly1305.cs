/*
    kcChaCha20Poly1305: Key-committing ChaCha20-Poly1305.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Buffers.Binary;
using System.Security.Cryptography;
using Geralt;

namespace kcAEAD;

public static class kcChaCha20Poly1305
{
    public const int KeySize = ChaCha20.KeySize;
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = Poly1305.TagSize;
    public const int CommitmentSize = 32;
    private const int AlignSize = 16;
    private const int UInt64BytesLength = 8;
    private const uint Counter = 1;
    
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length != CommitmentSize + plaintext.Length + Poly1305.TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {CommitmentSize + plaintext.Length + Poly1305.TagSize} bytes long."); }
        
        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Fill(block0, nonce, key);
        Span<byte> macKey = block0[..Poly1305.KeySize];
        Span<byte> commitment = block0[macKey.Length..];
        commitment.CopyTo(ciphertext[..commitment.Length]);
        
        Span<byte> ciphertextNoTag = ciphertext[commitment.Length..^Poly1305.TagSize];
        ChaCha20.Encrypt(ciphertextNoTag, plaintext, nonce, key, Counter);
        
        ComputeTag(ciphertext[^Poly1305.TagSize..], associatedData, ciphertextNoTag, macKey);
        CryptographicOperations.ZeroMemory(macKey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length < CommitmentSize + Poly1305.TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {CommitmentSize + Poly1305.TagSize} bytes long."); }
        if (plaintext.Length != ciphertext.Length - Poly1305.TagSize - CommitmentSize) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - Poly1305.TagSize - CommitmentSize} bytes long."); }
        
        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Fill(block0, nonce, key);
        Span<byte> macKey = block0[..Poly1305.KeySize];
        Span<byte> commitment = block0[macKey.Length..];
        
        ReadOnlySpan<byte> ciphertextNoTag = ciphertext[commitment.Length..^Poly1305.TagSize];
        
        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        ComputeTag(tag, associatedData, ciphertextNoTag, macKey);
        CryptographicOperations.ZeroMemory(macKey);
        
        bool valid = ConstantTime.Equals(tag, ciphertext[^Poly1305.TagSize..]);
        valid &= ConstantTime.Equals(commitment, ciphertext[..commitment.Length]);
        
        CryptographicOperations.ZeroMemory(tag);
        CryptographicOperations.ZeroMemory(commitment);
        
        if (!valid) {
            throw new CryptographicException("Authentication failed.");
        }
        
        ChaCha20.Decrypt(plaintext, ciphertextNoTag, nonce, key, Counter);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding1 = stackalloc byte[Align(associatedData.Length, AlignSize)];
        Span<byte> padding2 = stackalloc byte[Align(ciphertext.Length, AlignSize)];
        padding1.Clear(); padding2.Clear();
        
        Span<byte> associatedDataLength = stackalloc byte[UInt64BytesLength], ciphertextLength = stackalloc byte[UInt64BytesLength];
        BinaryPrimitives.WriteUInt64LittleEndian(associatedDataLength, (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(ciphertextLength, (ulong)ciphertext.Length);

        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        poly1305.Update(padding1);
        poly1305.Update(ciphertext);
        poly1305.Update(padding2);
        poly1305.Update(associatedDataLength);
        poly1305.Update(ciphertextLength);
        poly1305.Finalize(tag);
    }
    
    private static int Align(int x, int pow2)
    {
        return (~x + 1) & (pow2 - 1);
    }
}