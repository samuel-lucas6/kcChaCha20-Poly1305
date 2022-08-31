using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;
using kcAEAD;

namespace kcAEADTests;

[TestClass]
public class kcChaCha20Poly1305Tests
{
    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    [TestMethod]
    public void EncryptTestVector()
    {
        Span<byte> ciphertext = Convert.FromHexString("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
        Span<byte> plaintext = Convert.FromHexString("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        Span<byte> nonce = Convert.FromHexString("070000004041424344454647");
        Span<byte> key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        Span<byte> associatedData = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
        
        Span<byte> encrypted = new byte[kcChaCha20Poly1305.CommitmentSize + ciphertext.Length];
        kcChaCha20Poly1305.Encrypt(encrypted, plaintext, nonce, key, associatedData);
        Assert.IsTrue(encrypted[kcChaCha20Poly1305.CommitmentSize..].SequenceEqual(ciphertext));
        Assert.IsFalse(encrypted[..kcChaCha20Poly1305.CommitmentSize].SequenceEqual(new byte[kcChaCha20Poly1305.CommitmentSize]));
        
        Span<byte> decrypted = new byte[plaintext.Length];
        kcChaCha20Poly1305.Decrypt(decrypted, encrypted, nonce, key, associatedData);
        Assert.IsTrue(decrypted.SequenceEqual(plaintext));
    }
    
    // https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.5 but prepended commitment to ciphertext
    [TestMethod]
    public void DecryptTestVector()
    {
        Span<byte> plaintext = Convert.FromHexString("496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d");
        Span<byte> ciphertext = Convert.FromHexString("14e5b1110fccbaa015608a82815482d750a8a4e8d6bbdcd93ae32d4c12d9ccf864a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38");
        Span<byte> nonce = Convert.FromHexString("000000000102030405060708");
        Span<byte> key = Convert.FromHexString("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        Span<byte> associatedData = Convert.FromHexString("f33388860000000000004e91");
        
        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        kcChaCha20Poly1305.Decrypt(decrypted, ciphertext, nonce, key, associatedData);
        Assert.IsTrue(decrypted.SequenceEqual(plaintext));
        
        Span<byte> encrypted = stackalloc byte[ciphertext.Length];
        kcChaCha20Poly1305.Encrypt(encrypted, plaintext, nonce, key, associatedData);
        Assert.IsTrue(encrypted.SequenceEqual(ciphertext));
    }
    
    [TestMethod]
    public void DecryptWrongParameters()
    {
        byte[] plaintext = Convert.FromHexString("496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d");
        byte[] ciphertext = Convert.FromHexString("14e5b1110fccbaa015608a82815482d750a8a4e8d6bbdcd93ae32d4c12d9ccf864a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38");
        byte[] nonce = Convert.FromHexString("000000000102030405060708");
        byte[] key = Convert.FromHexString("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        byte[] associatedData = Convert.FromHexString("f33388860000000000004e91");
        var decrypted = new byte[plaintext.Length];
        
        var wrongCommitment = ciphertext.ToArray();
        wrongCommitment[0]++;
        Assert.ThrowsException<CryptographicException>(() => kcChaCha20Poly1305.Decrypt(decrypted, wrongCommitment, nonce, key, associatedData));
        
        var wrongTag = ciphertext.ToArray();
        wrongTag[^1]++;
        Assert.ThrowsException<CryptographicException>(() => kcChaCha20Poly1305.Decrypt(decrypted, wrongTag, nonce, key, associatedData));
        
        var wrongCiphertext = ciphertext.ToArray();
        wrongCiphertext[kcChaCha20Poly1305.CommitmentSize + 1]++;
        Assert.ThrowsException<CryptographicException>(() => kcChaCha20Poly1305.Decrypt(decrypted, wrongCiphertext, nonce, key, associatedData));
        
        var wrongNonce = nonce.ToArray();
        wrongNonce[0]++;
        Assert.ThrowsException<CryptographicException>(() => kcChaCha20Poly1305.Decrypt(decrypted, ciphertext, wrongNonce, key, associatedData));
        
        var wrongKey = key.ToArray();
        wrongKey[0]++;
        Assert.ThrowsException<CryptographicException>(() => kcChaCha20Poly1305.Decrypt(decrypted, ciphertext, nonce, wrongKey, associatedData));
        
        var wrongAssociatedData = associatedData.ToArray();
        wrongAssociatedData[0]++;
        Assert.ThrowsException<CryptographicException>(() => kcChaCha20Poly1305.Decrypt(decrypted, ciphertext, nonce, key, wrongAssociatedData));
        Assert.ThrowsException<CryptographicException>(() => kcChaCha20Poly1305.Decrypt(decrypted, ciphertext, nonce, key));
    }
    
    // Against libsodium
    [TestMethod]
    public void NoPlaintextOrAssociatedData()
    {
        Span<byte> plaintext = Span<byte>.Empty;
        Span<byte> nonce = stackalloc byte[kcChaCha20Poly1305.NonceSize];
        Span<byte> key = stackalloc byte[kcChaCha20Poly1305.KeySize];
        Span<byte> associatedData = Span<byte>.Empty;
        
        Span<byte> ciphertext = stackalloc byte[plaintext.Length + kcChaCha20Poly1305.TagSize];
        ChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
        
        Span<byte> encrypted = stackalloc byte[kcChaCha20Poly1305.CommitmentSize + ciphertext.Length];
        kcChaCha20Poly1305.Encrypt(encrypted, plaintext, nonce, key, associatedData);
        Assert.IsTrue(encrypted[kcChaCha20Poly1305.CommitmentSize..].SequenceEqual(ciphertext));
        
        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        kcChaCha20Poly1305.Decrypt(decrypted, encrypted, nonce, key, associatedData);
        Assert.IsTrue(decrypted.SequenceEqual(plaintext));
    }
    
    [TestMethod]
    public void OnlyAssociatedData()
    {
        Span<byte> plaintext = Span<byte>.Empty;
        Span<byte> nonce = stackalloc byte[kcChaCha20Poly1305.NonceSize];
        Span<byte> key = stackalloc byte[kcChaCha20Poly1305.KeySize];
        Span<byte> associatedData = stackalloc byte[kcChaCha20Poly1305.CommitmentSize];
        
        Span<byte> ciphertext = stackalloc byte[plaintext.Length + kcChaCha20Poly1305.TagSize];
        ChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
        
        Span<byte> encrypted = stackalloc byte[kcChaCha20Poly1305.CommitmentSize + ciphertext.Length];
        kcChaCha20Poly1305.Encrypt(encrypted, plaintext, nonce, key, associatedData);
        Assert.IsTrue(encrypted[kcChaCha20Poly1305.CommitmentSize..].SequenceEqual(ciphertext));
        
        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        kcChaCha20Poly1305.Decrypt(decrypted, encrypted, nonce, key, associatedData);
        Assert.IsTrue(decrypted.SequenceEqual(plaintext));
    }
    
    [TestMethod]
    public void OnlyPlaintext()
    {
        Span<byte> plaintext = stackalloc byte[kcChaCha20Poly1305.CommitmentSize];
        Span<byte> nonce = stackalloc byte[kcChaCha20Poly1305.NonceSize];
        Span<byte> key = stackalloc byte[kcChaCha20Poly1305.KeySize];
        
        Span<byte> ciphertext = stackalloc byte[plaintext.Length + kcChaCha20Poly1305.TagSize];
        ChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key);
        
        Span<byte> encrypted = stackalloc byte[kcChaCha20Poly1305.CommitmentSize + ciphertext.Length];
        kcChaCha20Poly1305.Encrypt(encrypted, plaintext, nonce, key);
        Assert.IsTrue(encrypted[kcChaCha20Poly1305.CommitmentSize..].SequenceEqual(ciphertext));
        
        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        kcChaCha20Poly1305.Decrypt(decrypted, encrypted, nonce, key);
        Assert.IsTrue(decrypted.SequenceEqual(plaintext));
    }
}