package com.universalverify.trustedissuerregistry

import com.universalverify.trustedissuerregistry.internal.cryptoProvider
import com.universalverify.trustedissuerregistry.internal.pemEncode
import okhttp3.Interceptor
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509v2CRLBuilder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.time.Instant
import java.util.Base64
import java.util.Date

class PssKeyTest {
    @Test
    fun `restricted PSS-only keys verify data certificates and CRLs without rewriting`() {
        val generator = KeyPairGenerator.getInstance("RSA", cryptoProvider)
        generator.initialize(2048)
        val pair = generator.generateKeyPair()
        val ordinary = SubjectPublicKeyInfo.getInstance(pair.public.encoded)
        val hash = AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE)
        val restrictions = RSASSAPSSparams(hash, AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hash), ASN1Integer(32), ASN1Integer(1))
        val restricted =
            SubjectPublicKeyInfo(AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, restrictions), ordinary.parsePublicKey())
        val signer = JcaContentSignerBuilder("SHA256withRSAandMGF1").setProvider(cryptoProvider).build(pair.private)
        val name = X500Name("CN=PSS issuer")
        val before = Date.from(Instant.parse("2000-01-01T00:00:00Z"))
        val after = Date.from(Instant.parse("2100-01-01T00:00:00Z"))
        val ski = byteArrayOf(1, 2, 3, 4)
        val issuer =
            X509v3CertificateBuilder(name, BigInteger.ONE, before, after, name, restricted)
                .addExtension(Extension.subjectKeyIdentifier, false, SubjectKeyIdentifier(ski))
                .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.cRLSign))
                .build(signer)
        val uri = GeneralName(GeneralName.uniformResourceIdentifier, "https://example.test/issuer.crl")
        val points = CRLDistPoint(arrayOf(DistributionPoint(DistributionPointName(GeneralNames(uri)), null, null)))
        val leaf =
            X509v3CertificateBuilder(name, BigInteger.TWO, before, after, X500Name("CN=Leaf"), ordinary)
                .addExtension(Extension.authorityKeyIdentifier, false, AuthorityKeyIdentifier(ski))
                .addExtension(Extension.cRLDistributionPoints, false, points)
                .build(signer)
        val crl = X509v2CRLBuilder(name, before).setNextUpdate(after).build(signer)
        val issuerPem = pemEncode(issuer.encoded)
        val leafPem = pemEncode(leaf.encoded)
        assertEquals(issuerPem, certificateToPem(parsePemCertificate(issuerPem)))
        assertTrue(verifyCertificateSignature(issuerPem, issuerPem))
        assertTrue(verifyCertificateSignature(leafPem, issuerPem))
        withClient(Interceptor { chain -> response(chain.request(), crl.encoded) }) { client ->
            val options = RegistryOptions(listOf(UserTrustedIssuerCertificate(issuerPem)), RevocationCheckMode.REQUIRED)
            Registry(options, client).use { registry ->
                val result = registry.resolveCertificateTrustBlocking(leafPem)
                assertTrue(result.trusted)
                assertEquals(
                    RevocationStatus.NOT_REVOKED,
                    result.issuer!!
                        .certificates
                        .single()
                        .revocationStatus,
                )
            }
        }
        val data = "PSS restrictions".toByteArray()

        fun signature(salt: Int): String {
            val signature = Signature.getInstance("RSASSA-PSS", cryptoProvider)
            signature.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, salt, 1))
            signature.initSign(pair.private)
            signature.update(data)
            return Base64.getEncoder().encodeToString(signature.sign())
        }
        assertTrue(verifySignatureWithPem(issuerPem, signature(80), data, SignatureVerificationOptions.RsaPss(HashAlgorithm.SHA256, 80)))
        for (options in listOf(
            SignatureVerificationOptions.RsaPss(HashAlgorithm.SHA256, 0),
            SignatureVerificationOptions.RsaPss(HashAlgorithm.SHA384, 48),
            SignatureVerificationOptions.RsaPkcs1v15(HashAlgorithm.SHA256),
        )) {
            assertEquals(
                RegistryErrorCategory.UNSUPPORTED_ALGORITHM,
                assertThrows(RegistryException::class.java) {
                    verifySignatureWithPem(issuerPem, signature(32), data, options)
                }.category,
            )
        }
        assertThrows(RegistryException::class.java) {
            verifySignatureWithPem(issuerPem, signature(32), data, SignatureVerificationOptions.RsaPss(HashAlgorithm.SHA256, Int.MAX_VALUE))
        }
    }
}
