package com.universalverify.consumer;

import android.content.Context;
import com.universalverify.trustedissuerregistry.*;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import okhttp3.*;
import org.json.JSONObject;
import org.json.JSONArray;

/** The checks are compiled with the application so R8 optimizes their SDK calls. */
public final class AndroidChecks {
    private static void require(boolean valid, String message) {
        if (!valid) throw new AssertionError(message);
    }

    private static JSONObject fixtures(Context context, String name) throws Exception {
        try (InputStream input = context.getAssets().open("fixtures/" + name)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            for (int read; (read = input.read(buffer)) >= 0;) output.write(buffer, 0, read);
            return new JSONObject(new String(output.toByteArray(), StandardCharsets.UTF_8));
        }
    }

    public static void signatureVectors(Context context) throws Exception {
        JSONObject fixtures = fixtures(context, "runtime.json");
        JSONObject certificates = fixtures.getJSONObject("certificates");
        byte[] data = Base64.getDecoder().decode(fixtures.getString("signatureData"));
        JSONArray signatures = fixtures.getJSONArray("signatures");
        for (int index = 0; index < signatures.length(); index++) {
            JSONObject vector = signatures.getJSONObject(index);
            HashAlgorithm hash = null;
            for (HashAlgorithm candidate : HashAlgorithm.values()) if (candidate.getAlgorithmName().equals(vector.getString("hash"))) hash = candidate;
            SignatureVerificationOptions options;
            switch (vector.getString("algorithm")) {
                case "ecdsa": options = new SignatureVerificationOptions.Ecdsa(vector.optBoolean("useDefault") ? null : hash); break;
                case "rsaPSS": options = new SignatureVerificationOptions.RsaPss(hash, vector.getInt("saltLength")); break;
                default: options = new SignatureVerificationOptions.RsaPkcs1v15(hash);
            }
            require(Certificates.verifySignatureWithPem(certificates.getString(vector.getString("certificate")), vector.getString("signature"), data, options), vector.toString());
        }
        String pss = certificates.getString("pssOnly");
        require(pss.equals(Certificates.certificateToPem(Certificates.parsePemCertificate(pss))), "PSS encoding changed");
    }

    private static void reasons(List<UntrustedReason> actual, JSONArray expected, String label) throws Exception {
        require(actual.size() == expected.length(), label + ": reason count");
        for (int index = 0; index < actual.size(); index++) {
            require(actual.get(index).getWireValue().equals(expected.getString(index)), label + ": reason " + index);
        }
    }

    private static void trustResult(CertificateTrustResult actual, JSONObject expected, String label) throws Exception {
        require(actual.getTrusted() == expected.getBoolean("trusted"), label + ": trust");
        reasons(actual.getUntrustedReasons(), expected.getJSONArray("untrustedReasons"), label);
        ResolvedIssuer issuer = actual.getIssuer();
        require(issuer != null, label + ": issuer");
        JSONObject expectedIssuer = expected.getJSONObject("issuer");
        require(issuer.getDisplay().getName().equals(expectedIssuer.getJSONObject("display").getString("name")), label + ": display name");
        JSONObject metadata = expectedIssuer.getJSONObject("entity_metadata");
        require(Objects.equals(issuer.getEntityMetadata().getCountry(), metadata.optString("country", null)), label + ": country");
        require(Objects.equals(issuer.getEntityMetadata().getRegion(), metadata.optString("region", null)), label + ": region");
        JSONArray certificates = expectedIssuer.getJSONArray("certificates");
        require(issuer.getCertificates().size() == certificates.length(), label + ": issuer certificates");
        for (int index = 0; index < certificates.length(); index++) {
            ResolvedIssuerCertificate certificate = issuer.getCertificates().get(index);
            JSONObject value = certificates.getJSONObject(index);
            require(certificate.getTrusted() == value.getBoolean("trusted"), label + ": issuer trust");
            require(certificate.getRevocationStatus().getWireValue().equals(value.getString("revocationStatus")), label + ": revocation");
            reasons(certificate.getUntrustedReasons(), value.getJSONArray("untrustedReasons"), label + ": issuer");
        }
    }

    public static void validationRegressions(Context context) throws Exception {
        JSONObject fixtures = fixtures(context, "validation.json");
        JSONObject certificates = fixtures.getJSONObject("certificates");
        JSONArray cases = fixtures.getJSONArray("cases");
        for (int index = 0; index < cases.length(); index++) {
            JSONObject scenario = cases.getJSONObject(index);
            String label = scenario.getString("label");
            byte[] crl = Base64.getDecoder().decode(fixtures.getJSONObject("crls").getString(scenario.getString("crl")));
            RevocationCheckMode mode = null;
            for (RevocationCheckMode candidate : RevocationCheckMode.values()) {
                if (candidate.getWireValue().equals(scenario.getString("mode"))) mode = candidate;
            }
            require(mode != null, label + ": revocation mode");
            RegistryOptions options = RegistryOptions.builder()
                    .addTrustedIssuerCertificate(certificates.getString(scenario.getString("issuer")))
                    .revocationCheckMode(mode).build();
            OkHttpClient client = new OkHttpClient.Builder().addInterceptor(chain ->
                    new Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                            .code(200).message("Fixture").body(ResponseBody.create(crl, MediaType.get("application/pkix-crl"))).build()).build();
            try (Registry registry = new Registry(options, client)) {
                String input = certificates.getString(scenario.getString("input"));
                JSONObject expected = scenario.getJSONObject("expected");
                trustResult(registry.resolveCertificateTrustBlocking(input), expected, label);
                trustResult(registry.resolveCertificateTrustAsync(Certificates.parsePemCertificate(input)).get(), expected, label);
            } finally {
                client.dispatcher().executorService().shutdown();
                client.connectionPool().evictAll();
            }
        }
        JSONArray signatures = fixtures.getJSONArray("certificateSignatures");
        for (int index = 0; index < signatures.length(); index++) {
            JSONObject scenario = signatures.getJSONObject(index);
            String input = certificates.getString(scenario.getString("input"));
            String issuer = certificates.getString(scenario.getString("issuer"));
            boolean expected = scenario.getBoolean("expected");
            require(Certificates.verifyCertificateSignature(input, issuer) == expected, scenario.toString());
            require(Certificates.verifyCertificateSignature(Certificates.parsePemCertificate(input), Certificates.parsePemCertificate(issuer)) == expected,
                    scenario.toString());
        }
    }
}
