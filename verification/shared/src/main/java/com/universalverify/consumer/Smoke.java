package com.universalverify.consumer;

import com.universalverify.trustedissuerregistry.*;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import okhttp3.*;

/** Exercises the published artifact from Java, using public fixture data and no network. */
public final class Smoke {
    private static String resource(String name) throws Exception {
        try (InputStream input = Smoke.class.getResourceAsStream("/" + name)) {
            if (input == null) throw new AssertionError("Missing fixture: " + name);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            for (int read; (read = input.read(buffer)) >= 0;) output.write(buffer, 0, read);
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Published SDK consumer check failed");
    }

    public static void main(String[] args) throws Exception {
        List<String> providers = Arrays.asList(Arrays.stream(Security.getProviders()).map(p -> p.getName()).toArray(String[]::new));
        String issuer = resource("issuer.pem");
        String leaf = resource("leaf.pem");
        String registryJson = resource("registry-issuer.json");
        OkHttpClient client = new OkHttpClient.Builder().addInterceptor(chain -> {
            String body = chain.request().url().encodedPath().contains("deprecation_notice")
                    ? "{\"version\":\"0.2\",\"end_of_life\":4102444800}" : registryJson;
            return new Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                    .code(200).message("Fixture").body(ResponseBody.create(body, MediaType.get("application/json"))).build();
        }).build();
        RegistryOptions options = RegistryOptions.builder().addTrustedIssuerCertificate(issuer)
                .timeout(Duration.ofSeconds(10)).cacheTtl(Duration.ofHours(24)).build();
        try (Registry registry = new Registry(options, client)) {
            require("0.2".equals(Registry.minorVersion));
            require(Certificates.verifyCertificateSignature(leaf, issuer));
            require(leaf.equals(Certificates.certificateToPem(Certificates.parsePemCertificate(leaf))));
            require(registry.resolveCertificateTrustBlocking(leaf).getTrusted());
            require(registry.resolveCertificateTrustAsync(Certificates.parsePemCertificate(leaf)).get().getTrusted());
            require(!registry.resolveCertificateTrustBlocking().getTrusted());
            require(registry.getIssuerFromX509AKIBlocking("fixture").getSignature() != null);
            require(registry.getIssuerFromX509AKIAsync("fixture").get().getSignature() != null);
            require(Instant.parse("2100-01-01T00:00:00Z").equals(registry.getEndOfLifeDateBlocking()));
            require(registry.getEndOfLifeDateAsync().get().equals(registry.getEndOfLifeDateBlocking()));
        } finally {
            require(!client.dispatcher().executorService().isShutdown());
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
        RegistrySnapshot snapshot = RegistrySnapshot.fromJson("{\"version\":\"informational\",\"issuers\":[" + registryJson + "]}");
        Matcher identifier = Pattern.compile("\"issuer_id\"\\s*:\\s*\"x509_aki:([A-Za-z0-9_-]+)\"").matcher(registryJson);
        require(identifier.find());
        String aki = identifier.group(1);
        OkHttpClient offline = new OkHttpClient.Builder().addInterceptor(chain -> {
            throw new AssertionError("Snapshot attempted a network request: " + chain.request().url());
        }).build();
        try (Registry registry = new Registry(RegistryOptions.builder().registrySnapshot(snapshot)
                .addTrustedIssuerCertificate(issuer).cacheEnabled(false).build(), offline)) {
            require("informational".equals(snapshot.getVersion()));
            require(registry.getIssuerFromX509AKIBlocking(aki).getSignature() != null);
            require(registry.getIssuerFromX509AKIAsync(aki).get().getSignature() != null);
            require(registry.getIssuerFromX509AKIBlocking("missing") == null);
            require(registry.getEndOfLifeDateBlocking() == null);
            require(registry.getEndOfLifeDateAsync().get() == null);
            require(registry.resolveCertificateTrustBlocking(leaf,
                    ResolveCertificateTrustOptions.builder().addTrustList(TrustList.UV).build()).getTrusted());
            require(registry.resolveCertificateTrustAsync(leaf).get().getTrusted());
            String tampered = registryJson.replaceFirst("\"entity_type\"", "\"tampered_entity_type\"");
            RegistrySnapshot invalid = RegistrySnapshot.fromJson("{\"issuers\":[" + tampered + "]}");
            try (Registry rejected = new Registry(RegistryOptions.builder().registrySnapshot(invalid).build(), offline)) {
                try {
                    rejected.getIssuerFromX509AKIAsync(aki).get();
                    throw new AssertionError("Tampered snapshot signature was accepted");
                } catch (java.util.concurrent.ExecutionException error) {
                    require(error.getCause() instanceof RegistryException);
                    require(((RegistryException) error.getCause()).getCategory() == RegistryErrorCategory.CRYPTOGRAPHIC_ERROR);
                }
            }
        } finally {
            require(!offline.dispatcher().executorService().isShutdown());
            offline.dispatcher().executorService().shutdown();
            offline.connectionPool().evictAll();
        }
        require(providers.equals(Arrays.asList(Arrays.stream(Security.getProviders()).map(p -> p.getName()).toArray(String[]::new))));
        System.out.println("Published Java consumer passed");
    }
}
