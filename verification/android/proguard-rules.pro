# Retain only the driver entry points. R8 optimizes the SDK and the checks' dependencies.
-keep class com.universalverify.consumer.Smoke { public static void main(java.lang.String[]); }
-keep class com.universalverify.consumer.AndroidChecks { public static void signatureVectors(android.content.Context); }
-keep class com.universalverify.consumer.AndroidChecks { public static void validationRegressions(android.content.Context); }
