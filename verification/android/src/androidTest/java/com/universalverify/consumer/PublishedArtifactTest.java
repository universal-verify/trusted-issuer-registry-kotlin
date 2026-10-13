package com.universalverify.consumer;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import java.io.PrintWriter;
import java.io.StringWriter;

/** A Java-only driver avoids sharing the app's optimized Kotlin runtime with the runner. */
public final class PublishedArtifactTest extends Instrumentation {
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override public void onStart() {
        int failures = run("javaAndCryptoWorkAfterShrinking", 1, () -> Smoke.main(new String[0]));
        failures += run("allJsSignatureVectorsWorkAfterShrinking", 2,
                () -> AndroidChecks.signatureVectors(getTargetContext()));
        failures += run("validationRegressionsMatchJsAfterShrinking", 3,
                () -> AndroidChecks.validationRegressions(getTargetContext()));
        Bundle result = new Bundle();
        result.putString("stream", "\nTests run: 3, failures: " + failures + "\n");
        finish(failures == 0 ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
    }

    private int run(String name, int current, Check check) {
        Bundle status = new Bundle();
        status.putString("id", getClass().getName());
        status.putString("class", "com.universalverify.consumer.PublishedArtifactTest");
        status.putString("test", name);
        status.putInt("numtests", 3);
        status.putInt("current", current);
        sendStatus(1, status);
        try {
            check.run();
            sendStatus(0, status);
            return 0;
        } catch (Throwable error) {
            StringWriter trace = new StringWriter();
            error.printStackTrace(new PrintWriter(trace));
            status.putString("stack", trace.toString());
            sendStatus(-2, status);
            return 1;
        }
    }

    private interface Check { void run() throws Exception; }
}
