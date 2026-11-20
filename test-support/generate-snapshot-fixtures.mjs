// Development-only JS oracle. Kotlin builds and CI consume only the committed JSON.
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFile, readdir, writeFile } from 'node:fs/promises';

const jsRoot = new URL('../../js/', import.meta.url);
const sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: jsRoot, encoding: 'utf8' }).trim();
if(execFileSync('git', ['status', '--porcelain'], { cwd: jsRoot, encoding: 'utf8' }).trim()) {
    throw new Error('Use a clean, reviewed JS checkout so fixture provenance identifies the actual source');
}
const require = createRequire(new URL('package.json', jsRoot));
const pki = await import(require.resolve('pkijs'));
const asn1 = await import(require.resolve('asn1js'));
const { default: canonical } = await import(require.resolve('canonical-json'));
const sdk = await import(new URL('scripts/trusted-issuer-registry.js', jsRoot));
const helpers = await import(new URL('scripts/certificate-helper.js', jsRoot));
helpers.ensurePKIjsCryptoEngine();
const runtime = JSON.parse(await readFile(new URL('../src/test/resources/fixtures/runtime.json', import.meta.url), 'utf8'));
const issuer = JSON.parse(await readFile(new URL('issuers/x509_aki/rX7vmMbQz-Qkb83hZ7xXO4PRJKA.json', jsRoot), 'utf8'));
const records = await Promise.all((await readdir(new URL('issuers/x509_aki/', jsRoot)))
    .filter(name => name.endsWith('.json')).sort()
    .map(async name => JSON.parse(await readFile(new URL(`issuers/x509_aki/${name}`, jsRoot), 'utf8'))));
const tombstone = records.find(record => record.certificates.length === 0);
if(!tombstone) throw new Error('Expected a signed issuer without certificates');
const now = '2026-11-20T00:00:00Z';
const NativeDate = Date;
globalThis.Date = class extends NativeDate {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return new NativeDate(now).getTime(); }
};
const certificates = { issuer: issuer.certificates[0].data, noAKI: runtime.certificates.noAKI };
const tampered = structuredClone(issuer);
tampered.display.name = 'Forged issuer';
const snapshots = {
    valid: { version: 'informational', issuers: [issuer] },
    empty: { issuers: [] },
    tampered: { issuers: [tampered] },
    tombstone: { issuers: [tombstone] },
};
const normalize = result => ({ ...result, untrustedReasons: result.untrustedReasons ?? [],
    ...(result.issuer && { issuer: { ...result.issuer, certificates: result.issuer.certificates.map(
        certificate => ({ ...certificate, untrustedReasons: certificate.untrustedReasons ?? [] })) } }) });
const cases = [];
const originalFetch = globalThis.fetch;
try {
    for(const scenario of [
        { label: 'signed snapshot', scope: 'government_issued_id' },
        { label: 'empty trust lists', trustLists: [] },
        { label: 'trust list mismatch', trustLists: ['aamva_dts'] },
        { label: 'scope mismatch', scope: 'document_signing' },
        { label: 'missing certificate', input: null },
        { label: 'missing AKI', input: 'noAKI' },
        { label: 'empty snapshot', snapshot: 'empty' },
        { label: 'local issuer and empty snapshot', snapshot: 'empty', custom: ['issuer'] },
        { label: 'local metadata overrides snapshot', custom: [{ data: 'issuer', display: { name: 'Local issuer' },
            trust_scopes: ['document_signing'] }] },
        { label: 'tampered snapshot', snapshot: 'tampered' },
        { label: 'local trust during signature failure', snapshot: 'tampered', custom: ['issuer'] },
        { label: 'local scope failure during signature failure', snapshot: 'tampered', custom: ['issuer'], scope: 'document_signing' },
        { label: 'required CRL remains online', mode: 'required' },
        { label: 'best effort CRL remains online', mode: 'best_effort' },
    ]) {
        const value = { snapshot: 'valid', custom: [], mode: 'skip', trustLists: ['uv'], input: 'issuer', ...scenario };
        let crlRequests = 0;
        globalThis.fetch = async url => {
            if(url.includes('cdn.jsdelivr.net')) throw new Error('Snapshot attempted a CDN request');
            crlRequests++;
            return new Response(null, { status: 404 });
        };
        const registry = new sdk.Registry({ registrySnapshot: snapshots[value.snapshot], cacheEnabled: false,
            trustedIssuerCertificates: value.custom.map(entry => typeof entry === 'string' ? certificates[entry]
                : { ...entry, data: certificates[entry.data] }), revocationCheckMode: value.mode });
        const expected = normalize(await registry.resolveCertificateTrust(value.input === null ? null : certificates[value.input],
            { trustLists: value.trustLists, trustScope: value.scope }));
        cases.push({ ...value, expected, crlRequests });
    }
} finally {
    globalThis.fetch = originalFetch;
    globalThis.Date = NativeDate;
}

// Separate test signing key checks unknown signed fields without requiring the production private key.
const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const dn = new pki.RelativeDistinguishedNames({ typesAndValues: [new pki.AttributeTypeAndValue({
    type: '2.5.4.3', value: new asn1.Utf8String({ value: 'Snapshot fixture signer' }),
})] });
const signing = new pki.Certificate({ version: 2, serialNumber: new asn1.Integer({ value: 1 }), issuer: dn, subject: dn,
    notBefore: new pki.Time({ type: 1, value: new Date('2000-01-01') }),
    notAfter: new pki.Time({ type: 1, value: new Date('2100-01-01') }) });
await signing.subjectPublicKeyInfo.importKey(keys.publicKey);
await signing.sign(keys.privateKey, 'SHA-256');
const { signature: ignoredSignature, ...payload } = issuer;
payload.future = { boolean: true, nested: { z: [false, 1e21, 'é\u2028😀'], a: null } };
const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(canonical(payload)));
const unknownFieldsIssuer = { ...payload, signature: Buffer.from(pki.createCMSECDSASignature(signature)).toString('base64') };
const signingCertificate = sdk.certificateToPem(signing);
if(!await sdk.verifySignatureWithPem(signingCertificate, unknownFieldsIssuer.signature, new TextEncoder().encode(canonical(payload)))) {
    throw new Error('JS did not verify unknown-field fixture');
}
await writeFile(new URL('../src/test/resources/fixtures/snapshot.json', import.meta.url), JSON.stringify({
    sourceCommit, sourceVersion: JSON.parse(await readFile(new URL('package.json', jsRoot), 'utf8')).version,
    now, aki: issuer.issuer_id.slice('x509_aki:'.length), certificates, snapshots, cases,
    signingCertificate, unknownFieldsIssuer,
}, null, 2) + '\n');
console.log(`Wrote ${cases.length} snapshot trust cases from JS ${sourceCommit}`);
