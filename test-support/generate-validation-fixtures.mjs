// Development-only JS oracle for certificate/CRL validation regressions.
// Private keys are generated in memory and never written to the fixture.
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
const jsRoot = new URL('../../js/', import.meta.url);
const sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: jsRoot, encoding: 'utf8' }).trim();
const require = createRequire(new URL('package.json', jsRoot));
const asn1 = await import(require.resolve('asn1js'));
const pki = await import(require.resolve('pkijs'));
const sdk = await import(new URL('scripts/trusted-issuer-registry.js', jsRoot));
const helpers = await import(new URL('scripts/certificate-helper.js', jsRoot));
helpers.ensurePKIjsCryptoEngine();
const NativeDate = Date;
const NOW = '2026-10-08T00:00:00Z';
globalThis.Date = class extends NativeDate {
    constructor(...args) { super(...(args.length ? args : [NOW])); }
    static now() { return new NativeDate(NOW).getTime(); }
};
const time = value => new pki.Time({ type: 1, value: new Date(value) });
const identifier = new Uint8Array([1, 2, 3, 4]);
const url = 'https://example.test/issuer.crl';
const ext = (oid, value, critical = false) => new pki.Extension({ extnID: oid, critical,
    extnValue: value.toSchema ? value.toSchema().toBER() : value.toBER() });
const attribute = (type, value, StringType = asn1.Utf8String) => new pki.AttributeTypeAndValue({ type, value: new StringType({ value }) });
const country = attribute('2.5.4.6', 'US', asn1.PrintableString);
const organization = attribute('2.5.4.10', 'Example Authority');
const commonName = attribute('2.5.4.3', 'Root');
function name(attributes, grouped = false) {
    const sets = grouped ? [attributes] : attributes.map(value => [value]);
    const schema = new asn1.Sequence({ value: sets.map(values =>
        new asn1.Set({ value: values.map(value => value.toSchema()) })) });
    // Decode the bytes so PKIjs retains the individual RDN sets when signing.
    return new pki.RelativeDistinguishedNames({ schema: asn1.fromBER(schema.toBER()).result });
}
const issuerName = name([country, organization, commonName]);
const reversedName = name([commonName, organization, country]);
const normalizedName = name([
    attribute('2.5.4.6', '\ufeffus\u00a0'),
    attribute('2.5.4.10', '  EXAMPLE   AUTHORITY  ', asn1.BmpString),
    attribute('2.5.4.3', 'root'),
]);
const organizationName = (value, StringType = asn1.Utf8String) => name([
    country, attribute('2.5.4.10', value, StringType), commonName,
]);
const ignoredNames = {
    softHyphen: organizationName('Example Authority\u00ad'),
    variationSelector: organizationName('Example Authority\ufe0f'),
    graphemeJoiner: organizationName('Exam\u034fple Authority'),
    wordJoiner: organizationName('Example Authority\u2060'),
};
const arabicName = organizationName('هيئة الإصدار');
const arabicStretchedName = organizationName('هـيئة الإصدار');
const hebrewName = organizationName('רשות');
const hebrewMarkedName = organizationName('ר\u0591שות');
const universalName = organizationName('Example Authority', asn1.UniversalString);
const universalUnicodeName = organizationName('Autorité 🏛', asn1.UniversalString);
const universalFallbackName = name([
    country,
    attribute('2.5.4.8', 'US-VA', asn1.UniversalString),
    attribute('2.5.4.3', 'Example Authority', asn1.UniversalString),
]);
const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const rsa = await crypto.subtle.generateKey({ name: 'RSA-PSS', hash: 'SHA-256', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify']);
const certificates = {};
let serial = 1;
async function certificate(label, { issuer = false, issuerDN = issuerName, subjectDN, keyPair = ec, publicKeyAlgorithm } = {}) {
    const extensions = issuer ? [
        ext('2.5.29.14', new asn1.OctetString({ valueHex: identifier })),
        ext('2.5.29.15', new asn1.BitString({ valueHex: new Uint8Array([2]), unusedBits: 1 }), true),
    ] : [
        ext('2.5.29.35', new pki.AuthorityKeyIdentifier({ keyIdentifier: new asn1.OctetString({ valueHex: identifier }) })),
        ext('2.5.29.31', new pki.CRLDistributionPoints({ distributionPoints: [new pki.DistributionPoint({
            distributionPoint: [new pki.GeneralName({ type: 6, value: url })],
        })] })),
    ];
    const value = new pki.Certificate({ version: 2, serialNumber: new asn1.Integer({ value: serial++ }),
        subject: subjectDN ?? (issuer ? issuerName : name([attribute('2.5.4.3', 'Leaf')])), issuer: issuerDN,
        notBefore: time('2000-01-01'), notAfter: time('2100-01-01'), extensions });
    await value.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    if(publicKeyAlgorithm) value.subjectPublicKeyInfo.algorithm = publicKeyAlgorithm;
    await value.sign(keyPair.privateKey, 'SHA-256');
    certificates[label] = sdk.certificateToPem(value);
    return value;
}
await certificate('issuer', { issuer: true });
const leaf = await certificate('leaf');
await certificate('reorderedName', { issuerDN: reversedName });
await certificate('normalizedName', { issuerDN: normalizedName });
for (const [label, issuerDN] of Object.entries(ignoredNames)) await certificate(label, { issuerDN });
for (const [label, subjectDN, issuerDN] of [
    ['arabicIssuer', arabicName, arabicName], ['hebrewIssuer', hebrewName, hebrewName],
    ['universalIssuer', universalName, universalName],
    ['universalUnicodeIssuer', universalUnicodeName, universalUnicodeName],
    ['universalFallbackIssuer', universalFallbackName, universalFallbackName],
]) await certificate(label, { issuer: true, subjectDN, issuerDN });
await certificate('arabicLeaf', { issuerDN: arabicStretchedName });
await certificate('hebrewLeaf', { issuerDN: hebrewMarkedName });
await certificate('universalUnicodeLeaf', { issuerDN: universalUnicodeName });
await certificate('universalFallbackLeaf', { issuerDN: universalFallbackName });
await certificate('pssIssuer', { issuer: true, keyPair: rsa });
const pssLeaf = await certificate('pssLeaf', { keyPair: rsa });
const crls = {};
async function crl(label, { issuerDN = issuerName, extension, revoked = false, keyPair = ec } = {}) {
    const value = new pki.CertificateRevocationList({ version: 1, issuer: issuerDN,
        thisUpdate: time('2000-01-01'), nextUpdate: time('2100-01-01'),
        ...(extension && { crlExtensions: new pki.Extensions({ extensions: [extension] }) }),
        revokedCertificates: revoked ? [new pki.RevokedCertificate({ userCertificate: leaf.serialNumber,
            revocationDate: time('2000-01-01') })] : [] });
    await value.sign(keyPair.privateKey, 'SHA-256');
    crls[label] = Buffer.from(value.toSchema().toBER()).toString('base64');
    return value;
}
await crl('valid');
await crl('unknownCritical', { extension: ext('1.2.3.4.5', new asn1.Integer({ value: 42 }), true) });
await crl('unknownCriticalRevoked', { revoked: true, extension: ext('1.2.3.4.5', new asn1.Integer({ value: 42 }), true) });
await crl('unknownNoncritical', { extension: ext('1.2.3.4.5', new asn1.Integer({ value: 42 })) });
await crl('knownCritical', { extension: ext('2.5.29.20', new asn1.Integer({ value: 42 }), true) });
await crl('reorderedName', { issuerDN: reversedName });
await crl('normalizedName', { issuerDN: normalizedName });
await crl('pssValid', { keyPair: rsa });
const hash = new pki.AlgorithmIdentifier({ algorithmId: '2.16.840.1.101.3.4.2.1', algorithmParams: new asn1.Null() });
const orderedParameters = new pki.RSASSAPSSParams({ hashAlgorithm: hash,
    maskGenAlgorithm: new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.8', algorithmParams: hash.toSchema() }),
    saltLength: 32 }).toSchema();
const reversedParameters = new asn1.Sequence({ value: [...orderedParameters.valueBlock.value].reverse() });
const unorderedAlgorithm = new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.10', algorithmParams: reversedParameters });
async function signMalformed(value) {
    value.signature = unorderedAlgorithm;
    value.signatureAlgorithm = unorderedAlgorithm;
    value.tbsView = new Uint8Array(value.encodeTBS().toBER());
    value.signatureValue = new asn1.BitString({ valueHex: await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, rsa.privateKey, value.tbsView) });
}
await signMalformed(pssLeaf);
certificates.pssOutOfOrder = sdk.certificateToPem(pssLeaf);
const malformedCRL = await crl('pssOutOfOrder', { keyPair: rsa });
await signMalformed(malformedCRL);
crls.pssOutOfOrder = Buffer.from(malformedCRL.toSchema().toBER()).toString('base64');
await certificate('pssKeyOutOfOrder', { issuer: true, keyPair: rsa, publicKeyAlgorithm: unorderedAlgorithm });
const cases = [];
const originalFetch = globalThis.fetch;
async function scenario(label, { input = 'leaf', issuer = 'issuer', mode = 'required', crl = 'valid' } = {}) {
    globalThis.fetch = async () => new Response(Buffer.from(crls[crl], 'base64'));
    const client = new sdk.Registry({ trustedIssuerCertificates: [certificates[issuer]], revocationCheckMode: mode });
    const result = await client.resolveCertificateTrust(certificates[input]);
    const expected = { ...result, untrustedReasons: result.untrustedReasons ?? [], issuer: { ...result.issuer,
        certificates: result.issuer.certificates.map(value => ({ ...value, untrustedReasons: value.untrustedReasons ?? [] })) } };
    cases.push({ label, input, issuer, mode, crl, expected });
}
await scenario('reordered certificate issuer is rejected', { input: 'reorderedName', mode: 'skip' });
await scenario('normalized certificate issuer remains valid', { input: 'normalizedName', mode: 'skip' });
for (const input of Object.keys(ignoredNames)) await scenario(`Unicode collation ${input}`, { input, mode: 'skip' });
await scenario('Arabic stretch mark is ignored', { input: 'arabicLeaf', issuer: 'arabicIssuer', mode: 'skip' });
await scenario('Hebrew cantillation mark is ignored', { input: 'hebrewLeaf', issuer: 'hebrewIssuer', mode: 'skip' });
await scenario('UniversalString organization metadata', { issuer: 'universalIssuer', mode: 'skip' });
await scenario('UniversalString non-ASCII metadata', { input: 'universalUnicodeLeaf', issuer: 'universalUnicodeIssuer', mode: 'skip' });
await scenario('UniversalString common name and region metadata', { input: 'universalFallbackLeaf', issuer: 'universalFallbackIssuer', mode: 'skip' });
for(const mode of ['required', 'best_effort']) {
    await scenario(`${mode} unknown critical CRL`, { mode, crl: 'unknownCritical' });
    await scenario(`${mode} unknown critical revoked CRL`, { mode, crl: 'unknownCriticalRevoked' });
}
for(const crl of ['valid', 'knownCritical', 'unknownNoncritical', 'reorderedName', 'normalizedName']) {
    await scenario(`CRL ${crl}`, { crl });
}
await scenario('ordered PSS certificate and CRL remain valid', { input: 'pssLeaf', issuer: 'pssIssuer', crl: 'pssValid' });
await scenario('out-of-order PSS certificate is rejected', { input: 'pssOutOfOrder', issuer: 'pssIssuer', mode: 'skip' });
await scenario('out-of-order PSS CRL is undetermined', { input: 'pssLeaf', issuer: 'pssIssuer', crl: 'pssOutOfOrder' });
await scenario('out-of-order PSS-only key is rejected', { input: 'pssLeaf', issuer: 'pssKeyOutOfOrder', mode: 'skip' });
const certificateSignatures = [];
for(const [input, issuer] of [['leaf','issuer'], ['reorderedName','issuer'], ['normalizedName','issuer'],
    ...Object.keys(ignoredNames).map(input => [input, 'issuer']),
    ['arabicLeaf','arabicIssuer'], ['hebrewLeaf','hebrewIssuer'], ['leaf','universalIssuer'],
    ['universalUnicodeLeaf','universalUnicodeIssuer'], ['universalFallbackLeaf','universalFallbackIssuer'],
    ['pssLeaf','pssIssuer'], ['pssOutOfOrder','pssIssuer'], ['pssLeaf','pssKeyOutOfOrder']]) {
    certificateSignatures.push({ input, issuer, expected: await sdk.verifyCertificateSignature(certificates[input], certificates[issuer]) });
}
const nameComparisons = [];
function compare(label, left, right) {
    nameComparisons.push({ label, left: Buffer.from(left.toSchema().toBER()).toString('base64'),
        right: Buffer.from(right.toSchema().toBER()).toString('base64'), expected: left.isEqual(right) });
}
compare('ordered names', issuerName, issuerName);
compare('reordered attributes', issuerName, reversedName);
compare('case whitespace and string encoding', issuerName, normalizedName);
compare('grouping is flattened', name([country, organization]), name([country, organization], true));
compare('canonical Unicode', name([attribute('2.5.4.3', 'é')]), name([attribute('2.5.4.3', 'e\u0301')]));
compare('different Unicode', name([attribute('2.5.4.3', 'é')]), name([attribute('2.5.4.3', 'e')]));
compare('UniversalString text', name([attribute('2.5.4.3', 'Authority', asn1.UniversalString)]), name([attribute('2.5.4.3', 'authority')]));
for (const [label, right] of Object.entries(ignoredNames)) compare(`Unicode collation ${label}`, issuerName, right);
compare('Arabic stretch mark', arabicName, arabicStretchedName);
compare('Hebrew cantillation mark', hebrewName, hebrewMarkedName);
compare('fullwidth text remains distinct', name([attribute('2.5.4.3', 'a')]), name([attribute('2.5.4.3', 'ａ')]));
compare('punctuation remains distinct', name([attribute('2.5.4.3', 'ab')]), name([attribute('2.5.4.3', 'a-b')]));
compare('nonstring attributes', name([new pki.AttributeTypeAndValue({ type: '1.2.3.4', value: new asn1.OctetString({ valueHex: new Uint8Array([1, 2]) }) })]),
    name([new pki.AttributeTypeAndValue({ type: '1.2.3.4', value: new asn1.OctetString({ valueHex: new Uint8Array([1, 2]) }) })]));
compare('string and nonstring differ', name([attribute('1.2.3.4', 'Authority')]),
    name([new pki.AttributeTypeAndValue({ type: '1.2.3.4', value: new asn1.OctetString({ valueHex: new TextEncoder().encode('Authority') }) })]));
globalThis.fetch = originalFetch;
await writeFile(new URL('../src/test/resources/fixtures/validation.json', import.meta.url), JSON.stringify({
    sourceCommit, now: NOW, certificates, crls, cases,
    certificateSignatures, nameComparisons,
}, null, 2) + '\n');
console.log(`Wrote ${cases.length} trust cases, ${certificateSignatures.length} certificate signatures, and ${nameComparisons.length} name comparisons.`);
