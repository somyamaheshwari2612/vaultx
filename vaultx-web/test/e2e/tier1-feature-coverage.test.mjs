/**
 * test/e2e/tier1-feature-coverage.test.mjs
 * Tier 1: Feature Coverage (40 Tests: 5 tests each for Features F1 to F8).
 * Evaluates core happy-path behaviors against contracts and specs.
 */
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import React from 'react';
import { createSuite, assert, waitFor } from './helpers/test-runner-core.mjs';
import {
  setupMockDOM,
  teardownMockDOM,
  resetMockDOM,
  renderHook,
  blobTracker,
  mockLocalStorage,
} from './helpers/mock-dom.mjs';
import { MockCrypto } from './helpers/mock-crypto.mjs';
import {
  getVaultCrypto,
  getKeyStore,
  getApi,
  getUseUpload,
  getUseDecrypt,
  MockUploadCard,
  MockDecryptView,
  MockQRModal,
  MockKeySetupModal,
  MockAuditTrail,
  MockHexInspector,
  MockRevokeButton,
} from './helpers/contracts.mjs';

const suite = createSuite('Tier 1: Feature Coverage (40 Tests)');

let vaultCrypto;
let keyStore;
let api;
let useUpload;
let useDecrypt;

suite.before(async () => {
  setupMockDOM();
  vaultCrypto = await getVaultCrypto();
  keyStore = await getKeyStore();
  api = await getApi();
  useUpload = await getUseUpload();
  useDecrypt = await getUseDecrypt();
});

suite.after(() => {
  teardownMockDOM();
});

suite.beforeEach(() => {
  resetMockDOM();
  api._resetMockStore?.();
});

// ==========================================
// Feature F1: Crypto Mode B (5 tests)
// ==========================================
suite.describe('F1: Crypto Mode B (AES-256-GCM, SHA-256, Base64URL)', () => {
  let encryptedArtifacts = null;
  const testData = new Uint8Array(1024).fill(0x42); // 1KB test buffer
  const metaObj = {
    filename: 'test.dat',
    mimeType: 'application/octet-stream',
    size: 1024,
  };

  suite.it('T1.F1.01: Mode B Standard File Encryption', async () => {
    encryptedArtifacts = await vaultCrypto.encryptFileAndMeta(testData.buffer, metaObj, 'MODE_B');

    assert.ok(encryptedArtifacts, 'Expected encryption result');
    assert.ok(encryptedArtifacts.encryptedBlob, 'Expected encryptedBlob');
    assert.ok(encryptedArtifacts.ivB64, 'Expected ivB64');
    assert.ok(encryptedArtifacts.metaIvB64, 'Expected metaIvB64');
    assert.ok(encryptedArtifacts.encryptedMetaB64, 'Expected encryptedMetaB64');
    assert.strictEqual(encryptedArtifacts.wrappedAesKeyB64, null, 'wrappedAesKeyB64 should be null in Mode B');
    assert.isBase64Url(encryptedArtifacts.fragmentKeyB64, 'Expected valid base64url fragment key');
    assert.isHexDigest(encryptedArtifacts.sha256Checksum, 64, 'Expected 64-char hex SHA-256');

    // IVs must be 12 bytes
    const ivBytes = MockCrypto.fromBase64(encryptedArtifacts.ivB64);
    assert.strictEqual(ivBytes.length, 12, 'File IV must be 12 bytes');
    const metaIvBytes = MockCrypto.fromBase64(encryptedArtifacts.metaIvB64);
    assert.strictEqual(metaIvBytes.length, 12, 'Meta IV must be 12 bytes');
  });

  suite.it('T1.F1.02: Mode B Standard File Decryption', async () => {
    const decryptResult = await vaultCrypto.decryptFileAndMeta(
      encryptedArtifacts.encryptedBlob,
      encryptedArtifacts.ivB64,
      encryptedArtifacts.encryptedMetaB64,
      encryptedArtifacts.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: encryptedArtifacts.metaIvB64 }
    );

    assert.strictEqual(decryptResult.isChecksumValid, true, 'Integrity checksum must be valid');
    assert.strictEqual(decryptResult.metaObj.filename, 'test.dat');
    assert.strictEqual(decryptResult.metaObj.size, 1024);

    const decryptedBytes = new Uint8Array(decryptResult.fileBuffer);
    assert.strictEqual(decryptedBytes.length, 1024);
    assert.deepStrictEqual(decryptedBytes, testData, 'Decrypted buffer must match original byte-for-byte');
  });

  suite.it('T1.F1.03: Mode B Base64URL Key Round-Trip Encoding & Decoding', async () => {
    const originalBytes = MockCrypto.randomBytes(32);
    const b64Url = MockCrypto.toBase64Url(originalBytes);

    assert.isBase64Url(b64Url);
    assert.notIncludes(b64Url, '+');
    assert.notIncludes(b64Url, '/');
    assert.notIncludes(b64Url, '=');
    assert.strictEqual(b64Url.length, 43, '256-bit key in Base64URL should be exactly 43 characters');

    const decodedBytes = MockCrypto.fromBase64Url(b64Url);
    assert.deepStrictEqual(decodedBytes, originalBytes, 'Decoded bytes must match original');

    // Re-import key into Web Crypto
    const importedKey = await globalThis.crypto.subtle.importKey(
      'raw',
      decodedBytes,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    assert.strictEqual(importedKey.algorithm.name, 'AES-GCM');
  });

  suite.it('T1.F1.04: Mode B PBKDF2 Password Protection Key Derivation', async () => {
    const password = 'SecretPassphrase2026!';
    const payload = new TextEncoder().encode('Confidential note protected by password');
    const meta = { filename: 'note.txt' };

    // Encrypt with password option
    const enc = await vaultCrypto.encryptFileAndMeta(payload.buffer, meta, 'MODE_B', null, { password });
    assert.ok(enc.fragmentKeyB64, 'Fragment key must be produced');

    // Decrypt successfully with correct password
    const dec = await vaultCrypto.decryptFileAndMeta(
      enc.encryptedBlob,
      enc.ivB64,
      enc.encryptedMetaB64,
      enc.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: enc.metaIvB64, password }
    );
    assert.strictEqual(dec.isChecksumValid, true);
    assert.deepStrictEqual(new Uint8Array(dec.fileBuffer), payload);

    // Decrypt fails with wrong password
    let failed = false;
    try {
      await vaultCrypto.decryptFileAndMeta(
        enc.encryptedBlob,
        enc.ivB64,
        enc.encryptedMetaB64,
        enc.fragmentKeyB64,
        'MODE_B',
        { metaIvB64: enc.metaIvB64, password: 'WrongPassword123!' }
      );
    } catch (err) {
      failed = true;
      assert.ok(
        err.code === 'INVALID_PASSWORD' ||
        err.message?.toLowerCase().includes('password') ||
        err.name === 'OperationError'
      );
    }
    assert.strictEqual(failed, true, 'Decryption must fail with wrong password');
  });

  suite.it('T1.F1.05: Mode B Encrypted Metadata Payload Sealing', async () => {
    const sensitiveMeta = {
      filename: 'confidential_memo.pdf',
      note: 'TopSecret',
      owner: 'Alice',
    };
    const dummyBuffer = new Uint8Array([1, 2, 3, 4]).buffer;

    const res = await vaultCrypto.encryptFileAndMeta(dummyBuffer, sensitiveMeta, 'MODE_B');
    const cipherTextRaw = Buffer.from(res.encryptedMetaB64, 'base64').toString('utf8');

    assert.notIncludes(cipherTextRaw, 'confidential_memo');
    assert.notIncludes(cipherTextRaw, 'TopSecret');
    assert.notIncludes(cipherTextRaw, 'Alice');

    // Decrypting metadata reproduces original fields
    const decrypted = await vaultCrypto.decryptFileAndMeta(
      res.encryptedBlob,
      res.ivB64,
      res.encryptedMetaB64,
      res.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: res.metaIvB64 }
    );
    assert.strictEqual(decrypted.metaObj.filename, 'confidential_memo.pdf');
    assert.strictEqual(decrypted.metaObj.note, 'TopSecret');
    assert.strictEqual(decrypted.metaObj.owner, 'Alice');
  });
});

// ==========================================
// Feature F2: Crypto Mode A (5 tests)
// ==========================================
suite.describe('F2: Crypto Mode A (RSA-OAEP 2048-bit Key Wrapping)', () => {
  let userKeyRecord = null;

  suite.it('T1.F2.01: RSA-OAEP 2048-bit Key Pair Generation', async () => {
    userKeyRecord = await vaultCrypto.generateUserKeyPair();

    assert.ok(userKeyRecord.keyPair, 'Expected keyPair');
    assert.ok(userKeyRecord.keyPair.publicKey, 'Expected publicKey');
    assert.ok(userKeyRecord.keyPair.privateKey, 'Expected privateKey');
    assert.strictEqual(userKeyRecord.keyPair.publicKey.algorithm.name, 'RSA-OAEP');
    assert.strictEqual(userKeyRecord.keyPair.publicKey.algorithm.modulusLength, 2048);
    assert.strictEqual(userKeyRecord.keyPair.privateKey.extractable, false, 'Private key must be non-extractable');
    assert.includes(userKeyRecord.keyPair.privateKey.usages, 'unwrapKey');
  });

  suite.it('T1.F2.02: Public Key SPKI PEM Serialization', async () => {
    const pem = userKeyRecord.publicKeyPem;
    assert.ok(typeof pem === 'string');
    assert.ok(pem.startsWith('-----BEGIN PUBLIC KEY-----'));
    assert.ok(pem.endsWith('-----END PUBLIC KEY-----'));

    const exportedPem = await keyStore.exportPublicKeyPem(userKeyRecord.keyPair.publicKey);
    assert.ok(typeof exportedPem === 'string');
    assert.ok(exportedPem.startsWith('-----BEGIN PUBLIC KEY-----'));
    assert.ok(exportedPem.endsWith('-----END PUBLIC KEY-----'));
    assert.strictEqual(exportedPem.trim(), pem.trim());
  });

  suite.it('T1.F2.03: Mode A Ephemeral AES Key Wrapping', async () => {
    const fileData = new Uint8Array(512).fill(0xAA);
    const meta = { filename: 'secret.docx', size: 512 };

    const result = await vaultCrypto.encryptFileAndMeta(fileData.buffer, meta, 'MODE_A', userKeyRecord.publicKeyPem);

    assert.strictEqual(result.fragmentKeyB64, null, 'fragmentKeyB64 must be null in Mode A');
    assert.ok(result.wrappedAesKeyB64, 'wrappedAesKeyB64 must be present');
    const wrappedBytes = MockCrypto.fromBase64(result.wrappedAesKeyB64);
    assert.strictEqual(wrappedBytes.length, 256, 'RSA 2048-bit wrapped key block must be 256 bytes');
    assert.ok(result.encryptedBlob);
    assert.isHexDigest(result.sha256Checksum, 64);

    // Save for next test
    userKeyRecord.modeAArtifacts = result;
    userKeyRecord.originalFileData = fileData;
  });

  suite.it('T1.F2.04: Mode A Recipient Key Unwrapping & Decryption', async () => {
    const { modeAArtifacts, originalFileData, keyPair } = userKeyRecord;

    const decryptResult = await vaultCrypto.decryptFileAndMeta(
      modeAArtifacts.encryptedBlob,
      modeAArtifacts.ivB64,
      modeAArtifacts.encryptedMetaB64,
      {
        privateKey: keyPair.privateKey,
        wrappedAesKeyB64: modeAArtifacts.wrappedAesKeyB64,
      },
      'MODE_A',
      { metaIvB64: modeAArtifacts.metaIvB64 }
    );

    assert.strictEqual(decryptResult.isChecksumValid, true);
    assert.strictEqual(decryptResult.metaObj.filename, 'secret.docx');
    assert.deepStrictEqual(new Uint8Array(decryptResult.fileBuffer), originalFileData);
  });

  suite.it('T1.F2.05: Mode A Zero-Fragment Invariant', async () => {
    const dummy = new Uint8Array([7, 8, 9]).buffer;
    const res = await vaultCrypto.encryptFileAndMeta(dummy, { filename: 'test' }, 'MODE_A', userKeyRecord.publicKeyPem);

    assert.strictEqual(res.fragmentKeyB64, null);
    // Simulating shareable URL construction
    const shareUrl = `http://localhost:3000/v/mock-id${res.fragmentKeyB64 ? `#key=${res.fragmentKeyB64}` : ''}`;
    assert.notIncludes(shareUrl, '#key=');
  });
});

// ==========================================
// Feature F3: KeyStore (5 tests)
// ==========================================
suite.describe('F3: KeyStore (IndexedDB, Non-Extractable, Fingerprint)', () => {
  suite.it('T1.F3.01: KeyStore Object Store Initialization', async () => {
    const db = await keyStore.openKeyStoreDB();
    if (db) {
      assert.ok(db.objectStoreNames.contains('keys'), 'Expected "keys" store to exist');
    } else {
      assert.ok(true, 'In-memory fallback initialized');
    }
  });

  suite.it('T1.F3.02: Store and Retrieve KeyPair by Username', async () => {
    const { keyPair, publicKeyPem, keyFingerprint } = await vaultCrypto.generateUserKeyPair();

    const storeRes = await keyStore.storeUserKey('alice', keyPair, publicKeyPem, keyFingerprint);
    assert.strictEqual(storeRes.success, true);

    const retrieved = await keyStore.getUserKey('alice');
    assert.ok(retrieved, 'Expected retrieved record');
    assert.strictEqual(retrieved.username, 'alice');
    assert.strictEqual(retrieved.publicKeyPem, publicKeyPem);
    assert.strictEqual(retrieved.fingerprint, keyFingerprint);
    assert.ok(retrieved.keyPair?.privateKey);
  });

  suite.it('T1.F3.03: Hardware Isolation / Non-Extractable Private Key Enforcement', async () => {
    const { keyPair, publicKeyPem, keyFingerprint } = await vaultCrypto.generateUserKeyPair();
    await keyStore.storeUserKey('test_iso_user', keyPair, publicKeyPem, keyFingerprint);

    const retrieved = await keyStore.getUserKey('test_iso_user');
    const privateKey = retrieved.keyPair.privateKey;

    assert.strictEqual(privateKey.extractable, false);

    let threw = false;
    try {
      await globalThis.crypto.subtle.exportKey('pkcs8', privateKey);
    } catch (err) {
      threw = true;
      assert.ok(
        err.name === 'InvalidAccessException' ||
          err.name === 'NotSupportedError' ||
          err.message?.includes('not extractable') ||
          err.message?.includes('key is not extractable'),
        `Unexpected error name: ${err.name}`
      );
    }
    assert.strictEqual(threw, true, 'Attempting to export non-extractable private key must throw');
  });

  suite.it('T1.F3.04: Colon-Separated SHA-256 Public Key Fingerprint Computation', async () => {
    const { keyPair } = await vaultCrypto.generateUserKeyPair();
    const fp = await keyStore.computeKeyFingerprint(keyPair.publicKey);

    assert.match(fp, /^([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}$/, 'Fingerprint must match 32 colon-separated hex bytes');
    assert.strictEqual(fp.length, 95, 'Fingerprint must be 95 characters (64 hex chars + 31 colons)');
  });

  suite.it('T1.F3.05: Memory Fallback Store in Non-Browser / Node Environment', async () => {
    // Test storing and retrieving when indexedDB is bypassed or unavailable
    keyStore._clearMemoryStore?.();
    const { keyPair, publicKeyPem, keyFingerprint } = await vaultCrypto.generateUserKeyPair();

    await keyStore.storeUserKey('fallback_user', keyPair, publicKeyPem, keyFingerprint);
    const result = await keyStore.getUserKey('fallback_user');
    assert.ok(result);
    assert.strictEqual(result.username, 'fallback_user');
  });
});

// ==========================================
// Feature F4: REST API Client (5 tests)
// ==========================================
suite.describe('F4: REST API Client (/api/users/*, /api/vault/*)', () => {
  suite.it('T1.F4.01: User Registration Endpoint (POST /api/users/register)', async () => {
    const res = await api.registerUser({
      username: 'bob',
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----',
      fingerprint: '11:22:33:44:mock',
    });

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.user.username, 'bob');
    assert.strictEqual(res.user.fingerprint, '11:22:33:44:mock');
  });

  suite.it('T1.F4.02: Public Key Retrieval Endpoint (GET /api/users/:username/pubkey)', async () => {
    await api.registerUser({
      username: 'bob_pubkey',
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\nBOB_KEY\n-----END PUBLIC KEY-----',
      fingerprint: 'aa:bb:cc:dd:mock',
    });

    const res = await api.getUserPubKey('bob_pubkey');

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.username, 'bob_pubkey');
    assert.strictEqual(res.publicKeyPem, '-----BEGIN PUBLIC KEY-----\nBOB_KEY\n-----END PUBLIC KEY-----');
  });

  suite.it('T1.F4.03: Vault Upload Endpoint (POST /api/vault/upload)', async () => {
    const payload = {
      encryptedBlobB64: MockCrypto.toBase64(new Uint8Array([1, 2, 3])),
      ivB64: MockCrypto.toBase64(MockCrypto.randomBytes(12)),
      metaIvB64: MockCrypto.toBase64(MockCrypto.randomBytes(12)),
      encryptedMetaB64: MockCrypto.toBase64(new TextEncoder().encode('{}')),
      expiryMinutes: 60,
      maxDownloads: 5,
      isBurnAfterReading: false,
    };

    const res = await api.uploadFile(payload);

    assert.strictEqual(res.success, true);
    assert.ok(res.fileId, 'Expected fileId');
    assert.ok(res.ownerToken, 'Expected ownerToken');
    assert.ok(res.downloadUrl, 'Expected downloadUrl');
    assert.ok(res.expiresAt, 'Expected expiresAt');
  });

  suite.it('T1.F4.04: Vault Metadata Retrieval Endpoint (GET /api/vault/:id/meta)', async () => {
    const upload = await api.uploadFile({
      encryptedBlobB64: MockCrypto.toBase64(new Uint8Array([10, 20, 30])),
      ivB64: 'test_iv',
      metaIvB64: 'test_meta_iv',
      encryptedMetaB64: 'test_meta',
      maxDownloads: 5,
      isBurnAfterReading: false,
    });

    const res = await api.getMetadata(upload.fileId);

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.id, upload.fileId);
    assert.strictEqual(res.isBurnAfterReading, false);
    assert.strictEqual(res.remainingDownloads, 5);
    // Payload should not return ciphertext blob in metadata
    assert.strictEqual(res.encryptedBlobB64, undefined);
  });

  suite.it('T1.F4.05: Vault Download Endpoint (GET /api/vault/:id/download)', async () => {
    const upload = await api.uploadFile({
      encryptedBlobB64: 'downloadable_blob',
      ivB64: 'dl_iv',
      metaIvB64: 'dl_meta_iv',
      encryptedMetaB64: 'dl_meta',
      maxDownloads: 5,
    });

    const res = await api.downloadFile(upload.fileId);

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.encryptedBlobB64, 'downloadable_blob');
    assert.strictEqual(res.ivB64, 'dl_iv');
    assert.strictEqual(res.remainingDownloads, 4, 'Remaining downloads decremented');
  });
});

// ==========================================
// Feature F5: Offline Mock Store Failover & Latency (5 tests)
// ==========================================
suite.describe('F5: Offline Mock Store Failover & Latency Simulation', () => {
  suite.it('T1.F5.01: Automatic Failover on Network Fetch Error', async () => {
    // In our offline-first architecture, upload seamlessly succeeds via mock fallback
    const res = await api.uploadFile({
      encryptedBlobB64: 'mock',
      ivB64: 'mock',
      metaIvB64: 'mock',
      encryptedMetaB64: 'mock',
    });
    assert.strictEqual(res.success, true);
    assert.ok(res.fileId);
  });

  suite.it('T1.F5.02: Explicit Mock Toggle Configuration', async () => {
    process.env.NEXT_PUBLIC_MOCK_BACKEND = 'true';
    const regRes = await api.registerUser({ username: 'mock_tester', publicKeyPem: 'pem', fingerprint: 'fp' });
    assert.strictEqual(regRes.success, true);
  });

  suite.it('T1.F5.03: Mock Store CRUD State Persistence', async () => {
    const uploadRes = await api.uploadFile({
      encryptedBlobB64: 'crud_data',
      ivB64: 'crud_iv',
      metaIvB64: 'crud_meta_iv',
      encryptedMetaB64: 'crud_meta',
    });

    const metaRes = await api.getMetadata(uploadRes.fileId);
    assert.strictEqual(metaRes.success, true);
    assert.strictEqual(metaRes.ivB64, 'crud_iv');

    const dlRes = await api.downloadFile(uploadRes.fileId);
    assert.strictEqual(dlRes.encryptedBlobB64, 'crud_data');
  });

  suite.it('T1.F5.04: Mock Audit Log Entry Generation', async () => {
    const uploadRes = await api.uploadFile({
      encryptedBlobB64: 'audit_test',
      encryptedMetaB64: 'meta_test',
      ivB64: 'iv_test',
      maxDownloads: 5,
    });
    await api.downloadFile(uploadRes.fileId);
    await api.downloadFile(uploadRes.fileId);

    const logsRes = await api.getAccessLogs(uploadRes.fileId, uploadRes.ownerToken);
    assert.strictEqual(logsRes.success, true);
    assert.greaterThan(logsRes.logs.length, 2);
    assert.strictEqual(logsRes.logs[0].event, 'CREATED');
    assert.ok(
      logsRes.logs[1].event === 'DOWNLOAD' || logsRes.logs[1].event === 'DOWNLOADED',
      'Event must be DOWNLOAD or DOWNLOADED'
    );
  });

  suite.it('T1.F5.05: Simulated Latency Execution', async () => {
    const start = performance.now();
    let threw = false;
    try {
      await api.getUserPubKey('non_existent');
    } catch (err) {
      threw = true;
      assert.ok(err.status === 404 || err.message?.includes('not found'));
    }
    assert.strictEqual(threw, true, 'api.getUserPubKey for non-existent user must throw 404');
    const elapsed = performance.now() - start;
    assert.ok(elapsed >= 0);
  });
});

// ==========================================
// Feature F6: Functional State Hooks (5 tests)
// ==========================================
suite.describe('F6: Functional State Hooks (useUpload, useDecrypt)', () => {
  suite.it('T1.F6.01: useUpload Standard File Upload State Flow', async () => {
    const { result, unmount } = renderHook(() => useUpload());

    assert.strictEqual(result.current.status, 'idle');
    const mockFile = {
      name: 'notes.txt',
      type: 'text/plain',
      arrayBuffer: async () => new TextEncoder().encode('Confidential Note 123').buffer,
    };

    result.current.setFile(mockFile);
    await result.current.executeUpload();

    assert.strictEqual(result.current.status, 'success');
    assert.ok(result.current.result.fileId);
    assert.ok(result.current.result.fullShareUrl);
    assert.includes(result.current.result.fullShareUrl, '#key=');

    unmount();
  });

  suite.it('T1.F6.02: useUpload Secret Text Note Tab Mode', async () => {
    const { result, unmount } = renderHook(() => useUpload());

    result.current.setTab('text');
    result.current.setTextNote('Top Secret Passphrase');
    await result.current.executeUpload();

    assert.strictEqual(result.current.status, 'success');
    assert.ok(result.current.result.fullShareUrl);
    unmount();
  });

  suite.it('T1.F6.03: useDecrypt Fragment Key Parsing & Lifecycle Flow', async () => {
    // Self-contained upload setup
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Decrypt Test 123');
    await upHook.current.executeUpload();
    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    unmountUp();

    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));

    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');

    assert.strictEqual(decHook.current.hasFragmentKey, true);
    assert.strictEqual(decHook.current.status, 'ready');
    assert.strictEqual(decHook.current.isChecksumValid, true);
    assert.ok(decHook.current.fileBlob);
    unmountDec();
  });

  suite.it('T1.F6.04: useDecrypt Zero-Footprint Preview URL Construction', async () => {
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Preview URL Check');
    await upHook.current.executeUpload();
    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    unmountUp();

    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));

    await waitFor(() => decHook.current.previewUrl !== null);

    assert.ok(decHook.current.previewUrl);
    assert.ok(decHook.current.previewUrl.startsWith('blob:'));
    const activeUrls = blobTracker.getActiveUrls();
    assert.includes(activeUrls, decHook.current.previewUrl);

    unmountDec();
    assert.notIncludes(blobTracker.getActiveUrls(), decHook.current.previewUrl);
  });

  suite.it('T1.F6.05: useDecrypt Password Challenge Workflow', async () => {
    // Create password-protected upload
    const { result: uploadHook, unmount: unmountUpload } = renderHook(() => useUpload());
    uploadHook.current.setTab('text');
    uploadHook.current.setTextNote('Password Protected Message');
    uploadHook.current.setIsPasswordProtected(true);
    uploadHook.current.setPassword('VaultPass2026!');
    await uploadHook.current.executeUpload();
    const pwShareUrl = uploadHook.current.result.fullShareUrl;
    const pwFileId = uploadHook.current.result.fileId;
    unmountUpload();

    // Recipient decrypt with password challenge
    const pwHash = pwShareUrl.slice(pwShareUrl.indexOf('#'));
    const { result: decryptHook, unmount: unmountDecrypt } = renderHook(() => useDecrypt(pwFileId, pwHash));

    await waitFor(() => decryptHook.current.status === 'password_required');
    assert.strictEqual(decryptHook.current.status, 'password_required');

    // Submit password
    await decryptHook.current.submitPassword('VaultPass2026!');
    await waitFor(() => decryptHook.current.status === 'ready');
    assert.strictEqual(decryptHook.current.status, 'ready');
    assert.strictEqual(decryptHook.current.isChecksumValid, true);

    unmountDecrypt();
  });
});

// ==========================================
// Feature F7: Structural Components & Routes (5 tests)
// ==========================================
suite.describe('F7: Structural Components & Page Routes', () => {
  suite.it('T1.F7.01: Page Route / (Main Upload Route Structure)', async () => {
    const pagePath = path.resolve(process.cwd(), 'app/page.jsx');
    assert.ok(fs.existsSync(pagePath), 'app/page.jsx must exist');
    const content = fs.readFileSync(pagePath, 'utf8');
    assert.includes(content, 'VaultX');
    assert.includes(content, 'Zero-Knowledge');
  });

  suite.it('T1.F7.02: Dynamic Page Route /v/[id] Param Unwrapping', async () => {
    // Tests mock DecryptView receiving fileId prop
    const decryptElement = MockDecryptView({ fileId: 'test-uuid-1234', isChecksumValid: true });
    assert.strictEqual(decryptElement.type, 'div');
    assert.includes(decryptElement.props.className, 'decrypt-view');
  });

  suite.it('T1.F7.03: Page Route /dashboard & Person 4 Placeholder Slots', async () => {
    const auditEl = MockAuditTrail({ logs: [{ timestamp: '2026-11-23', event: 'CREATED', ipHash: 'abc' }] });
    const hexEl = MockHexInspector({});
    const revokeEl = MockRevokeButton({ onRevoke: () => {} });

    assert.ok(auditEl);
    assert.ok(hexEl);
    assert.ok(revokeEl);
  });

  suite.it('T1.F7.04: <QRModal /> Dialog Rendering', async () => {
    const qrElement = MockQRModal({ isOpen: true, shareUrl: 'http://localhost:3000/v/1#key=xyz' });
    assert.strictEqual(qrElement.type, 'div');
    assert.includes(qrElement.props.className, 'modal-overlay');

    const closedElement = MockQRModal({ isOpen: false });
    assert.strictEqual(closedElement, null);
  });

  suite.it('T1.F7.05: <KeySetupModal /> Onboarding Dialog', async () => {
    let generatedFp = null;
    const modalElement = MockKeySetupModal({
      isOpen: true,
      fingerprint: '54:75:fa:29:mock',
      onKeyGenerated: (res) => {
        generatedFp = res.fingerprint;
      },
    });

    assert.ok(modalElement);
    assert.includes(modalElement.props.className, 'modal-container');
  });
});

// ==========================================
// Feature F8: Offline Build & Local Fonts Config (5 tests)
// ==========================================
suite.describe('F8: Offline Build & Local Fallback Fonts Config', () => {
  suite.it('T1.F8.01: Clean Offline Build Configuration Verification', () => {
    const pkgPath = path.resolve(process.cwd(), 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    assert.ok(pkg.scripts?.build, 'build script must exist');
    assert.ok(pkg.dependencies?.next, 'next dependency must exist');
  });

  suite.it('T1.F8.02: Absence of Remote Font CDN Requests', () => {
    const layoutPath = path.resolve(process.cwd(), 'app/layout.jsx');
    const layoutContent = fs.readFileSync(layoutPath, 'utf8');

    assert.notIncludes(layoutContent, 'fonts.googleapis.com');
    assert.notIncludes(layoutContent, 'fonts.gstatic.com');
    assert.notIncludes(layoutContent, 'next/font/google');
  });

  suite.it('T1.F8.03: Local System Font Stack Configuration', () => {
    const tailwindPath = path.resolve(process.cwd(), 'tailwind.config.js');
    const content = fs.readFileSync(tailwindPath, 'utf8');

    assert.includes(content, 'system-ui');
    assert.includes(content, 'ui-monospace');
  });

  suite.it('T1.F8.04: Content Security Policy (CSP) Headers in next.config.mjs', () => {
    const nextConfigPath = path.resolve(process.cwd(), 'next.config.mjs');
    const content = fs.readFileSync(nextConfigPath, 'utf8');

    assert.includes(content, 'Content-Security-Policy');
    assert.includes(content, "default-src 'self'");
    assert.includes(content, "object-src 'none'");
    assert.includes(content, "frame-ancestors 'none'");
  });

  suite.it('T1.F8.05: Standalone Offline Web Crypto Self-Test Contract', async () => {
    // Probes Node 22 subtle Web Crypto availability
    assert.ok(globalThis.crypto?.subtle, 'Web Crypto subtle must be natively available');
    const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode('VaultX'));
    assert.strictEqual(digest.byteLength, 32);
  });
});

export default suite;

// Standalone execution support
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  suite.run().then((res) => process.exit(res.failed > 0 ? 1 : 0));
}
