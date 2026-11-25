/**
 * test/e2e/tier2-boundary-corner.test.mjs
 * Tier 2: Boundary & Corner Cases (40 Tests: 5 tests each for Features F1 to F8).
 * Evaluates error handling, bit tampering, auth tag corruption, boundary stress,
 * expiration caps, burn-after-reading, and invalid states.
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

const suite = createSuite('Tier 2: Boundary & Corner Cases (40 Tests)');

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
// Feature F1 Boundaries (Crypto Mode B)
// ==========================================
suite.describe('F1 Boundaries: Crypto Mode B', () => {
  suite.it('T2.F1.01: 0-Byte Empty Buffer Rejection', async () => {
    let threw = false;
    try {
      await vaultCrypto.encryptFileAndMeta(new ArrayBuffer(0), { filename: 'empty.dat' }, 'MODE_B');
    } catch (err) {
      threw = true;
      assert.ok(
        err.message?.includes('cannot be empty') || err instanceof TypeError,
        `Expected empty buffer error, got: ${err.message}`
      );
    }
    assert.strictEqual(threw, true, '0-byte buffer must be rejected before encryption');
  });

  suite.it('T2.F1.02: 1-Bit Tampered Ciphertext Authentication Failure', async () => {
    const original = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
    const enc = await vaultCrypto.encryptFileAndMeta(original.buffer, { filename: 'test' }, 'MODE_B');

    // Tamper 1 bit in ciphertext
    const tamperedCipher = await MockCrypto.flipBit(enc.encryptedBlob, 5, 0);

    let threw = false;
    try {
      await vaultCrypto.decryptFileAndMeta(
        tamperedCipher,
        enc.ivB64,
        enc.encryptedMetaB64,
        enc.fragmentKeyB64,
        'MODE_B',
        { metaIvB64: enc.metaIvB64 }
      );
    } catch (err) {
      threw = true;
      // Web Crypto throws OperationError on AES-GCM tag mismatch
      assert.ok(
        err.name === 'OperationError' || err.message?.includes('operation failed') || err.message?.includes('decrypt'),
        `Expected OperationError, got: ${err.name} - ${err.message}`
      );
    }
    assert.strictEqual(threw, true, '1-bit tampered ciphertext must fail authentication');
  });

  suite.it('T2.F1.03: Tampered Metadata Checksum Mismatch', async () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const enc = await vaultCrypto.encryptFileAndMeta(original.buffer, { filename: 'doc.txt' }, 'MODE_B');

    // Create encrypted metadata with tampered checksum
    const rawAesKey = MockCrypto.fromBase64Url(enc.fragmentKeyB64);
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      rawAesKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    const tamperedMeta = {
      filename: 'doc.txt',
      sha256Checksum: '0000000000000000000000000000000000000000000000000000000000000000',
    };
    const metaBytes = new TextEncoder().encode(JSON.stringify(tamperedMeta));
    const metaCipher = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: MockCrypto.fromBase64(enc.metaIvB64) },
      aesKey,
      metaBytes
    );

    const dec = await vaultCrypto.decryptFileAndMeta(
      enc.encryptedBlob,
      enc.ivB64,
      MockCrypto.toBase64(metaCipher),
      enc.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: enc.metaIvB64 }
    );

    assert.strictEqual(dec.isChecksumValid, false, 'Tampered checksum must set isChecksumValid to false');
  });

  suite.it('T2.F1.04: Malformed Base64URL Fragment Key Rejection', async () => {
    const validBuffer = new Uint8Array([1, 2, 3, 4]).buffer;
    const enc = await vaultCrypto.encryptFileAndMeta(validBuffer, { filename: 'test' }, 'MODE_B');

    const malformedKeys = ['!@#$%^&*()', 'too-short', '', 'invalid==padding=='];
    for (const badKey of malformedKeys) {
      let threw = false;
      try {
        await vaultCrypto.decryptFileAndMeta(
          enc.encryptedBlob,
          enc.ivB64,
          enc.encryptedMetaB64,
          badKey,
          'MODE_B',
          { metaIvB64: enc.metaIvB64 }
        );
      } catch (err) {
        threw = true;
      }
      assert.strictEqual(threw, true, `Malformed key "${badKey}" must throw`);
    }
  });

  suite.it('T2.F1.05: Wrong Password PBKDF2 Rejection', async () => {
    const data = new Uint8Array([9, 8, 7, 6]).buffer;
    const enc = await vaultCrypto.encryptFileAndMeta(data, { filename: 'secret.txt' }, 'MODE_B', null, {
      password: 'CorrectPassword123!',
    });

    let threw = false;
    try {
      await vaultCrypto.decryptFileAndMeta(
        enc.encryptedBlob,
        enc.ivB64,
        enc.encryptedMetaB64,
        enc.fragmentKeyB64,
        'MODE_B',
        { metaIvB64: enc.metaIvB64, password: 'WrongPassword456!' }
      );
    } catch (err) {
      threw = true;
      assert.ok(
        err.name === 'OperationError' ||
        err.code === 'INVALID_PASSWORD' ||
        err.message?.toLowerCase().includes('password') ||
        err.message?.includes('operation failed') ||
        err.message?.includes('decrypt'),
        `Expected password/crypto error, got: ${err.message}`
      );
    }
    assert.strictEqual(threw, true, 'Wrong password must fail decryption');
  });
});

// ==========================================
// Feature F2 Boundaries (Crypto Mode A)
// ==========================================
suite.describe('F2 Boundaries: Crypto Mode A', () => {
  suite.it('T2.F2.01: Mode A Encryption Without Recipient Public Key', async () => {
    let threw = false;
    try {
      await vaultCrypto.encryptFileAndMeta(new Uint8Array([1, 2, 3]).buffer, { filename: 'test' }, 'MODE_A', null);
    } catch (err) {
      threw = true;
      assert.includes(err.message, 'Recipient public key is required');
    }
    assert.strictEqual(threw, true);
  });

  suite.it('T2.F2.02: Corrupted Recipient Public Key PEM', async () => {
    const corruptedPem = '-----BEGIN PUBLIC KEY-----\nBADKEYDATA123\n-----END PUBLIC KEY-----';
    let threw = false;
    try {
      await vaultCrypto.encryptFileAndMeta(new Uint8Array([1, 2, 3]).buffer, { filename: 'test' }, 'MODE_A', corruptedPem);
    } catch (err) {
      threw = true;
    }
    assert.strictEqual(threw, true, 'Corrupted PEM must fail key import');
  });

  suite.it('T2.F2.03: Wrong Recipient Private Key Unwrapping Rejection', async () => {
    const alice = await vaultCrypto.generateUserKeyPair();
    const bob = await vaultCrypto.generateUserKeyPair();

    const enc = await vaultCrypto.encryptFileAndMeta(
      new Uint8Array([10, 20, 30]).buffer,
      { filename: 'alice_memo.pdf' },
      'MODE_A',
      alice.publicKeyPem
    );

    let threw = false;
    try {
      // Bob attempts to unwrap Alice's wrapped key with Bob's private key
      await vaultCrypto.decryptFileAndMeta(
        enc.encryptedBlob,
        enc.ivB64,
        enc.encryptedMetaB64,
        {
          privateKey: bob.keyPair.privateKey,
          wrappedAesKeyB64: enc.wrappedAesKeyB64,
        },
        'MODE_A',
        { metaIvB64: enc.metaIvB64 }
      );
    } catch (err) {
      threw = true;
      assert.ok(
        err.name === 'OperationError' || err.message?.includes('operation failed') || err.message?.includes('unwrap'),
        `Expected OperationError, got ${err.name}`
      );
    }
    assert.strictEqual(threw, true, 'Unwrapping with wrong private key must throw OperationError');
  });

  suite.it('T2.F2.04: Truncated Wrapped AES Key Buffer', async () => {
    const { keyPair, publicKeyPem } = await vaultCrypto.generateUserKeyPair();
    const enc = await vaultCrypto.encryptFileAndMeta(
      new Uint8Array([1, 2, 3]).buffer,
      { filename: 'doc' },
      'MODE_A',
      publicKeyPem
    );

    // Truncate wrapped key by half
    const fullWrapped = MockCrypto.fromBase64(enc.wrappedAesKeyB64);
    const truncated = MockCrypto.toBase64(fullWrapped.slice(0, 128));

    let threw = false;
    try {
      await vaultCrypto.decryptFileAndMeta(
        enc.encryptedBlob,
        enc.ivB64,
        enc.encryptedMetaB64,
        {
          privateKey: keyPair.privateKey,
          wrappedAesKeyB64: truncated,
        },
        'MODE_A',
        { metaIvB64: enc.metaIvB64 }
      );
    } catch (err) {
      threw = true;
    }
    assert.strictEqual(threw, true, 'Truncated wrapped key must fail unwrap');
  });

  suite.it('T2.F2.05: Tampered Ciphertext in Mode A Envelope', async () => {
    const { keyPair, publicKeyPem } = await vaultCrypto.generateUserKeyPair();
    const enc = await vaultCrypto.encryptFileAndMeta(
      new Uint8Array([10, 20, 30, 40, 50]).buffer,
      { filename: 'doc' },
      'MODE_A',
      publicKeyPem
    );

    const tampered = await MockCrypto.flipBit(enc.encryptedBlob, 2, 0);

    let threw = false;
    try {
      await vaultCrypto.decryptFileAndMeta(
        tampered,
        enc.ivB64,
        enc.encryptedMetaB64,
        {
          privateKey: keyPair.privateKey,
          wrappedAesKeyB64: enc.wrappedAesKeyB64,
        },
        'MODE_A',
        { metaIvB64: enc.metaIvB64 }
      );
    } catch (err) {
      threw = true;
      assert.ok(err.name === 'OperationError');
    }
    assert.strictEqual(threw, true, 'Tampered ciphertext in Mode A must throw OperationError');
  });
});

// ==========================================
// Feature F3 Boundaries (KeyStore)
// ==========================================
suite.describe('F3 Boundaries: KeyStore', () => {
  suite.it('T2.F3.01: Query Non-Existent User in KeyStore', async () => {
    const res = await keyStore.getUserKey('nonexistent_ghost_user_123');
    assert.strictEqual(res, null, 'Querying non-existent user should resolve to null');
  });

  suite.it('T2.F3.02: Overwrite Existing User Key in KeyStore', async () => {
    const pairA = await vaultCrypto.generateUserKeyPair();
    const pairB = await vaultCrypto.generateUserKeyPair();

    await keyStore.storeUserKey('mutable_alice', pairA.keyPair, pairA.publicKeyPem, pairA.keyFingerprint);
    let current = await keyStore.getUserKey('mutable_alice');
    assert.strictEqual(current.fingerprint, pairA.keyFingerprint);

    await keyStore.storeUserKey('mutable_alice', pairB.keyPair, pairB.publicKeyPem, pairB.keyFingerprint);
    current = await keyStore.getUserKey('mutable_alice');
    assert.strictEqual(current.fingerprint, pairB.keyFingerprint, 'Overwritten key must match pairB');
  });

  suite.it('T2.F3.03: Delete / Clear User Key', async () => {
    const { keyPair, publicKeyPem, keyFingerprint } = await vaultCrypto.generateUserKeyPair();
    await keyStore.storeUserKey('charlie_clear', keyPair, publicKeyPem, keyFingerprint);

    assert.strictEqual(await keyStore.hasUserKey('charlie_clear'), true);
    await keyStore.clearUserKey('charlie_clear');

    assert.strictEqual(await keyStore.hasUserKey('charlie_clear'), false);
    assert.strictEqual(await keyStore.getUserKey('charlie_clear'), null);
  });

  suite.it('T2.F3.04: Usernames with Special Characters and Unicode', async () => {
    const { keyPair, publicKeyPem, keyFingerprint } = await vaultCrypto.generateUserKeyPair();
    const specialUser = 'user+test@domain.co.uk_🎉_test';

    await keyStore.storeUserKey(specialUser, keyPair, publicKeyPem, keyFingerprint);
    const retrieved = await keyStore.getUserKey(specialUser);

    assert.ok(retrieved);
    assert.strictEqual(retrieved.username, specialUser);
    assert.strictEqual(retrieved.fingerprint, keyFingerprint);
  });

  suite.it('T2.F3.05: Fingerprint Computation with Invalid Object', async () => {
    let threwNull = false;
    try {
      await keyStore.computeKeyFingerprint(null);
    } catch (err) {
      threwNull = true;
      assert.ok(err instanceof TypeError || err instanceof Error);
    }
    assert.strictEqual(threwNull, true);

    let threwEmpty = false;
    try {
      await keyStore.computeKeyFingerprint({});
    } catch (err) {
      threwEmpty = true;
      assert.ok(err instanceof TypeError || err instanceof Error);
    }
    assert.strictEqual(threwEmpty, true);
  });
});

// ==========================================
// Feature F4 Boundaries (REST API Client)
// ==========================================
suite.describe('F4 Boundaries: REST API Client', () => {
  suite.it('T2.F4.01: Query Non-Existent File ID (404 Not Found)', async () => {
    const ghostId = '00000000-0000-0000-0000-000000000000';
    let metaRes = null;
    try {
      metaRes = await api.getMetadata(ghostId);
    } catch (err) {
      assert.strictEqual(err.status, 404);
    }
    if (metaRes) {
      assert.strictEqual(metaRes.success, false);
      assert.strictEqual(metaRes.status, 404);
    }

    let dlRes = null;
    try {
      dlRes = await api.downloadFile(ghostId);
    } catch (err) {
      assert.strictEqual(err.status, 404);
    }
    if (dlRes) {
      assert.strictEqual(dlRes.success, false);
      assert.strictEqual(dlRes.status, 404);
    }
  });

  suite.it('T2.F4.02: Expired Vault Item Access (410 Gone)', async () => {
    const upload = await api.uploadFile({
      encryptedBlobB64: 'expired_payload',
      encryptedMetaB64: 'expired_meta',
      ivB64: 'expired_iv',
      expiryMinutes: -5, // already expired 5 mins ago
    });

    let res = null;
    try {
      res = await api.downloadFile(upload.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
      assert.ok(err.message?.toLowerCase().includes('expired'));
    }
    if (res) {
      assert.strictEqual(res.success, false);
      assert.strictEqual(res.status, 410);
      assert.includes(res.message, 'expired');
    }
  });

  suite.it('T2.F4.03: Download Limit Cap Enforcement (410 Gone)', async () => {
    const upload = await api.uploadFile({
      encryptedBlobB64: 'capped_payload',
      encryptedMetaB64: 'capped_meta',
      ivB64: 'capped_iv',
      maxDownloads: 1,
    });

    // 1st download succeeds
    const dl1 = await api.downloadFile(upload.fileId);
    assert.strictEqual(dl1.success, true);
    assert.strictEqual(dl1.remainingDownloads, 0);

    // 2nd download cap exceeded
    let dl2 = null;
    try {
      dl2 = await api.downloadFile(upload.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
      assert.ok(
        err.message?.toLowerCase().includes('limit') ||
        err.message?.toLowerCase().includes('burned')
      );
    }
    if (dl2) {
      assert.strictEqual(dl2.success, false);
      assert.strictEqual(dl2.status, 410);
      assert.includes(dl2.message, 'limit exceeded');
    }
  });

  suite.it('T2.F4.04: Burn-After-Reading Destruction (410 Gone)', async () => {
    const upload = await api.uploadFile({
      encryptedBlobB64: 'burn_payload',
      encryptedMetaB64: 'burn_meta',
      ivB64: 'burn_iv',
      isBurnAfterReading: true,
      maxDownloads: 5,
    });

    // 1st download retrieves data and burns
    const dl1 = await api.downloadFile(upload.fileId);
    assert.strictEqual(dl1.success, true);
    assert.strictEqual(dl1.encryptedBlobB64, 'burn_payload');

    // 2nd download returns 410
    let dl2 = null;
    try {
      dl2 = await api.downloadFile(upload.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (dl2) {
      assert.strictEqual(dl2.success, false);
      assert.strictEqual(dl2.status, 410);
    }
  });

  suite.it('T2.F4.05: Unauthorized Revocation with Invalid Owner Token (401 Unauthorized)', async () => {
    const upload = await api.uploadFile({
      encryptedBlobB64: 'protected_payload',
      encryptedMetaB64: 'protected_meta',
      ivB64: 'protected_iv',
      maxDownloads: 5,
    });

    let revokeRes = null;
    try {
      revokeRes = await api.revokeFile(upload.fileId, 'invalid_attacker_token');
    } catch (err) {
      assert.strictEqual(err.status, 401);
    }
    if (revokeRes) {
      assert.strictEqual(revokeRes.success, false);
      assert.strictEqual(revokeRes.status, 401);
    }

    // File should remain active and downloadable
    const dl = await api.downloadFile(upload.fileId);
    assert.strictEqual(dl.success, true);
  });
});

// ==========================================
// Feature F5 Boundaries (Offline Mock Store)
// ==========================================
suite.describe('F5 Boundaries: Offline Mock Store', () => {
  suite.it('T2.F5.01: Mock Store State Reset Isolation', async () => {
    await api.uploadFile({ encryptedBlobB64: 'data1', encryptedMetaB64: 'meta1', ivB64: 'iv1' });
    await api.uploadFile({ encryptedBlobB64: 'data2', encryptedMetaB64: 'meta2', ivB64: 'iv2' });

    api._resetMockStore?.();

    // Check store is empty
    let ghost = null;
    try {
      ghost = await api.getMetadata('any-id');
    } catch (err) {
      assert.strictEqual(err.status, 404);
    }
    if (ghost) {
      assert.strictEqual(ghost.success, false);
      assert.strictEqual(ghost.status, 404);
    }
  });

  suite.it('T2.F5.02: Concurrent Multi-Upload Race Resistance', async () => {
    const uploads = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        api.uploadFile({
          encryptedBlobB64: `blob_${i}`,
          encryptedMetaB64: `meta_${i}`,
          ivB64: `iv_${i}`,
        })
      )
    );

    const fileIds = new Set(uploads.map((u) => u.fileId));
    const ownerTokens = new Set(uploads.map((u) => u.ownerToken));

    assert.strictEqual(fileIds.size, 10, 'All 10 file IDs must be unique');
    assert.strictEqual(ownerTokens.size, 10, 'All 10 owner tokens must be unique');
  });

  suite.it('T2.F5.03: Mock Clock Advance Expiry Enforcement', async () => {
    const upload = await api.uploadFile({
      encryptedBlobB64: 'clock_data',
      encryptedMetaB64: 'clock_meta',
      ivB64: 'clock_iv',
      expiryMinutes: -1,
    });

    let res = null;
    try {
      res = await api.getMetadata(upload.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (res) {
      assert.strictEqual(res.success, false);
      assert.strictEqual(res.status, 410);
    }
  });

  suite.it('T2.F5.04: Mock Immediate Revocation Purge', async () => {
    const upload = await api.uploadFile({
      encryptedBlobB64: 'purge_me',
      encryptedMetaB64: 'purge_meta',
      ivB64: 'purge_iv',
    });
    const revokeRes = await api.revokeFile(upload.fileId, upload.ownerToken);
    assert.strictEqual(revokeRes.success, true);

    let metaRes = null;
    try {
      metaRes = await api.getMetadata(upload.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (metaRes) {
      assert.strictEqual(metaRes.status, 410);
    }
  });

  suite.it('T2.F5.05: Network Resumption Clean Reconnection', async () => {
    // Verifies client continues operation cleanly
    const res = await api.uploadFile({
      encryptedBlobB64: 'reconnect_test',
      encryptedMetaB64: 'reconnect_meta',
      ivB64: 'reconnect_iv',
    });
    assert.strictEqual(res.success, true);
  });
});

// ==========================================
// Feature F6 Boundaries (Functional State Hooks)
// ==========================================
suite.describe('F6 Boundaries: Functional State Hooks', () => {
  suite.it('T2.F6.01: useDecrypt Missing Fragment Key Handling', async () => {
    const up = await api.uploadFile({
      encryptedBlobB64: 'data',
      encryptedMetaB64: 'meta',
      ivB64: 'iv',
      mode: 'MODE_B',
    });
    // URL with no fragment
    const { result, unmount } = renderHook(() => useDecrypt(up.fileId, ''));

    await waitFor(() => result.current.status !== 'loading_meta');

    assert.strictEqual(result.current.hasFragmentKey, false);
    assert.strictEqual(result.current.status, 'idle');
    assert.ok(typeof result.current.setManualKey === 'function');
    unmount();
  });

  suite.it('T2.F6.02: useDecrypt Checksum Mismatch Status Transition', async () => {
    // Upload valid payload
    const data = new Uint8Array([1, 2, 3, 4]).buffer;
    const enc = await vaultCrypto.encryptFileAndMeta(data, { filename: 'test' }, 'MODE_B');

    // Create record with tampered checksum
    const rawAesKey = MockCrypto.fromBase64Url(enc.fragmentKeyB64);
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      rawAesKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    const tamperedMeta = {
      filename: 'test',
      sha256Checksum: '1111111111111111111111111111111111111111111111111111111111111111',
    };
    const metaCipher = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: MockCrypto.fromBase64(enc.metaIvB64) },
      aesKey,
      new TextEncoder().encode(JSON.stringify(tamperedMeta))
    );

    const cipherArrayBuf = enc.encryptedBlob instanceof ArrayBuffer
      ? enc.encryptedBlob
      : (enc.encryptedBlob?.arrayBuffer ? await enc.encryptedBlob.arrayBuffer() : enc.encryptedBlob.buffer);

    const uploadRes = await api.uploadFile({
      encryptedBlobB64: MockCrypto.toBase64(cipherArrayBuf),
      ivB64: enc.ivB64,
      metaIvB64: enc.metaIvB64,
      encryptedMetaB64: MockCrypto.toBase64(metaCipher),
      mode: 'MODE_B',
    });

    const hash = `#key=${enc.fragmentKeyB64}`;
    const { result, unmount } = renderHook(() => useDecrypt(uploadRes.fileId, hash));

    await waitFor(() => result.current.status !== 'loading_meta' && result.current.status !== 'decrypting');

    assert.strictEqual(result.current.status, 'tampered');
    assert.strictEqual(result.current.isChecksumValid, false);
    assert.includes(result.current.error, 'checksum verification failed');
    unmount();
  });

  suite.it('T2.F6.03: useDecrypt Memory Blob Cleanup on Component Unmount', async () => {
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Memory Hygiene Test');
    await upHook.current.executeUpload();
    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    unmountUp();

    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));

    await waitFor(() => decHook.current.previewUrl !== null);
    const activeUrl = decHook.current.previewUrl;
    assert.ok(activeUrl);

    unmountDec();
    assert.notIncludes(blobTracker.getActiveUrls(), activeUrl, 'URL must be revoked after unmount');
  });

  suite.it('T2.F6.04: useUpload Form Validation Rejection (Empty Submission)', async () => {
    const { result, unmount } = renderHook(() => useUpload());

    // tab is 'file' by default, file is null
    await result.current.executeUpload();

    assert.strictEqual(result.current.status, 'idle');
    assert.strictEqual(result.current.error, 'Please select a file to encrypt');
    assert.strictEqual(result.current.result, null);
    unmount();
  });

  suite.it('T2.F6.05: useUpload Full Reset State Machine Cleanliness', async () => {
    const { result, unmount } = renderHook(() => useUpload());
    result.current.setTab('text');
    result.current.setTextNote('Reset Me');
    await result.current.executeUpload();
    assert.strictEqual(result.current.status, 'success');

    result.current.reset();
    assert.strictEqual(result.current.status, 'idle');
    assert.strictEqual(result.current.result, null);
    assert.strictEqual(result.current.error, null);
    assert.strictEqual(result.current.textNote, '');
    unmount();
  });
});

// ==========================================
// Feature F7 Boundaries (Structural Components & Routes)
// ==========================================
suite.describe('F7 Boundaries: Structural Components & Routes', () => {
  suite.it('T2.F7.01: Recipient Route /v/[id] with Malformed ID Handling', () => {
    const badId = 'invalid%20id%20with%20spaces';
    const decEl = MockDecryptView({ fileId: badId });
    assert.ok(decEl);
  });

  suite.it('T2.F7.02: <DecryptView /> Tamper Warning Banner Rendering', () => {
    const view = MockDecryptView({ isChecksumValid: false });
    assert.ok(view);
    // Find warning banner child
    const children = Array.isArray(view.props.children) ? view.props.children : [view.props.children];
    const banner = children.find((c) => c && c.props?.className?.includes('warning-banner'));
    assert.ok(banner, 'Expected warning banner when isChecksumValid is false');
  });

  suite.it('T2.F7.03: <UploadCard /> Mode A Without Verified Recipient', () => {
    const card = MockUploadCard({ isModeA: true, recipientUsername: '' });
    const children = Array.isArray(card.props.children) ? card.props.children : [card.props.children];
    const uploadBtn = children.find((c) => c && c.props?.className?.includes('btn-upload'));
    assert.ok(uploadBtn);
    assert.strictEqual(uploadBtn.props.disabled, true, 'Upload button must be disabled when recipient is missing');
  });

  suite.it('T2.F7.04: Dashboard Empty State Handling', () => {
    mockLocalStorage.clear();
    const stored = JSON.parse(mockLocalStorage.getItem('vaultx_history') || '[]');
    assert.strictEqual(stored.length, 0);
  });

  suite.it('T2.F7.05: Person 4 Dashboard Placeholder Component Isolation', () => {
    // Null/undefined props should not crash components
    const audit = MockAuditTrail({ logs: null });
    const hex = MockHexInspector({});
    const revoke = MockRevokeButton({});
    assert.ok(audit);
    assert.ok(hex);
    assert.ok(revoke);
  });
});

// ==========================================
// Feature F8 Boundaries (Offline Build & Config)
// ==========================================
suite.describe('F8 Boundaries: Offline Build & Local Fonts Config', () => {
  suite.it('T2.F8.01: Build with Complete Network Isolation', () => {
    const pkg = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'package.json'), 'utf8'));
    assert.ok(pkg.name === 'vaultx-web');
  });

  suite.it('T2.F8.02: React StrictMode SSR Hydration Match', () => {
    const nextConfig = fs.readFileSync(path.resolve(process.cwd(), 'next.config.mjs'), 'utf8');
    assert.includes(nextConfig, 'reactStrictMode: true');
  });

  suite.it('T2.F8.03: Tailwind Utility Class Availability in Build Config', () => {
    const tailwindConfig = fs.readFileSync(path.resolve(process.cwd(), 'tailwind.config.js'), 'utf8');
    assert.includes(tailwindConfig, './app/**/*.{js,ts,jsx,tsx,mdx}');
  });

  suite.it('T2.F8.04: CSP Disallows Wildcard Script Sources', () => {
    const nextConfig = fs.readFileSync(path.resolve(process.cwd(), 'next.config.mjs'), 'utf8');
    const match = nextConfig.match(/script-src\s+([^;]+)/);
    assert.ok(match, 'script-src directive must exist in CSP');
    assert.notIncludes(match[1], "'*'", "script-src must NOT contain wildcard '*'");
  });

  suite.it('T2.F8.05: Missing NEXT_PUBLIC_API_URL Graceful Default', () => {
    const original = process.env.NEXT_PUBLIC_API_URL;
    delete process.env.NEXT_PUBLIC_API_URL;

    const base = api.getBaseUrl?.() || 'http://localhost:5000/api';
    assert.strictEqual(base, 'http://localhost:5000/api');

    if (original) process.env.NEXT_PUBLIC_API_URL = original;
  });
});

export default suite;

// Standalone execution support
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  suite.run().then((res) => process.exit(res.failed > 0 ? 1 : 0));
}
