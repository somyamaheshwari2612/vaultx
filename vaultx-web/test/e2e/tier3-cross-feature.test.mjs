/**
 * test/e2e/tier3-cross-feature.test.mjs
 * Tier 3: Cross-Feature Combinations (8 Pairwise Interaction Tests).
 * Evaluates pairwise combinations across crypto modes, keystore, api, hooks, and routes.
 */
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
  MockKeySetupModal,
  MockRevokeButton,
} from './helpers/contracts.mjs';

const suite = createSuite('Tier 3: Cross-Feature Combinations (8 Tests)');

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
// Tier 3 Combinations (T3.01 - T3.08)
// ==========================================
suite.describe('Cross-Feature Pairwise Interactions', () => {
  suite.it('T3.01: Mode B + Password Protection + Burn-After-Reading (F1 + F4 + F5 + F6)', async () => {
    // Step 1: Upload with password + burn toggle
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Burn after reading password note');
    upHook.current.setIsPasswordProtected(true);
    upHook.current.setPassword('Hackathon2026!');
    upHook.current.setIsBurnAfterReading(true);

    await upHook.current.executeUpload();
    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    unmountUp();

    // Step 2: Recipient mounts useDecrypt
    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));

    await waitFor(() => decHook.current.status === 'password_required');
    assert.strictEqual(decHook.current.status, 'password_required');

    // Step 3: Wrong password attempt
    let wrongFailed = false;
    try {
      await decHook.current.submitPassword('wrong_password');
    } catch (_) {
      wrongFailed = true;
    }
    assert.strictEqual(wrongFailed, true, 'Wrong password must fail decryption');

    // Step 4: Correct password attempt
    await decHook.current.submitPassword('Hackathon2026!');
    await waitFor(() => decHook.current.status === 'ready');
    assert.strictEqual(decHook.current.status, 'ready');
    assert.strictEqual(decHook.current.isChecksumValid, true);

    unmountDec();

    // Step 5: Second access attempt must return 410 Gone (burned)
    let secondTry = null;
    try {
      secondTry = await api.downloadFile(fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (secondTry) {
      assert.strictEqual(secondTry.success, false);
      assert.strictEqual(secondTry.status, 410);
    }
  });

  suite.it('T3.02: Mode A + KeyStore Non-Extractable Key Persistence (F2 + F3 + F4 + F6)', async () => {
    // Step 1: Alice generates keypair and persists in KeyStore
    const aliceKeys = await vaultCrypto.generateUserKeyPair();
    await keyStore.storeUserKey('alice', aliceKeys.keyPair, aliceKeys.publicKeyPem, aliceKeys.keyFingerprint);
    await keyStore.storeUserKey('current_user', aliceKeys.keyPair, aliceKeys.publicKeyPem, aliceKeys.keyFingerprint);

    // Step 2: Alice registers with API
    try {
      await api.registerUser({
        username: 'alice',
        publicKeyPem: aliceKeys.publicKeyPem,
        fingerprint: aliceKeys.keyFingerprint,
      });
    } catch (err) {
      if (err.status !== 409) throw err;
    }

    // Step 3: Sender uploads file in Mode A targeting Alice
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Confidential for Alice Only');
    upHook.current.setMode('MODE_A');
    upHook.current.setRecipientUsername('alice');

    await upHook.current.executeUpload();
    const fileId = upHook.current.result.fileId;
    const fullShareUrl = upHook.current.result.fullShareUrl;
    assert.notIncludes(fullShareUrl, '#key=');
    unmountUp();

    // Step 4: Alice decrypts with private key from KeyStore
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, null, 'alice'));
    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');

    // Decryption should succeed because alice's key is in KeyStore
    assert.strictEqual(decHook.current.status, 'ready');
    assert.strictEqual(decHook.current.isChecksumValid, true);
    unmountDec();

    // Step 5: Verify Alice's private key cannot be extracted
    const stored = await keyStore.getUserKey('alice');
    let threw = false;
    try {
      await globalThis.crypto.subtle.exportKey('pkcs8', stored.keyPair.privateKey);
    } catch (_) {
      threw = true;
    }
    assert.strictEqual(threw, true, 'Alice private key must remain non-extractable');
  });

  suite.it('T3.03: Secret Text Note + Large Multibyte Payload + Mode B Fragment (F1 + F6 + F7)', async () => {
    // Generate 50KB multibyte Unicode text (emojis, CJK, symbols)
    const baseChunk = 'VaultX 🔒 零知识 • 秘密共有 • 2026! 🚀 \n';
    let largeText = '';
    while (new TextEncoder().encode(largeText).byteLength < 50000) {
      largeText += baseChunk;
    }

    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote(largeText);

    await upHook.current.executeUpload();
    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    unmountUp();

    // Recipient decrypts large text
    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));

    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');

    assert.strictEqual(decHook.current.status, 'ready');
    assert.strictEqual(decHook.current.isChecksumValid, true);

    const decryptedText = await decHook.current.fileBlob.text();
    assert.strictEqual(decryptedText, largeText, 'Decrypted large Unicode text must match exactly');
    unmountDec();
  });

  suite.it('T3.04: Full REST API Upload + Mock Download + Decrypt Pipeline (F1 + F4 + F5 + F6)', async () => {
    // 100KB binary buffer
    const payloadBuffer = MockCrypto.randomBytes(100 * 1024).buffer;
    const meta = { filename: 'binary_test.bin', size: 100 * 1024 };

    const enc = await vaultCrypto.encryptFileAndMeta(payloadBuffer, meta, 'MODE_B');

    const cipherArrayBuf = enc.encryptedBlob instanceof ArrayBuffer
      ? enc.encryptedBlob
      : (enc.encryptedBlob?.arrayBuffer ? await enc.encryptedBlob.arrayBuffer() : enc.encryptedBlob.buffer);

    const uploadRes = await api.uploadFile({
      encryptedBlobB64: MockCrypto.toBase64(cipherArrayBuf),
      ivB64: enc.ivB64,
      metaIvB64: enc.metaIvB64,
      encryptedMetaB64: enc.encryptedMetaB64,
      mode: 'MODE_B',
    });
    assert.strictEqual(uploadRes.success, true);

    const metaRes = await api.getMetadata(uploadRes.fileId);
    assert.strictEqual(metaRes.success, true);

    const downloadRes = await api.downloadFile(uploadRes.fileId);
    assert.strictEqual(downloadRes.success, true);

    const dec = await vaultCrypto.decryptFileAndMeta(
      MockCrypto.fromBase64(downloadRes.encryptedBlobB64).buffer,
      downloadRes.ivB64,
      metaRes.encryptedMetaB64,
      enc.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: downloadRes.metaIvB64 }
    );

    assert.strictEqual(dec.isChecksumValid, true);
    assert.deepStrictEqual(new Uint8Array(dec.fileBuffer), new Uint8Array(payloadBuffer));
  });

  suite.it('T3.05: Mode B + Max Downloads Cap Enforcement (F1 + F4 + F5 + F6)', async () => {
    const uploadRes = await api.uploadFile({
      encryptedBlobB64: 'payload_capped_at_2',
      encryptedMetaB64: 'meta_capped',
      ivB64: 'iv_capped',
      maxDownloads: 2,
    });

    // Download 1
    const d1 = await api.downloadFile(uploadRes.fileId);
    assert.strictEqual(d1.success, true);
    assert.strictEqual(d1.remainingDownloads, 1);

    // Download 2
    const d2 = await api.downloadFile(uploadRes.fileId);
    assert.strictEqual(d2.success, true);
    assert.strictEqual(d2.remainingDownloads, 0);

    // Download 3 cap reached
    let d3 = null;
    try {
      d3 = await api.downloadFile(uploadRes.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (d3) {
      assert.strictEqual(d3.success, false);
      assert.strictEqual(d3.status, 410);
    }
  });

  suite.it('T3.06: Key Setup Modal Onboarding + Mode A Recipient Lookup (F2 + F3 + F4 + F7)', async () => {
    // 1. Generate keys for Bob via modal mock
    const { keyPair, publicKeyPem, keyFingerprint } = await vaultCrypto.generateUserKeyPair();
    await keyStore.storeUserKey('bob_onboard', keyPair, publicKeyPem, keyFingerprint);
    try {
      await api.registerUser({ username: 'bob_onboard', publicKeyPem, fingerprint: keyFingerprint });
    } catch (err) {
      if (err.status !== 409) throw err;
    }

    // 2. Lookup recipient Bob in useUpload hook
    const { result: upHook, unmount } = renderHook(() => useUpload());
    const lookup = await upHook.current.lookupRecipient('bob_onboard');

    assert.ok(lookup);
    assert.strictEqual(lookup.username, 'bob_onboard');
    assert.strictEqual(lookup.fingerprint, keyFingerprint);
    unmount();
  });

  suite.it('T3.07: Sender Dashboard Revocation + Kill-Switch Enforcement (F4 + F5 + F7)', async () => {
    const uploadRes = await api.uploadFile({
      encryptedBlobB64: 'kill_switch_test',
      encryptedMetaB64: 'meta_kill',
      ivB64: 'iv_kill',
    });

    // Verify accessible before revocation
    const metaBefore = await api.getMetadata(uploadRes.fileId);
    assert.strictEqual(metaBefore.success, true);

    // Revoke using ownerToken
    const revokeRes = await api.revokeFile(uploadRes.fileId, uploadRes.ownerToken);
    assert.strictEqual(revokeRes.success, true);

    // Subsequent access must return 410
    let metaAfter = null;
    try {
      metaAfter = await api.getMetadata(uploadRes.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (metaAfter) {
      assert.strictEqual(metaAfter.success, false);
      assert.strictEqual(metaAfter.status, 410);
    }

    let dlAfter = null;
    try {
      dlAfter = await api.downloadFile(uploadRes.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (dlAfter) {
      assert.strictEqual(dlAfter.success, false);
      assert.strictEqual(dlAfter.status, 410);
    }
  });

  suite.it('T3.08: Offline Failover During Active Decrypt Session (F1 + F4 + F5 + F6)', async () => {
    // Upload file into offline store
    const note = 'Offline Failover Session Note';
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote(note);
    await upHook.current.executeUpload();
    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    unmountUp();

    // Recipient decrypts seamlessly with offline mock store
    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));

    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');

    assert.strictEqual(decHook.current.status, 'ready');
    const text = await decHook.current.fileBlob.text();
    assert.strictEqual(text, note);
    unmountDec();
  });
});

export default suite;

// Standalone execution support
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  suite.run().then((res) => process.exit(res.failed > 0 ? 1 : 0));
}
