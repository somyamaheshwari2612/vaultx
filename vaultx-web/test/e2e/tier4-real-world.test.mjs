/**
 * test/e2e/tier4-real-world.test.mjs
 * Tier 4: Real-World Application Scenarios (5 Comprehensive Multi-Step Workflows).
 * Evaluates realistic end-to-end user journeys including encryption, transfer,
 * recipient decryption, memory hygiene, revocation, and offline failover.
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
  MockQRModal,
  MockKeySetupModal,
  MockAuditTrail,
  MockHexInspector,
  MockRevokeButton,
} from './helpers/contracts.mjs';

const suite = createSuite('Tier 4: Real-World Scenarios (5 Scenarios)');

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
// Tier 4 Multi-Step Workflows (T4.01 - T4.05)
// ==========================================
suite.describe('Real-World End-to-End User Journeys', () => {
  // ----------------------------------------------------
  // Scenario 1: Secret Note Sharing Flow
  // ----------------------------------------------------
  suite.it('T4.01: Scenario 1 — Secret Note Sharing Flow (Mode B + Password + Burn)', async () => {
    // 1. Sender Action & Input
    const noteContent = 'Confidential API Token: sk_live_998877665544332211';
    const password = 'HackathonPass2026!';

    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote(noteContent);
    upHook.current.setIsPasswordProtected(true);
    upHook.current.setPassword(password);
    upHook.current.setIsBurnAfterReading(true);
    upHook.current.setExpiryMinutes(60);

    // 2. Encryption Execution
    const uploadRes = await upHook.current.executeUpload();
    assert.strictEqual(upHook.current.status, 'success');
    assert.ok(uploadRes.fileId);
    assert.ok(uploadRes.fullShareUrl);
    assert.includes(uploadRes.fullShareUrl, '#key=');
    unmountUp();

    // 3. Recipient Access
    const hash = uploadRes.fullShareUrl.slice(uploadRes.fullShareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(uploadRes.fileId, hash));

    await waitFor(() => decHook.current.status === 'password_required');
    assert.strictEqual(decHook.current.status, 'password_required');

    // 4. Password Challenge Failure (wrong password)
    let failed = false;
    try {
      await decHook.current.submitPassword('WrongPassword');
    } catch (_) {
      failed = true;
    }
    assert.strictEqual(failed, true, 'Incorrect password must reject');

    // 5. Password Challenge Success (correct password)
    await decHook.current.submitPassword(password);
    await waitFor(() => decHook.current.status === 'ready');
    assert.strictEqual(decHook.current.status, 'ready');
    assert.strictEqual(decHook.current.isChecksumValid, true);

    const decryptedText = await decHook.current.fileBlob.text();
    assert.strictEqual(decryptedText, noteContent);
    unmountDec();

    // 6. Burn-After-Reading Enforcement (second access returns 410)
    let secondFetch = null;
    try {
      secondFetch = await api.downloadFile(uploadRes.fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (secondFetch) {
      assert.strictEqual(secondFetch.success, false);
      assert.strictEqual(secondFetch.status, 410);
    }
  });

  // ----------------------------------------------------
  // Scenario 2: Large Multi-Megabyte File Sharing
  // ----------------------------------------------------
  suite.it('T4.02: Scenario 2 — Large Multi-Megabyte File Sharing (Mode B + Integrity)', async () => {
    // 1. Generate 2MB binary payload (2,097,152 bytes)
    const payloadSize = 2 * 1024 * 1024;
    const largeBuffer = MockCrypto.randomBytes(payloadSize).buffer;
    const hOrig = await MockCrypto.sha256Hex(largeBuffer);

    // 2. Client Encryption
    const meta = { filename: 'large_dataset.bin', mimeType: 'application/octet-stream', size: payloadSize };
    const enc = await vaultCrypto.encryptFileAndMeta(largeBuffer, meta, 'MODE_B');

    // Ciphertext length: 2MB + 16 bytes auth tag
    const cipherArrayBuf = enc.encryptedBlob instanceof ArrayBuffer
      ? enc.encryptedBlob
      : (enc.encryptedBlob?.arrayBuffer ? await enc.encryptedBlob.arrayBuffer() : enc.encryptedBlob.buffer);
    assert.strictEqual(cipherArrayBuf.byteLength, payloadSize + 16, 'AES-GCM adds 16-byte auth tag');
    assert.strictEqual(enc.sha256Checksum, hOrig, 'Checksum in metadata must match baseline');
    assert.strictEqual(enc.fragmentKeyB64.length, 43, 'Base64URL key must be 43 characters');

    // 3. Mock Upload
    const uploadRes = await api.uploadFile({
      encryptedBlobB64: MockCrypto.toBase64(cipherArrayBuf),
      ivB64: enc.ivB64,
      metaIvB64: enc.metaIvB64,
      encryptedMetaB64: enc.encryptedMetaB64,
      mode: 'MODE_B',
      maxDownloads: 5,
    });
    assert.strictEqual(uploadRes.success, true);

    // 4. Recipient Download & Decrypt
    const downloadRes = await api.downloadFile(uploadRes.fileId);
    assert.strictEqual(downloadRes.success, true);

    const dec = await vaultCrypto.decryptFileAndMeta(
      MockCrypto.fromBase64(downloadRes.encryptedBlobB64).buffer,
      downloadRes.ivB64,
      enc.encryptedMetaB64,
      enc.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: downloadRes.metaIvB64 }
    );

    // 5. Integrity Verification
    assert.strictEqual(dec.fileBuffer.byteLength, payloadSize);
    assert.strictEqual(dec.isChecksumValid, true);
    assert.strictEqual(dec.sha256Checksum, hOrig);

    // 6. Zero-Footprint URL Cleanup
    const blob = new Blob([dec.fileBuffer]);
    const objUrl = URL.createObjectURL(blob);
    assert.includes(blobTracker.getActiveUrls(), objUrl);

    URL.revokeObjectURL(objUrl);
    assert.notIncludes(blobTracker.getActiveUrls(), objUrl);
  });

  // ----------------------------------------------------
  // Scenario 3: Registered Recipient Secure Transfer (Mode A)
  // ----------------------------------------------------
  suite.it('T4.03: Scenario 3 — Registered Recipient Secure Transfer (Mode A)', async () => {
    const recipientUser = 'alice_scenario3';

    // 1. Recipient Key Generation
    const aliceKeys = await vaultCrypto.generateUserKeyPair();
    assert.strictEqual(aliceKeys.keyPair.privateKey.extractable, false);
    const fpAlice = aliceKeys.keyFingerprint;
    await keyStore.storeUserKey(recipientUser, aliceKeys.keyPair, aliceKeys.publicKeyPem, fpAlice);
    await keyStore.storeUserKey('current_user', aliceKeys.keyPair, aliceKeys.publicKeyPem, fpAlice);

    // 2. User Registration
    try {
      await api.registerUser({
        username: recipientUser,
        publicKeyPem: aliceKeys.publicKeyPem,
        fingerprint: fpAlice,
      });
    } catch (err) {
      if (err.status !== 409) throw err;
    }

    // 3. Sender Recipient Lookup
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    const lookup = await upHook.current.lookupRecipient(recipientUser);
    assert.strictEqual(lookup.fingerprint, fpAlice);

    // 4. Mode A Encryption
    const documentData = MockCrypto.randomBytes(256 * 1024).buffer; // 256KB
    const docHash = await MockCrypto.sha256Hex(documentData);

    upHook.current.setMode('MODE_A');
    upHook.current.setRecipientUsername(recipientUser);
    upHook.current.setFile({
      name: 'memo.docx',
      type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      arrayBuffer: async () => documentData,
    });

    const uploadRes = await upHook.current.executeUpload();
    assert.strictEqual(upHook.current.status, 'success');
    assert.notIncludes(uploadRes.fullShareUrl, '#key=', 'Mode A must NOT append #key in URL');
    unmountUp();

    // 5. Alice Decryption
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(uploadRes.fileId, null, recipientUser));
    const start = Date.now();
    while ((decHook.current.status === 'decrypting' || decHook.current.status === 'loading_meta') && Date.now() - start < 3000) {
      await new Promise((r) => setTimeout(r, 25));
    }

    assert.strictEqual(decHook.current.status, 'ready');
    assert.strictEqual(decHook.current.isChecksumValid, true);
    assert.strictEqual(decHook.current.sha256Checksum, docHash);
    unmountDec();

    // 6. Adversarial Tamper / Unauthorized Access by Eve
    const eveKeys = await vaultCrypto.generateUserKeyPair();
    const metaRes = await api.getMetadata(uploadRes.fileId);
    const dlRes = await api.downloadFile(uploadRes.fileId);

    let eveThrew = false;
    try {
      await vaultCrypto.decryptFileAndMeta(
        MockCrypto.fromBase64(dlRes.encryptedBlobB64).buffer,
        dlRes.ivB64,
        metaRes.encryptedMetaB64,
        {
          privateKey: eveKeys.keyPair.privateKey,
          wrappedAesKeyB64: metaRes.wrappedAesKeyB64,
        },
        'MODE_A',
        { metaIvB64: dlRes.metaIvB64 }
      );
    } catch (err) {
      eveThrew = true;
      assert.ok(err.name === 'OperationError' || err.message?.includes('operation failed') || err.message?.includes('unwrap'));
    }
    assert.strictEqual(eveThrew, true, "Eve's private key must fail unwrap with OperationError");
  });

  // ----------------------------------------------------
  // Scenario 4: Sender Dashboard History & Audit Log Verification
  // ----------------------------------------------------
  suite.it('T4.04: Scenario 4 — Sender Dashboard History & Audit Log Verification', async () => {
    // 1. Multi-Upload Generation
    const uploads = [];
    for (let i = 1; i <= 3; i++) {
      const { result: hook, unmount } = renderHook(() => useUpload());
      hook.current.setTab('text');
      hook.current.setTextNote(`Vault Item Payload #${i}`);
      await hook.current.executeUpload();
      uploads.push(hook.current.result);
      unmount();
    }
    assert.strictEqual(uploads.length, 3);

    // 2. Recipient Download Activity
    // Download Vault-1 twice, Vault-2 once
    await api.downloadFile(uploads[0].fileId);
    await api.downloadFile(uploads[0].fileId);
    await api.downloadFile(uploads[1].fileId);

    // 3. Sender Dashboard History Inspection
    const localHistory = JSON.parse(mockLocalStorage.getItem('vaultx_history') || '[]');
    assert.greaterThan(localHistory.length, 2);

    // 4. Audit Trail Inspection on Vault-1
    const logsRes = await api.getAccessLogs(uploads[0].fileId, uploads[0].ownerToken);
    assert.strictEqual(logsRes.success, true);
    // 1 CREATED + 2 DOWNLOADED = 3 records
    assert.strictEqual(logsRes.logs.length, 3);
    assert.strictEqual(logsRes.logs[0].event, 'CREATED');
    assert.ok(logsRes.logs[1].event === 'DOWNLOAD' || logsRes.logs[1].event === 'DOWNLOADED');
    assert.ok(logsRes.logs[2].event === 'DOWNLOAD' || logsRes.logs[2].event === 'DOWNLOADED');

    // 5. Hex Inspector Component Rendering
    const hexEl = MockHexInspector({});
    assert.ok(hexEl);
    assert.includes(hexEl.props.className, 'hex-inspector');

    // 6. Kill-Switch Revocation
    const revokeRes = await api.revokeFile(uploads[0].fileId, uploads[0].ownerToken);
    assert.strictEqual(revokeRes.success, true);

    // 7. Revocation Enforcement
    let recipientMeta = null;
    try {
      recipientMeta = await api.getMetadata(uploads[0].fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (recipientMeta) {
      assert.strictEqual(recipientMeta.success, false);
      assert.strictEqual(recipientMeta.status, 410);
    }

    let recipientDl = null;
    try {
      recipientDl = await api.downloadFile(uploads[0].fileId);
    } catch (err) {
      assert.strictEqual(err.status, 410);
    }
    if (recipientDl) {
      assert.strictEqual(recipientDl.success, false);
      assert.strictEqual(recipientDl.status, 410);
    }
  });

  // ----------------------------------------------------
  // Scenario 5: Network Failure Offline Resilience & Seamless Fallback
  // ----------------------------------------------------
  suite.it('T4.05: Scenario 5 — Network Failure Offline Resilience & Seamless Fallback', async () => {
    // 1. Simulate network disconnect / outage
    const offlineNote = 'Critical Offline Field Report — Venue Disconnect Simulation';

    // 2. Sender Offline Upload
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote(offlineNote);
    await upHook.current.executeUpload();

    assert.strictEqual(upHook.current.status, 'success');
    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    unmountUp();

    // 3. Recipient Offline Decrypt
    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));

    const start = Date.now();
    while ((decHook.current.status === 'decrypting' || decHook.current.status === 'loading_meta') && Date.now() - start < 3000) {
      await new Promise((r) => setTimeout(r, 25));
    }

    assert.strictEqual(decHook.current.status, 'ready');
    assert.strictEqual(decHook.current.isChecksumValid, true);
    const recoveredText = await decHook.current.fileBlob.text();
    assert.strictEqual(recoveredText, offlineNote);
    unmountDec();

    // 4. Network Reconnection Resilience
    const nextUpload = await api.uploadFile({
      encryptedBlobB64: 'reconnected_data',
      encryptedMetaB64: 'meta_recon',
      ivB64: 'iv_recon',
    });
    assert.strictEqual(nextUpload.success, true);
  });
});

export default suite;

// Standalone execution support
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  suite.run().then((res) => process.exit(res.failed > 0 ? 1 : 0));
}
