/**
 * test/hooks-test.mjs
 * Comprehensive Standalone Verification Suite for VaultX Milestone 3 Functional State Hooks:
 * - hooks/useUpload.js
 * - hooks/useDecrypt.js
 */

import { setupMockDOM, renderHook, blobTracker, mockLocalStorage, waitFor } from './e2e/helpers/mock-dom.mjs';
import { useUpload } from '../hooks/useUpload.js';
import { useDecrypt, extractKeyFromHash } from '../hooks/useDecrypt.js';
import { generateUserKeyPair, encryptFileAndMeta, bufferToBase64, bufferToBase64Url, base64UrlToBuffer } from '../lib/vaultCrypto.js';
import { storeUserKey } from '../lib/keyStore.js';
import { registerUser, uploadFile, getMetadata, downloadFile, ApiError } from '../lib/api.js';

// Initialize mock DOM environment
setupMockDOM();

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (!condition) {
    failed++;
    console.error(`  ❌ FAIL: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  passed++;
  console.log(`  ✅ PASS: ${message}`);
}

async function assertThrowsAsync(fn, expectedSnippet, message) {
  try {
    await fn();
    failed++;
    console.error(`  ❌ FAIL (Expected error but succeeded): ${message}`);
    throw new Error(`Expected error but function succeeded: ${message}`);
  } catch (err) {
    if (expectedSnippet) {
      const match =
        (err.message && err.message.toLowerCase().includes(String(expectedSnippet).toLowerCase())) ||
        (err.code && err.code === expectedSnippet) ||
        (err.status && err.status === expectedSnippet);
      if (!match) {
        failed++;
        console.error(`  ❌ FAIL (Unexpected error message): ${err.message}`);
        throw err;
      }
    }
    passed++;
    console.log(`  ✅ PASS: ${message} (Threw: ${err.message || err.code})`);
  }
}

console.log('='.repeat(70));
console.log(' VaultX Milestone 3: Core Functional State Hooks Verification Suite');
console.log('='.repeat(70));

async function runTests() {
  // -------------------------------------------------------------
  // Test Suite 1: useUpload Form Validation, State Machine & Reset
  // -------------------------------------------------------------
  console.log('\n[Suite 1] useUpload Validation, State Transitions & Reset');
  {
    const { result, unmount } = renderHook(() => useUpload());

    // 1.1 Initial default states
    assert(result.current.tab === 'file', 'Default tab is "file"');
    assert(result.current.mode === 'MODE_B', 'Default mode is "MODE_B"');
    assert(result.current.file === null, 'Initial file is null');
    assert(result.current.textNote === '', 'Initial textNote is empty');
    assert(result.current.status === 'idle', 'Initial status is "idle"');
    assert(result.current.result === null, 'Initial result is null');
    assert(result.current.error === null, 'Initial error is null');
    assert(result.current.expiryMinutes === 60, 'Default expiryMinutes is 60');
    assert(result.current.maxDownloads === 5, 'Default maxDownloads is 5');
    assert(result.current.isBurnAfterReading === false, 'Default isBurnAfterReading is false');
    assert(result.current.isPasswordProtected === false, 'Default isPasswordProtected is false');

    // 1.2 Empty file validation rejection
    await result.current.executeUpload();
    assert(result.current.status === 'idle', 'Status remains "idle" after empty file validation rejection');
    assert(result.current.error === 'Please select a file to encrypt', 'Error message set for missing file');
    assert(result.current.result === null, 'Result remains null on validation failure');

    // 1.3 Empty secret note validation rejection
    result.current.setTab('text');
    await result.current.executeUpload();
    assert(result.current.status === 'idle', 'Status remains "idle" after empty note rejection');
    assert(result.current.error === 'Secret note cannot be empty', 'Error message set for empty secret note');

    // 1.4 Mode A missing recipient validation rejection
    result.current.setTab('text');
    result.current.setTextNote('Some secret text');
    result.current.setMode('MODE_A');
    await result.current.executeUpload();
    assert(result.current.status === 'idle', 'Status remains "idle" when Mode A recipient is missing');
    assert(result.current.error === 'Recipient username required for Mode A', 'Error message set for missing recipient');

    // 1.5 Password-protected without password rejection
    result.current.setMode('MODE_B');
    result.current.setIsPasswordProtected(true);
    result.current.setPassword('');
    await result.current.executeUpload();
    assert(result.current.status === 'idle', 'Status remains "idle" when password protection has empty password');
    assert(result.current.error.includes('Password is required'), 'Error message set for empty password');

    // 1.6 Full state reset
    result.current.reset();
    assert(result.current.tab === 'file', 'Reset restores tab to "file"');
    assert(result.current.mode === 'MODE_B', 'Reset restores mode to "MODE_B"');
    assert(result.current.file === null, 'Reset clears file');
    assert(result.current.textNote === '', 'Reset clears textNote');
    assert(result.current.isPasswordProtected === false, 'Reset clears isPasswordProtected');
    assert(result.current.password === '', 'Reset clears password');
    assert(result.current.status === 'idle', 'Reset restores status to "idle"');
    assert(result.current.error === null, 'Reset clears error');

    unmount();
  }

  // -------------------------------------------------------------
  // Test Suite 2: Mode B Standard File Upload and Decrypt Roundtrip
  // -------------------------------------------------------------
  console.log('\n[Suite 2] Mode B File Upload & Decrypt Roundtrip');
  let modeBShareUrl;
  let modeBFileId;
  let modeBChecksum;
  const testPlaintext = 'VaultX Milestone 3 Confidential Document 2026';
  const testFileBytes = new TextEncoder().encode(testPlaintext);

  {
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());

    const mockFile = {
      name: 'annual_report.pdf',
      type: 'application/pdf',
      arrayBuffer: async () => testFileBytes.buffer
    };

    upHook.current.setFile(mockFile);
    upHook.current.setExpiryMinutes(120);
    upHook.current.setMaxDownloads(3);

    const uploadPromise = upHook.current.executeUpload();
    const upRes = await uploadPromise;

    assert(upHook.current.status === 'success', 'useUpload status reached "success"');
    assert(Boolean(upRes.fileId), `FileId generated: ${upRes.fileId}`);
    assert(Boolean(upRes.ownerToken), 'Owner token generated');
    assert(Boolean(upRes.fullShareUrl), 'fullShareUrl generated');
    assert(upRes.fullShareUrl.includes('#key='), 'fullShareUrl carries #key= fragment');
    assert(upRes.qrCodePayload === upRes.fullShareUrl, 'qrCodePayload matches fullShareUrl');
    assert(Boolean(upRes.expiresAt), 'expiresAt generated');
    assert(Boolean(upRes.sha256Checksum), 'sha256Checksum generated');

    modeBShareUrl = upRes.fullShareUrl;
    modeBFileId = upRes.fileId;
    modeBChecksum = upRes.sha256Checksum;

    unmountUp();

    // Now Decrypt using useDecrypt
    const hash = modeBShareUrl.slice(modeBShareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(modeBFileId, hash));

    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');

    assert(decHook.current.hasFragmentKey === true, 'hasFragmentKey is true');
    assert(decHook.current.status === 'ready', 'useDecrypt status transitioned to "ready"');
    assert(decHook.current.isChecksumValid === true, 'isChecksumValid is true');
    assert(decHook.current.sha256Checksum === modeBChecksum, 'sha256Checksum matches upload checksum');
    assert(Boolean(decHook.current.fileBlob), 'fileBlob is present');
    assert(decHook.current.previewType === 'pdf', 'previewType detected as "pdf"');
    assert(Boolean(decHook.current.previewUrl), 'previewUrl was generated');
    assert(decHook.current.decryptedMeta?.filename === 'annual_report.pdf', 'Decrypted metadata filename matches');

    // Test downloadToDisk callable
    assert(typeof decHook.current.downloadToDisk === 'function', 'downloadToDisk is exposed as function');
    decHook.current.downloadToDisk(); // should execute cleanly without error

    unmountDec();
  }

  // -------------------------------------------------------------
  // Test Suite 3: Mode B Password Challenge Workflow
  // -------------------------------------------------------------
  console.log('\n[Suite 3] Mode B Password Challenge Workflow');
  {
    const password = 'SuperSecretVaultXPassword!2026';
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());

    upHook.current.setTab('text');
    upHook.current.setTextNote('Confidential text behind password barrier');
    upHook.current.setIsPasswordProtected(true);
    upHook.current.setPassword(password);

    await upHook.current.executeUpload();
    assert(upHook.current.status === 'success', 'Password-protected upload succeeded');

    const pwShareUrl = upHook.current.result.fullShareUrl;
    const pwFileId = upHook.current.result.fileId;
    unmountUp();

    // Mount recipient hook
    const hash = pwShareUrl.slice(pwShareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(pwFileId, hash));

    await waitFor(() => decHook.current.status === 'password_required');
    assert(decHook.current.status === 'password_required', 'Status transitioned to "password_required"');

    // Attempt decryption with wrong password
    try {
      await decHook.current.submitPassword('WrongPassword123!');
    } catch (_) {}
    assert(
      decHook.current.status === 'password_required',
      'Status remains "password_required" after wrong password attempt'
    );
    assert(decHook.current.error !== null, 'Error message recorded for failed password attempt');

    // Submit correct password
    await decHook.current.submitPassword(password);
    assert(decHook.current.status === 'ready', 'Status transitioned to "ready" upon correct password submission');
    assert(decHook.current.isChecksumValid === true, 'Checksum integrity verified');
    assert(decHook.current.textContent === 'Confidential text behind password barrier', 'Text note content verified');

    unmountDec();
  }

  // -------------------------------------------------------------
  // Test Suite 4: Mode A Registered Recipient (RSA-OAEP Key Wrapping)
  // -------------------------------------------------------------
  console.log('\n[Suite 4] Mode A Recipient RSA-OAEP Key Wrapping Roundtrip');
  {
    // Generate recipient keypair for "david"
    const davidKeys = await generateUserKeyPair();
    await storeUserKey('david', davidKeys.keyPair, davidKeys.publicKeyPem, davidKeys.keyFingerprint);
    await registerUser({
      username: 'david',
      publicKeyPem: davidKeys.publicKeyPem,
      fingerprint: davidKeys.keyFingerprint
    });

    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());

    upHook.current.setTab('text');
    upHook.current.setTextNote('Mode A Secret Message for David');
    upHook.current.setMode('MODE_A');
    upHook.current.setRecipientUsername('david');

    // Lookup recipient
    const lookup = await upHook.current.lookupRecipient('david');
    assert(lookup && lookup.publicKeyPem === davidKeys.publicKeyPem, 'lookupRecipient found David\'s public key');
    assert(upHook.current.recipientInfo !== null, 'recipientInfo state populated');

    await upHook.current.executeUpload();
    assert(upHook.current.status === 'success', 'Mode A upload succeeded');

    const modeAShareUrl = upHook.current.result.fullShareUrl;
    const modeAFileId = upHook.current.result.fileId;
    assert(!modeAShareUrl.includes('#key='), 'Mode A fullShareUrl contains NO #key= fragment (Zero-Fragment Invariant)');

    unmountUp();

    // Recipient decrypts Mode A payload using KeyStore private key
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(modeAFileId, null, 'david'));

    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');
    assert(decHook.current.status === 'ready', 'Mode A useDecrypt transitioned to "ready"');
    assert(decHook.current.isChecksumValid === true, 'Mode A checksum valid');
    assert(decHook.current.textContent === 'Mode A Secret Message for David', 'Mode A decrypted text content verified');

    unmountDec();
  }

  // -------------------------------------------------------------
  // Test Suite 5: Secret Text Notes (isNote: true & textContent)
  // -------------------------------------------------------------
  console.log('\n[Suite 5] Secret Text Note Workflow (isNote: true & textContent)');
  {
    const noteContent = 'Top Secret VaultX Note 🚀 2026';
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());

    upHook.current.setTab('text');
    upHook.current.setTextNote(noteContent);
    await upHook.current.executeUpload();
    assert(upHook.current.status === 'success', 'Secret note upload succeeded');

    const noteShareUrl = upHook.current.result.fullShareUrl;
    const noteFileId = upHook.current.result.fileId;
    unmountUp();

    const hash = noteShareUrl.slice(noteShareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(noteFileId, hash));

    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');
    assert(decHook.current.status === 'ready', 'Secret note decrypted successfully');
    assert(decHook.current.previewType === 'text', 'previewType is "text"');
    assert(decHook.current.textContent === noteContent, 'textContent matches secret note plaintext');
    assert(decHook.current.decryptedMeta?.isNote === true, 'decryptedMeta.isNote is true');

    unmountDec();
  }

  // -------------------------------------------------------------
  // Test Suite 6: Checksum Tampering Detection (Tampered State)
  // -------------------------------------------------------------
  console.log('\n[Suite 6] Integrity Verification & Tampering Detection');
  {
    const originalText = 'Tamper-resistant message 12345';
    const rawBytes = new TextEncoder().encode(originalText);
    const enc = await encryptFileAndMeta(rawBytes, { filename: 'secure.txt' }, 'MODE_B');

    // Create a modified metadata with a mismatching fake checksum
    const rawAesKey = base64UrlToBuffer(enc.fragmentKeyB64);
    const aesKey = await globalThis.crypto.subtle.importKey('raw', rawAesKey, { name: 'AES-GCM' }, false, ['encrypt']);
    const tamperedMeta = {
      filename: 'secure.txt',
      checksum: '0000000000000000000000000000000000000000000000000000000000000000'
    };
    const metaIv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const tamperedMetaEnc = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metaIv },
      aesKey,
      new TextEncoder().encode(JSON.stringify(tamperedMeta))
    );

    const upRes = await uploadFile({
      encryptedBlob: enc.encryptedBlob,
      ivB64: enc.ivB64,
      metaIvB64: bufferToBase64(metaIv),
      encryptedMetaB64: bufferToBase64(tamperedMetaEnc),
      mode: 'MODE_B'
    });

    const hash = `#key=${enc.fragmentKeyB64}`;
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(upRes.fileId, hash));

    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');
    assert(decHook.current.status === 'tampered', 'Status transitioned to "tampered" upon checksum mismatch');
    assert(decHook.current.isChecksumValid === false, 'isChecksumValid is false');
    assert(decHook.current.error.includes('checksum verification failed'), 'Error describes checksum verification failure');

    unmountDec();
  }

  // -------------------------------------------------------------
  // Test Suite 7: Object URL Creation & Memory Cleanup Lifecycle
  // -------------------------------------------------------------
  console.log('\n[Suite 7] In-Memory Preview URL & Garbage Collection Hygiene');
  {
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Preview Hygiene Payload');
    await upHook.current.executeUpload();

    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    unmountUp();

    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));

    await waitFor(() => decHook.current.previewUrl !== null);
    const previewUrl = decHook.current.previewUrl;
    assert(Boolean(previewUrl) && previewUrl.startsWith('blob:'), 'Valid blob previewUrl created');

    const activeBefore = blobTracker.getActiveUrls();
    assert(activeBefore.includes(previewUrl), 'previewUrl tracked in active blob registry');

    // Test explicit cleanupPreview
    decHook.current.cleanupPreview();
    assert(decHook.current.previewUrl === null, 'cleanupPreview cleared previewUrl in state');
    assert(!blobTracker.getActiveUrls().includes(previewUrl), 'cleanupPreview revoked previewUrl in registry');

    unmountDec();
  }

  // -------------------------------------------------------------
  // Test Suite 8: LocalStorage Persistence (vaultx_sent_vaults)
  // -------------------------------------------------------------
  console.log('\n[Suite 8] LocalStorage Audit Trail Persistence');
  {
    const rawStoredBefore = mockLocalStorage.getItem('vaultx_sent_vaults');
    const listBefore = rawStoredBefore ? JSON.parse(rawStoredBefore) : [];

    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Audit Trail Persistence Test');
    await upHook.current.executeUpload();

    const fileId = upHook.current.result.fileId;
    const ownerToken = upHook.current.result.ownerToken;
    unmountUp();

    const rawStoredAfter = mockLocalStorage.getItem('vaultx_sent_vaults');
    assert(Boolean(rawStoredAfter), 'vaultx_sent_vaults is present in localStorage');

    const listAfter = JSON.parse(rawStoredAfter);
    assert(listAfter.length > listBefore.length, 'New record appended to vaultx_sent_vaults');

    const savedRecord = listAfter[0];
    assert(savedRecord.id === fileId || savedRecord.fileId === fileId, 'Saved record id matches upload fileId');
    assert(savedRecord.ownerToken === ownerToken, 'Saved record ownerToken matches upload ownerToken');
    assert(Boolean(savedRecord.createdAt), 'Saved record has createdAt timestamp');
    assert(Boolean(savedRecord.expiresAt), 'Saved record has expiresAt timestamp');
    assert(savedRecord.filename === 'secret-note.txt', 'Saved record has filename');
  }

  // -------------------------------------------------------------
  // Test Suite 9: Manual Key Entry Fallback
  // -------------------------------------------------------------
  console.log('\n[Suite 9] Manual Key Entry Fallback');
  {
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Manual Key Test');
    await upHook.current.executeUpload();

    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    const key = extractKeyFromHash(shareUrl);
    unmountUp();

    // Mount useDecrypt with empty fragment
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, ''));
    await waitFor(() => decHook.current.status !== 'loading_meta');

    assert(decHook.current.hasFragmentKey === false, 'hasFragmentKey is false without fragment');
    assert(decHook.current.status === 'idle', 'Status remains "idle" awaiting manual key');

    // Supply manual key
    decHook.current.setManualKey(key);
    await waitFor(() => decHook.current.status === 'ready');

    assert(decHook.current.status === 'ready', 'Status transitioned to "ready" after manual key entry');
    assert(decHook.current.textContent === 'Manual Key Test', 'Plaintext verified after manual key entry');

    unmountDec();
  }

  // -------------------------------------------------------------
  // Test Suite 10: Revocation Action (destroyNow)
  // -------------------------------------------------------------
  console.log('\n[Suite 10] Revocation Action (destroyNow)');
  {
    const { result: upHook, unmount: unmountUp } = renderHook(() => useUpload());
    upHook.current.setTab('text');
    upHook.current.setTextNote('Revocation Kill-Switch Test');
    await upHook.current.executeUpload();

    const shareUrl = upHook.current.result.fullShareUrl;
    const fileId = upHook.current.result.fileId;
    const ownerToken = upHook.current.result.ownerToken;
    unmountUp();

    const hash = shareUrl.slice(shareUrl.indexOf('#'));
    const { result: decHook, unmount: unmountDec } = renderHook(() => useDecrypt(fileId, hash));
    await waitFor(() => decHook.current.status !== 'loading_meta' && decHook.current.status !== 'decrypting');
    assert(decHook.current.status === 'ready', 'Vault is ready before revocation');

    // Trigger destroyNow
    await decHook.current.destroyNow(ownerToken);
    assert(decHook.current.status === 'idle', 'Status transitioned to "idle" after destruction');
    assert(decHook.current.previewUrl === null, 'previewUrl cleared after destruction');
    assert(decHook.current.fileBlob === null, 'fileBlob cleared after destruction');

    // Confirm file revoked at API level (410 Gone)
    await assertThrowsAsync(
      async () => await getMetadata(fileId),
      410,
      'Subsequent getMetadata call throws 410 Revoked'
    );

    unmountDec();
  }

  // -------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------
  console.log('\n' + '='.repeat(70));
  console.log(` HOOKS VERIFICATION COMPLETE: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(70));

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('\n❌ Unhandled error in hooks verification test runner:', err);
  process.exit(1);
});
