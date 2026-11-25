/**
 * VaultX Cryptography & API Verification Suite
 * Standalone offline test runner verifying Web Crypto operations, key storage, and API contracts.
 */

import {
  generateUserKeyPair,
  encryptFileAndMeta,
  decryptFileAndMeta,
  computeSha256Checksum,
  computeKeyFingerprint,
  exportPublicKeyPem,
  bufferToBase64,
  base64ToBuffer,
  bufferToBase64Url,
  base64UrlToBuffer
} from '../lib/vaultCrypto.js';

import {
  storeUserKey,
  getUserKey,
  hasUserKey,
  clearUserKey,
  openKeyStoreDB
} from '../lib/keyStore.js';

import {
  registerUser,
  getUserPubKey,
  uploadFile,
  getMetadata,
  downloadFile,
  getAccessLogs,
  revokeFile,
  ApiError
} from '../lib/api.js';

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

async function assertThrowsAsync(fn, expectedCodeOrSnippet, message) {
  try {
    await fn();
    failed++;
    console.error(`  ❌ FAIL (Expected error but succeeded): ${message}`);
    throw new Error(`Expected error but function succeeded: ${message}`);
  } catch (err) {
    if (expectedCodeOrSnippet) {
      const match =
        (err.code && err.code === expectedCodeOrSnippet) ||
        (err.status && err.status === expectedCodeOrSnippet) ||
        (err.message && err.message.toLowerCase().includes(String(expectedCodeOrSnippet).toLowerCase()));
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
console.log(' VaultX Milestone 2 Cryptography & Integration Verification Suite');
console.log('='.repeat(70));

async function runTests() {
  // -------------------------------------------------------------
  // Test Suite 1: Base64 and Base64URL Conversion Utilities
  // -------------------------------------------------------------
  console.log('\n[Suite 1] Base64 & Base64URL Encoding/Decoding');
  {
    const sampleBytes = new Uint8Array([0, 255, 128, 64, 32, 16, 8, 4, 2, 1, 63, 62]);
    const b64 = bufferToBase64(sampleBytes);
    const roundtripB64 = base64ToBuffer(b64);
    assert(
      Buffer.from(sampleBytes).equals(Buffer.from(roundtripB64)),
      'Base64 roundtrip matches original binary bytes'
    );

    const b64url = bufferToBase64Url(sampleBytes);
    assert(!b64url.includes('+') && !b64url.includes('/') && !b64url.includes('='), 'Base64URL does not contain +, /, or =');
    const roundtripB64Url = base64UrlToBuffer(b64url);
    assert(
      Buffer.from(sampleBytes).equals(Buffer.from(roundtripB64Url)),
      'Base64URL roundtrip matches original binary bytes'
    );
  }

  // -------------------------------------------------------------
  // Test Suite 2: RSA-OAEP Keypair Generation & Security
  // -------------------------------------------------------------
  console.log('\n[Suite 2] RSA-OAEP Keypair Generation & Security Invariants');
  let userAlice;
  {
    userAlice = await generateUserKeyPair();
    assert(Boolean(userAlice.keyPair), 'Keypair object generated');
    assert(userAlice.keyPair.publicKey.extractable === true, 'Public key is extractable');
    assert(userAlice.keyPair.privateKey.extractable === false, 'Private key is strictly NON-EXTRACTABLE (extractable: false)');
    assert(userAlice.keyPair.publicKey.algorithm.name === 'RSA-OAEP', 'Algorithm is RSA-OAEP');
    assert(userAlice.keyPair.publicKey.algorithm.modulusLength === 2048, 'Modulus length is 2048 bits');

    // Verify non-extractable private key throws on export
    await assertThrowsAsync(
      async () => await crypto.subtle.exportKey('pkcs8', userAlice.keyPair.privateKey),
      'extractable',
      'Exporting non-extractable private key is blocked by Web Crypto'
    );

    assert(
      userAlice.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----\n') &&
      userAlice.publicKeyPem.endsWith('-----END PUBLIC KEY-----'),
      'Public key PEM format matches standard SPKI PEM markers'
    );

    const fpRegex = /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/;
    assert(fpRegex.test(userAlice.keyFingerprint), `Fingerprint formatted as colon-separated uppercase hex: ${userAlice.keyFingerprint.substring(0, 20)}...`);

    const derivedFp = await computeKeyFingerprint(userAlice.keyPair.publicKey);
    assert(derivedFp === userAlice.keyFingerprint, 'computeKeyFingerprint utility matches generated fingerprint');
  }

  // -------------------------------------------------------------
  // Test Suite 3: KeyStore Persistence (In-Memory / IndexedDB)
  // -------------------------------------------------------------
  console.log('\n[Suite 3] KeyStore Persistence & CRUD');
  {
    const db = await openKeyStoreDB();
    assert(Boolean(db), 'KeyStore DB initialized');

    const storeRes = await storeUserKey('alice', userAlice.keyPair, userAlice.publicKeyPem, userAlice.keyFingerprint);
    assert(storeRes.success === true, 'storeUserKey succeeded');

    const hasAlice = await hasUserKey('alice');
    assert(hasAlice === true, 'hasUserKey returns true for stored user');

    const retrieved = await getUserKey('alice');
    assert(retrieved && retrieved.username === 'alice', 'getUserKey retrieves stored user record');
    assert(retrieved.fingerprint === userAlice.keyFingerprint, 'Retrieved fingerprint matches original');
    assert(retrieved.keyPair.privateKey.extractable === false, 'Retrieved private key remains non-extractable');

    const clearRes = await clearUserKey('alice');
    assert(clearRes.success === true, 'clearUserKey succeeded');

    const hasAfterClear = await hasUserKey('alice');
    assert(hasAfterClear === false, 'hasUserKey returns false after clear');
    const getAfterClear = await getUserKey('alice');
    assert(getAfterClear === null, 'getUserKey returns null after clear');
  }

  // -------------------------------------------------------------
  // Test Suite 4: Mode B Encryption & Decryption (Public Link)
  // -------------------------------------------------------------
  console.log('\n[Suite 4] Mode B Symmetric Encryption, Decryption & Checksum Verification');
  const secretData = 'VaultX Zero-Knowledge Test Payload: confidential document content 🔒 2026';
  const fileBytes = new TextEncoder().encode(secretData);
  const metadata = {
    filename: 'confidential.txt',
    mimeType: 'text/plain',
    size: fileBytes.byteLength,
    isNote: false,
    expiryMinutes: 30,
    maxDownloads: 3
  };

  let modeBResult;
  {
    modeBResult = await encryptFileAndMeta(fileBytes, metadata, 'MODE_B');
    assert(modeBResult.encryptedBlob && modeBResult.encryptedBlob.byteLength > 0, 'Encrypted blob is non-empty');
    assert(typeof modeBResult.ivB64 === 'string' && modeBResult.ivB64.length === 16, 'File IV is 12 bytes base64 (16 chars)');
    assert(typeof modeBResult.metaIvB64 === 'string' && modeBResult.metaIvB64.length === 16, 'Meta IV is 12 bytes base64 (16 chars)');
    assert(typeof modeBResult.encryptedMetaB64 === 'string', 'Encrypted metadata is base64 string');
    assert(typeof modeBResult.fragmentKeyB64 === 'string' && modeBResult.fragmentKeyB64.length === 43, 'Mode B fragment key is 32-byte raw AES key base64url (43 chars)');
    assert(modeBResult.wrappedAesKeyB64 === null, 'Mode B wrappedAesKeyB64 is null');

    const expectedChecksum = await computeSha256Checksum(fileBytes);
    assert(modeBResult.sha256Checksum === expectedChecksum, 'Calculated checksum matches plaintext SHA-256');

    // Decrypt Mode B
    const decrypted = await decryptFileAndMeta(
      modeBResult.encryptedBlob,
      modeBResult.ivB64,
      modeBResult.encryptedMetaB64,
      modeBResult.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: modeBResult.metaIvB64 }
    );

    const decryptedText = new TextDecoder().decode(decrypted.fileBuffer);
    assert(decryptedText === secretData, 'Decrypted plaintext matches original content exactly');
    assert(decrypted.metaObj.filename === metadata.filename, 'Decrypted metadata filename matches');
    assert(decrypted.metaObj.checksum === expectedChecksum, 'Decrypted metadata embeds correct checksum');
    assert(decrypted.isChecksumValid === true, 'Plaintext SHA-256 checksum integrity verification passed');
    assert(decrypted.sha256Checksum === expectedChecksum, 'Decrypted SHA-256 checksum matches expected');
  }

  // -------------------------------------------------------------
  // Test Suite 5: Mode B Password Protection (PBKDF2)
  // -------------------------------------------------------------
  console.log('\n[Suite 5] Mode B Password Protection with PBKDF2 Key Derivation');
  {
    const password = 'SuperSecretVaultXPassword!2026';
    const encPassResult = await encryptFileAndMeta(fileBytes, metadata, 'MODE_B', null, { password });

    assert(
      encPassResult.fragmentKeyB64.length > 43,
      `Password-protected fragment key is packed salt+IV+ciphertext (${encPassResult.fragmentKeyB64.length} chars)`
    );

    // Decrypt without password -> should fail
    await assertThrowsAsync(
      async () => await decryptFileAndMeta(
        encPassResult.encryptedBlob,
        encPassResult.ivB64,
        encPassResult.encryptedMetaB64,
        encPassResult.fragmentKeyB64,
        'MODE_B',
        { metaIvB64: encPassResult.metaIvB64 }
      ),
      'password',
      'Decryption without password throws PASSWORD_REQUIRED'
    );

    // Decrypt with wrong password -> should fail
    await assertThrowsAsync(
      async () => await decryptFileAndMeta(
        encPassResult.encryptedBlob,
        encPassResult.ivB64,
        encPassResult.encryptedMetaB64,
        encPassResult.fragmentKeyB64,
        'MODE_B',
        { metaIvB64: encPassResult.metaIvB64, password: 'WrongPassword123!' }
      ),
      'password',
      'Decryption with wrong password throws authentication failure'
    );

    // Decrypt with correct password -> should succeed
    const decPass = await decryptFileAndMeta(
      encPassResult.encryptedBlob,
      encPassResult.ivB64,
      encPassResult.encryptedMetaB64,
      encPassResult.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: encPassResult.metaIvB64, password }
    );

    const decText = new TextDecoder().decode(decPass.fileBuffer);
    assert(decText === secretData, 'Password-protected payload decrypted successfully with correct password');
    assert(decPass.isChecksumValid === true, 'Checksum integrity valid for password-protected vault');
  }

  // -------------------------------------------------------------
  // Test Suite 6: Mode A Asymmetric Key Wrapping (RSA-OAEP)
  // -------------------------------------------------------------
  console.log('\n[Suite 6] Mode A Recipient Key Wrapping (RSA-OAEP)');
  let userBob;
  {
    userBob = await generateUserKeyPair();

    // Mode A encryption using recipient's public key PEM
    const modeAResult = await encryptFileAndMeta(
      fileBytes,
      metadata,
      'MODE_A',
      userBob.publicKeyPem
    );

    assert(typeof modeAResult.wrappedAesKeyB64 === 'string', 'Mode A wrappedAesKeyB64 is base64 string');
    assert(modeAResult.fragmentKeyB64 === null, 'Mode A fragmentKeyB64 is null');

    // Decrypt Mode A with Bob's private key
    const decryptedA = await decryptFileAndMeta(
      modeAResult.encryptedBlob,
      modeAResult.ivB64,
      modeAResult.encryptedMetaB64,
      {
        privateKey: userBob.keyPair.privateKey,
        wrappedAesKeyB64: modeAResult.wrappedAesKeyB64
      },
      'MODE_A',
      { metaIvB64: modeAResult.metaIvB64 }
    );

    const decTextA = new TextDecoder().decode(decryptedA.fileBuffer);
    assert(decTextA === secretData, 'Mode A decrypted plaintext matches original content');
    assert(decryptedA.isChecksumValid === true, 'Mode A checksum integrity verified');

    // Also test Mode A with recipient key as CryptoKey object
    const modeAKeyResult = await encryptFileAndMeta(
      fileBytes,
      metadata,
      'MODE_A',
      userBob.keyPair.publicKey
    );
    const decAKey = await decryptFileAndMeta(
      modeAKeyResult.encryptedBlob,
      modeAKeyResult.ivB64,
      modeAKeyResult.encryptedMetaB64,
      {
        privateKey: userBob.keyPair.privateKey,
        wrappedAesKeyB64: modeAKeyResult.wrappedAesKeyB64
      },
      'MODE_A',
      { metaIvB64: modeAKeyResult.metaIvB64 }
    );
    assert(new TextDecoder().decode(decAKey.fileBuffer) === secretData, 'Mode A with CryptoKey recipient succeeds');

    // Attempt decrypting with Alice's private key (mismatch) -> should fail
    await assertThrowsAsync(
      async () => await decryptFileAndMeta(
        modeAResult.encryptedBlob,
        modeAResult.ivB64,
        modeAResult.encryptedMetaB64,
        {
          privateKey: userAlice.keyPair.privateKey,
          wrappedAesKeyB64: modeAResult.wrappedAesKeyB64
        },
        'MODE_A',
        { metaIvB64: modeAResult.metaIvB64 }
      ),
      null,
      'Mode A decryption with wrong recipient private key fails'
    );
  }

  // -------------------------------------------------------------
  // Test Suite 7: Ciphertext & Checksum Tampering Detection
  // -------------------------------------------------------------
  console.log('\n[Suite 7] Adversarial Tampering Detection');
  {
    // 7.1 Ciphertext bit-flip tampering
    const tamperedCiphertext = new Uint8Array(modeBResult.encryptedBlob.slice(0));
    tamperedCiphertext[0] ^= 0x01; // flip 1 bit

    await assertThrowsAsync(
      async () => await decryptFileAndMeta(
        tamperedCiphertext,
        modeBResult.ivB64,
        modeBResult.encryptedMetaB64,
        modeBResult.fragmentKeyB64,
        'MODE_B',
        { metaIvB64: modeBResult.metaIvB64 }
      ),
      null,
      'Flipping 1 bit in AES-GCM ciphertext triggers authentication tag verification failure'
    );

    // 7.2 Metadata checksum tampering
    // We re-encrypt metadata with a modified fake checksum
    const rawAesKey = base64UrlToBuffer(modeBResult.fragmentKeyB64);
    const aesKey = await crypto.subtle.importKey('raw', rawAesKey, { name: 'AES-GCM' }, false, ['encrypt']);
    const tamperedMeta = {
      ...metadata,
      checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' // empty hash
    };
    const metaIv = crypto.getRandomValues(new Uint8Array(12));
    const tamperedMetaEnc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metaIv },
      aesKey,
      new TextEncoder().encode(JSON.stringify(tamperedMeta))
    );

    const tamperedMetaDec = await decryptFileAndMeta(
      modeBResult.encryptedBlob,
      modeBResult.ivB64,
      bufferToBase64(tamperedMetaEnc),
      modeBResult.fragmentKeyB64,
      'MODE_B',
      { metaIvB64: bufferToBase64(metaIv) }
    );

    assert(tamperedMetaDec.isChecksumValid === false, 'Checksum mismatch detected: isChecksumValid is false');
  }

  // -------------------------------------------------------------
  // Test Suite 8: Boundary & Edge Case Validation
  // -------------------------------------------------------------
  console.log('\n[Suite 8] Edge Cases & Boundary Conditions');
  {
    // Empty payload rejection
    await assertThrowsAsync(
      async () => await encryptFileAndMeta(new Uint8Array(0), metadata, 'MODE_B'),
      'Payload cannot be empty',
      'Empty 0-byte payload is rejected with "Payload cannot be empty"'
    );

    // Mode A missing recipient key rejection
    await assertThrowsAsync(
      async () => await encryptFileAndMeta(fileBytes, metadata, 'MODE_A', null),
      'Recipient public key is required',
      'Mode A without recipient key is rejected'
    );
  }

  // -------------------------------------------------------------
  // Test Suite 9: Client API & Offline Mock Backend Lifecycle
  // -------------------------------------------------------------
  console.log('\n[Suite 9] Client REST API & Offline Mock Lifecycle');
  {
    // 9.1 Register User
    const regRes = await registerUser({
      username: 'charlie',
      publicKeyPem: userAlice.publicKeyPem,
      fingerprint: userAlice.keyFingerprint
    });
    assert(regRes.success === true && regRes.user.username === 'charlie', 'registerUser succeeded');

    // Duplicate registration -> 409
    await assertThrowsAsync(
      async () => await registerUser({ username: 'charlie', publicKeyPem: userAlice.publicKeyPem }),
      409,
      'Duplicate username registration throws 409 Conflict'
    );

    // 9.2 Get User Public Key
    const pubRes = await getUserPubKey('charlie');
    assert(pubRes.success === true && pubRes.publicKeyPem === userAlice.publicKeyPem, 'getUserPubKey retrieved public key');

    // Non-existent user -> 404
    await assertThrowsAsync(
      async () => await getUserPubKey('nonexistent_user_999'),
      404,
      'Looking up non-existent user throws 404'
    );

    // 9.3 Upload File (with Burn-After-Reading)
    const uploadRes = await uploadFile({
      encryptedBlob: modeBResult.encryptedBlob,
      ivB64: modeBResult.ivB64,
      metaIvB64: modeBResult.metaIvB64,
      encryptedMetaB64: modeBResult.encryptedMetaB64,
      mode: 'MODE_B',
      isBurnAfterReading: true,
      maxDownloads: 1,
      expiryMinutes: 60
    });

    assert(uploadRes.success === true, 'uploadFile succeeded');
    assert(Boolean(uploadRes.fileId), `Generated fileId: ${uploadRes.fileId}`);
    assert(Boolean(uploadRes.ownerToken), 'Generated ownerToken');
    assert(uploadRes.downloadUrl.includes(uploadRes.fileId), 'downloadUrl contains fileId');

    const fileId = uploadRes.fileId;
    const ownerToken = uploadRes.ownerToken;

    // 9.4 Metadata Retrieval
    const metaRes = await getMetadata(fileId);
    assert(metaRes.success === true && metaRes.id === fileId, 'getMetadata returned vault record');
    assert(metaRes.isBurnAfterReading === true, 'Metadata preserves isBurnAfterReading flag');

    // 9.5 Download File (First access: burn trigger)
    const dlRes = await downloadFile(fileId);
    assert(dlRes.success === true, 'downloadFile succeeded on first access');
    assert(dlRes.remainingDownloads === 0, 'remainingDownloads decremented to 0');

    // Second access on burned item -> 410 Gone
    await assertThrowsAsync(
      async () => await downloadFile(fileId),
      410,
      'Second download of burn-after-reading file throws 410 Gone'
    );

    await assertThrowsAsync(
      async () => await getMetadata(fileId),
      410,
      'Metadata request on burned file throws 410 Gone'
    );

    // 9.6 Access Logs & Revocation Lifecycle
    const upload2 = await uploadFile({
      encryptedBlob: modeBResult.encryptedBlob,
      ivB64: modeBResult.ivB64,
      metaIvB64: modeBResult.metaIvB64,
      encryptedMetaB64: modeBResult.encryptedMetaB64,
      mode: 'MODE_B',
      isBurnAfterReading: false,
      maxDownloads: 10,
      expiryMinutes: 60
    });

    // Check access logs with valid owner token
    const logsRes = await getAccessLogs(upload2.fileId, upload2.ownerToken);
    assert(logsRes.success === true && Array.isArray(logsRes.logs) && logsRes.logs.length >= 1, 'getAccessLogs returned audit entries');

    // Check access logs with invalid owner token -> 401
    await assertThrowsAsync(
      async () => await getAccessLogs(upload2.fileId, 'invalid-owner-token'),
      401,
      'Access logs with invalid owner token throws 401 Unauthorized'
    );

    // Revoke file with owner token
    const revokeRes = await revokeFile(upload2.fileId, upload2.ownerToken);
    assert(revokeRes.success === true, 'revokeFile succeeded');

    // Subsequent metadata request -> 410 Revoked
    await assertThrowsAsync(
      async () => await getMetadata(upload2.fileId),
      410,
      'Accessing revoked vault item throws 410'
    );
  }

  // -------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------
  console.log('\n' + '='.repeat(70));
  console.log(` VERIFICATION COMPLETE: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(70));

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('\n❌ Unhandled error in verification test runner:', err);
  process.exit(1);
});
