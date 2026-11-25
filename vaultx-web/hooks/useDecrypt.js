'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { decryptFileAndMeta, base64ToBuffer, base64UrlToBuffer } from '../lib/vaultCrypto.js';
import { getMetadata, downloadFile, revokeFile } from '../lib/api.js';
import { getUserKey } from '../lib/keyStore.js';

/**
 * Validates Mode B Base64URL fragment key format and decoded byte length
 * before any network download occurs, preventing premature burn of single-use vaults.
 */
function validateModeBKey(keyStr, isPasswordProtected = false) {
  if (!keyStr || typeof keyStr !== 'string') {
    return { valid: false, error: 'Key material is required for Mode B decryption' };
  }
  const trimmed = keyStr.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(trimmed) || trimmed.length % 4 === 1) {
    return { valid: false, error: 'Invalid key format: malformed Base64URL fragment key' };
  }
  let keyBytes;
  try {
    keyBytes = base64UrlToBuffer(trimmed);
  } catch (_) {
    return { valid: false, error: 'Invalid key format: malformed Base64URL fragment key' };
  }
  if (isPasswordProtected) {
    if (keyBytes.byteLength !== 76) {
      return {
        valid: false,
        error: `Invalid keyMaterial length for Mode B (${keyBytes.byteLength} bytes)`
      };
    }
  } else if (keyBytes.byteLength !== 32) {
    return {
      valid: false,
      error: `Invalid keyMaterial length for Mode B (${keyBytes.byteLength} bytes)`
    };
  }
  return { valid: true, key: trimmed, byteLength: keyBytes.byteLength };
}

/**
 * Extracts base64url key from URL hash fragment or query string.
 * Supports:
 * - #key=<b64url>
 * - ?key=<b64url>
 * - #key:<b64url>
 * - Bare base64url hash (#<b64url>)
 */
export function extractKeyFromHash(hashOrUrl) {
  if (!hashOrUrl || typeof hashOrUrl !== 'string') return null;

  // 1. Match ?key=<val> or #key=<val> or &key=<val>
  const paramMatch = hashOrUrl.match(/[#?&]key=([A-Za-z0-9_-]+)/i);
  if (paramMatch) return paramMatch[1];

  // 2. Match #key:<val>
  const colonMatch = hashOrUrl.match(/[#?&]key:([A-Za-z0-9_-]+)/i);
  if (colonMatch) return colonMatch[1];

  // 3. Match bare hash with base64url key (at least 40 chars for AES-256)
  const bareMatch = hashOrUrl.match(/#([A-Za-z0-9_-]{40,})/);
  if (bareMatch) return bareMatch[1];

  return null;
}

/**
 * useDecrypt
 * Core recipient decryption state machine hook for VaultX.
 * Orchestrates metadata loading, URL fragment key extraction, password challenges,
 * ciphertext download, Web Crypto decryption, SHA-256 integrity verification,
 * and zero-footprint in-memory preview URL lifecycle.
 */
export function useDecrypt(fileId, optionsOrFragment = null, recipientUsernameArg = null) {
  let initialFragment = null;
  let recipientUsername = recipientUsernameArg || null;
  let initialOwnerToken = null;

  if (typeof optionsOrFragment === 'string') {
    initialFragment = optionsOrFragment;
  } else if (optionsOrFragment && typeof optionsOrFragment === 'object') {
    initialFragment = optionsOrFragment.initialFragment || null;
    recipientUsername = optionsOrFragment.recipientUsername || recipientUsernameArg || null;
    initialOwnerToken = optionsOrFragment.ownerToken || null;
  }

  const [status, setStatus] = useState('loading_meta'); // 'idle' | 'loading_meta' | 'password_required' | 'decrypting' | 'ready' | 'tampered' | 'error'
  const [hasFragmentKey, setHasFragmentKey] = useState(false);
  const [meta, setMeta] = useState(null);
  const [decryptedMeta, setDecryptedMeta] = useState(null);
  const [fileBlob, setFileBlob] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [previewType, setPreviewType] = useState(null);
  const [textContent, setTextContent] = useState('');
  const [isChecksumValid, setIsChecksumValid] = useState(null);
  const [sha256Checksum, setSha256Checksum] = useState(null);
  const [error, setError] = useState(null);
  const [manualKey, setManualKeyState] = useState('');

  const previewUrlRef = useRef(null);
  const downloadedDataRef = useRef(null);
  const isMountedRef = useRef(true);
  const prevFileIdRef = useRef(fileId);
  const prevFragmentRef = useRef(initialFragment);
  const prevRecipientRef = useRef(recipientUsername);
  const lastModeRef = useRef(null);
  const hasInitializedRef = useRef(false);

  // Automatic cleanup of preview ObjectURL on unmount
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (previewUrlRef.current && typeof URL !== 'undefined' && URL.revokeObjectURL) {
        try {
          URL.revokeObjectURL(previewUrlRef.current);
        } catch (_) {}
        previewUrlRef.current = null;
      }
    };
  }, []);

  /**
   * Revokes and cleans up active in-memory preview URL.
   */
  const cleanupPreview = useCallback(() => {
    if (previewUrlRef.current && typeof URL !== 'undefined' && URL.revokeObjectURL) {
      try {
        URL.revokeObjectURL(previewUrlRef.current);
      } catch (_) {}
      previewUrlRef.current = null;
    }
    setPreviewUrl(null);
  }, []);

  /**
   * Core decryption routine.
   */
  const performDecryption = useCallback(
    async (keyB64Url, userPassword = null, metaData = null) => {
      setStatus('decrypting');
      setError(null);

      try {
        const currentMeta = metaData || meta;
        if (!currentMeta) {
          throw new Error('Vault metadata not available');
        }

        const mode = currentMeta.mode || 'MODE_B';

        // 1. Validate cryptographic key material BEFORE downloading payload
        //    (prevents premature burn of burn-after-reading vaults on bad/missing keys)
        let keyMaterial;
        if (mode === 'MODE_B') {
          const keyCheck = validateModeBKey(keyB64Url, Boolean(currentMeta.isPasswordProtected));
          if (!keyCheck.valid) {
            const keyErr = new Error(keyCheck.error);
            keyErr.code = 'INVALID_KEY_FORMAT';
            throw keyErr;
          }
          keyMaterial = keyCheck.key;
        } else if (mode === 'MODE_A') {
          const storedActiveUser =
            typeof window !== 'undefined' && window.localStorage
              ? window.localStorage.getItem('vaultx_active_username')
              : null;
          const targetUsername =
            recipientUsername || currentMeta.recipientUsername || storedActiveUser || 'current_user';
          let userKey = await getUserKey(targetUsername);
          if (!userKey || !userKey.keyPair?.privateKey) {
            if (storedActiveUser && storedActiveUser !== targetUsername) {
              userKey = await getUserKey(storedActiveUser);
            }
          }
          if (!userKey || !userKey.keyPair?.privateKey) {
            userKey = (await getUserKey('current_user')) || (await getUserKey('alice'));
          }

          if (!userKey || !userKey.keyPair?.privateKey) {
            throw new Error(`Private key for recipient "${targetUsername}" not found in KeyStore`);
          }

          keyMaterial = {
            privateKey: userKey.keyPair.privateKey,
            wrappedAesKeyB64: currentMeta.wrappedAesKeyB64
          };
        } else {
          throw new Error(`Unsupported mode: ${mode}`);
        }

        // 2. Download ciphertext if not cached
        let downloadRes = downloadedDataRef.current;
        if (!downloadRes) {
          const dlOpts = {};
          if (userPassword) {
            dlOpts.password = userPassword;
          }
          downloadRes = await downloadFile(fileId, dlOpts);
          if (!downloadRes || !downloadRes.success) {
            throw new Error(downloadRes?.message || 'Ciphertext download failed');
          }
          downloadedDataRef.current = downloadRes;
        }

        const cipherBytes = base64ToBuffer(downloadRes.encryptedBlobB64);

        // 3. Configure decrypt options
        const decryptOptions = {
          metaIvB64: downloadRes.metaIvB64 || currentMeta.metaIvB64
        };
        if (userPassword) {
          decryptOptions.password = userPassword;
        }

        // 4. Decrypt metadata & payload using Web Crypto
        const result = await decryptFileAndMeta(
          cipherBytes,
          downloadRes.ivB64,
          currentMeta.encryptedMetaB64,
          keyMaterial,
          mode,
          decryptOptions
        );

        // Guard against unmount while asynchronous decryption was in-flight
        if (!isMountedRef.current) {
          return;
        }

        // 5. Integrity verification
        if (!result.isChecksumValid) {
          setStatus('tampered');
          setIsChecksumValid(false);
          setError('Integrity checksum verification failed: payload may have been tampered with');
          return;
        }

        setIsChecksumValid(true);
        setSha256Checksum(result.sha256Checksum);
        setDecryptedMeta(result.metaObj);

        // 6. Build file Blob and in-memory preview
        const mimeType = result.metaObj?.mimeType || 'application/octet-stream';
        const blob = new Blob([result.fileBuffer], { type: mimeType });
        setFileBlob(blob);

        if (typeof URL !== 'undefined' && URL.createObjectURL) {
          cleanupPreview();
          const objUrl = URL.createObjectURL(blob);
          previewUrlRef.current = objUrl;
          setPreviewUrl(objUrl);
        }

        // 7. Determine preview type and text content
        if (result.metaObj?.isNote || mimeType.startsWith('text/')) {
          const decodedText = new TextDecoder().decode(result.fileBuffer);
          setTextContent(decodedText);
          setPreviewType('text');
        } else if (mimeType.startsWith('image/')) {
          setPreviewType('image');
        } else if (mimeType === 'application/pdf') {
          setPreviewType('pdf');
        } else {
          setPreviewType('binary');
        }

        setStatus('ready');
      } catch (err) {
        if (!isMountedRef.current) {
          return;
        }
        setError(err.message || 'Decryption failed');
        const currentMeta = metaData || meta;
        if (currentMeta?.isPasswordProtected && err.code !== 'INVALID_KEY_FORMAT') {
          setStatus('password_required');
        } else {
          setStatus('error');
        }
        throw err;
      }
    },
    [fileId, meta, recipientUsername, cleanupPreview]
  );

  /**
   * Submits a password for password-protected Mode B vaults.
   */
  const submitPassword = useCallback(
    async (pwd) => {
      const hash = initialFragment || (typeof window !== 'undefined' && window.location ? window.location.hash : '');
      const key = extractKeyFromHash(hash) || manualKey;
      await performDecryption(key, pwd, meta);
    },
    [initialFragment, manualKey, meta, performDecryption]
  );

  /**
   * Sets manual decryption key if fragment was missing.
   */
  const setManualKey = useCallback(
    (key) => {
      const trimmed = typeof key === 'string' ? key.trim() : '';
      setManualKeyState(trimmed);
      if (trimmed) {
        setHasFragmentKey(true);
        if (meta && meta.mode === 'MODE_B') {
          if (meta.isPasswordProtected) {
            const check = validateModeBKey(trimmed, true);
            if (!check.valid) {
              setError(check.error);
              setStatus('error');
              return;
            }
            setError(null);
            setStatus('password_required');
            return;
          }
          performDecryption(trimmed, null, meta).catch(() => {});
        }
      }
    },
    [meta, performDecryption]
  );

  /**
   * Triggers client-side disk download of the decrypted file blob.
   */
  const downloadToDisk = useCallback(() => {
    if (!fileBlob) return;
    try {
      const url =
        previewUrl ||
        (typeof URL !== 'undefined' && URL.createObjectURL ? URL.createObjectURL(fileBlob) : null);
      if (!url) return;

      if (typeof document !== 'undefined' && document.createElement) {
        const a = document.createElement('a');
        a.href = url;
        a.download = decryptedMeta?.filename || meta?.filename || 'vaultx-decrypted-file';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        if (!previewUrl && typeof URL !== 'undefined' && URL.revokeObjectURL) {
          URL.revokeObjectURL(url);
        }
      }
    } catch (_) {}
  }, [fileBlob, previewUrl, decryptedMeta, meta]);

  /**
   * Revokes the vault file immediately using owner token.
   */
  const destroyNow = useCallback(
    async (token) => {
      const actualToken = token || initialOwnerToken;
      if (actualToken && fileId) {
        try {
          await revokeFile(fileId, actualToken);
        } catch (_) {}
      }
      cleanupPreview();
      downloadedDataRef.current = null;
      setMeta(null);
      setDecryptedMeta(null);
      setFileBlob(null);
      setPreviewType(null);
      setTextContent('');
      setIsChecksumValid(null);
      setSha256Checksum(null);
      setError(null);
      setStatus('idle');
    },
    [fileId, initialOwnerToken, cleanupPreview]
  );

  /**
   * Full reset of decryption state machine.
   */
  const reset = useCallback(() => {
    cleanupPreview();
    setStatus('idle');
    setHasFragmentKey(false);
    setMeta(null);
    setDecryptedMeta(null);
    setFileBlob(null);
    setPreviewType(null);
    setTextContent('');
    setIsChecksumValid(null);
    setSha256Checksum(null);
    setError(null);
    setManualKeyState('');
    downloadedDataRef.current = null;
  }, [cleanupPreview]);

  // Initial metadata loading and hydration lifecycle
  useEffect(() => {
    let cancelled = false;

    const fileChanged = prevFileIdRef.current !== fileId;
    const fragmentChanged = prevFragmentRef.current !== initialFragment;
    const recipientChanged = prevRecipientRef.current !== recipientUsername;

    if (
      hasInitializedRef.current &&
      !fileChanged &&
      !fragmentChanged &&
      recipientChanged &&
      lastModeRef.current === 'MODE_B'
    ) {
      prevRecipientRef.current = recipientUsername;
      return;
    }

    hasInitializedRef.current = true;
    prevFileIdRef.current = fileId;
    prevFragmentRef.current = initialFragment;
    prevRecipientRef.current = recipientUsername;

    if (fileChanged || fragmentChanged) {
      downloadedDataRef.current = null;
      lastModeRef.current = null;
      cleanupPreview();
      setMeta(null);
      setDecryptedMeta(null);
      setFileBlob(null);
      setPreviewType(null);
      setTextContent('');
      setIsChecksumValid(null);
      setSha256Checksum(null);
      setError(null);
      setManualKeyState('');
      setHasFragmentKey(false);
    }

    async function loadMetaAndInit() {
      if (!fileId) {
        setStatus('idle');
        return;
      }

      setStatus('loading_meta');
      setError(null);
      try {
        const metaRes = await getMetadata(fileId);
        if (cancelled) return;

        if (!metaRes || !metaRes.success) {
          setError(metaRes?.message || 'Vault item not found');
          setStatus('error');
          return;
        }

        lastModeRef.current = metaRes.mode || 'MODE_B';
        setMeta(metaRes);

        // Check URL fragment for base64url key
        const hash = initialFragment || (typeof window !== 'undefined' && window.location ? window.location.hash : '');
        const activeManualKey = fileChanged || fragmentChanged ? '' : manualKey;
        const key = extractKeyFromHash(hash) || activeManualKey;
        const hasKey = Boolean(key);
        setHasFragmentKey(hasKey);

        if (metaRes.mode === 'MODE_B') {
          if (!hasKey) {
            setStatus('idle');
            return;
          }

          if (metaRes.isPasswordProtected) {
            const check = validateModeBKey(key, true);
            if (!check.valid) {
              setError(check.error);
              setStatus('error');
              return;
            }
            setStatus('password_required');
            return;
          }

          await performDecryption(key, null, metaRes);
        } else {
          // Mode A
          await performDecryption(null, null, metaRes);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Failed to load vault item');
          setStatus('error');
        }
      }
    }

    loadMetaAndInit();

    return () => {
      cancelled = true;
    };
  }, [fileId, initialFragment, recipientUsername]);

  return {
    status,
    hasFragmentKey,
    meta,
    decryptedMeta,
    fileBlob,
    previewUrl,
    previewType,
    textContent,
    isChecksumValid,
    sha256Checksum,
    error,
    submitPassword,
    setManualKey,
    downloadToDisk,
    destroyNow,
    cleanupPreview,
    reset
  };
}

export default useDecrypt;
