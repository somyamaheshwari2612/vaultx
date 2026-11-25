'use client';

import { useState, useCallback } from 'react';
import { encryptFileAndMeta, bufferToBase64 } from '../lib/vaultCrypto.js';
import { getUserPubKey, uploadFile } from '../lib/api.js';

/**
 * useUpload
 * Core functional upload state machine hook for VaultX.
 * Supports Mode A (registered recipient) and Mode B (ephemeral link),
 * dual input tabs (file upload vs secret text note), password protection,
 * configurable TTL & download limits, and sender dashboard history persistence.
 */
export function useUpload() {
  const [tab, setTab] = useState('file'); // 'file' | 'text'
  const [mode, setMode] = useState('MODE_B'); // 'MODE_B' | 'MODE_A'
  const [file, setFile] = useState(null);
  const [textNote, setTextNote] = useState('');
  const [recipientUsername, setRecipientUsername] = useState('');
  const [recipientInfo, setRecipientInfo] = useState(null);
  const [expiryMinutes, setExpiryMinutes] = useState(60);
  const [maxDownloads, setMaxDownloads] = useState(5);
  const [isBurnAfterReading, setIsBurnAfterReading] = useState(false);
  const [isPasswordProtected, setIsPasswordProtected] = useState(false);
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState('idle'); // 'idle' | 'encrypting' | 'uploading' | 'success' | 'error'
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  /**
   * Looks up recipient public key and fingerprint for Mode A transfers.
   */
  const lookupRecipient = useCallback(async (username) => {
    const target = (username !== undefined ? username : recipientUsername || '').trim();
    if (!target) {
      setRecipientInfo(null);
      return null;
    }
    try {
      const res = await getUserPubKey(target);
      if (res && res.success) {
        setRecipientInfo(res);
        return res;
      }
    } catch (_) {
      // Lookup error handled gracefully
    }
    setRecipientInfo(null);
    return null;
  }, [recipientUsername]);

  /**
   * Resets upload state back to initial clean state.
   */
  const reset = useCallback(() => {
    setTab('file');
    setMode('MODE_B');
    setFile(null);
    setTextNote('');
    setRecipientUsername('');
    setRecipientInfo(null);
    setExpiryMinutes(60);
    setMaxDownloads(5);
    setIsBurnAfterReading(false);
    setIsPasswordProtected(false);
    setPassword('');
    setStatus('idle');
    setResult(null);
    setError(null);
  }, []);

  /**
   * Executes the full client-side encryption and vault upload pipeline.
   */
  const executeUpload = useCallback(async () => {
    // 1. Validation checks
    if (tab === 'file' && !file) {
      setError('Please select a file to encrypt');
      return;
    }

    const trimmedRecipient = (recipientUsername || '').trim();

    if (tab === 'text' && !textNote.trim()) {
      setError('Secret note cannot be empty');
      return;
    }

    if (mode === 'MODE_A' && !trimmedRecipient) {
      setError('Recipient username required for Mode A');
      return;
    }

    if (isPasswordProtected && !password) {
      setError('Password is required for password-protected vault');
      return;
    }

    setError(null);
    setStatus('encrypting');

    try {
      // 2. Read payload and prepare metadata
      let buffer;
      let metaObj = {};

      if (tab === 'file') {
        if (typeof file.arrayBuffer === 'function') {
          buffer = await file.arrayBuffer();
        } else if (file instanceof ArrayBuffer) {
          buffer = file;
        } else if (file instanceof Uint8Array) {
          buffer = file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength);
        } else if (file && typeof file === 'object' && file.data) {
          buffer = file.data instanceof ArrayBuffer ? file.data : new TextEncoder().encode(String(file.data)).buffer;
        } else {
          buffer = new TextEncoder().encode(String(file)).buffer;
        }

        metaObj = {
          filename: file.name || 'file.dat',
          mimeType: file.type || 'application/octet-stream',
          size: buffer.byteLength,
          isNote: false
        };
      } else {
        const enc = new TextEncoder().encode(textNote);
        buffer = enc.buffer.slice(enc.byteOffset, enc.byteOffset + enc.byteLength);

        metaObj = {
          filename: 'secret-note.txt',
          mimeType: 'text/plain',
          size: enc.byteLength,
          isNote: true
        };
      }

      // 3. Resolve Mode A recipient key if required
      let recipientPubKey = null;
      if (mode === 'MODE_A') {
        let lookup = recipientInfo;
        if (!lookup || lookup.username !== trimmedRecipient) {
          lookup = await lookupRecipient(trimmedRecipient);
        }
        if (!lookup || !lookup.publicKeyPem) {
          throw new Error(`Recipient "${trimmedRecipient}" not found or has no public key`);
        }
        recipientPubKey = lookup.publicKeyPem;
      }

      // 4. Configure encryption options (PBKDF2 password derivation if enabled)
      const encryptOptions = {};
      if (isPasswordProtected && password) {
        encryptOptions.password = password;
      }

      // 5. Zero-Knowledge client-side encryption
      const cryptoResult = await encryptFileAndMeta(
        buffer,
        metaObj,
        mode,
        recipientPubKey,
        encryptOptions
      );

      setStatus('uploading');

      // 6. Normalize encrypted ciphertext payload
      let blobB64;
      if (cryptoResult.encryptedBlob instanceof ArrayBuffer) {
        blobB64 = bufferToBase64(cryptoResult.encryptedBlob);
      } else if (cryptoResult.encryptedBlob && typeof cryptoResult.encryptedBlob.arrayBuffer === 'function') {
        const ab = await cryptoResult.encryptedBlob.arrayBuffer();
        blobB64 = bufferToBase64(ab);
      } else if (cryptoResult.encryptedBlob instanceof Uint8Array) {
        blobB64 = bufferToBase64(cryptoResult.encryptedBlob);
      } else {
        blobB64 = bufferToBase64(cryptoResult.encryptedBlob);
      }

      const uploadPayload = {
        encryptedBlobB64: blobB64,
        ivB64: cryptoResult.ivB64,
        metaIvB64: cryptoResult.metaIvB64,
        encryptedMetaB64: cryptoResult.encryptedMetaB64,
        wrappedAesKeyB64: cryptoResult.wrappedAesKeyB64,
        mode,
        recipientUsername: mode === 'MODE_A' ? trimmedRecipient : null,
        expiryMinutes,
        maxDownloads,
        isBurnAfterReading,
        isPasswordProtected
      };

      // 7. Dispatch to API client
      const apiRes = await uploadFile(uploadPayload);

      // 8. Construct full zero-knowledge share URL and QR payload
      const origin =
        typeof window !== 'undefined' && window.location?.origin
          ? window.location.origin
          : 'http://localhost:3000';

      const downloadPath = apiRes.downloadUrl.startsWith('http')
        ? apiRes.downloadUrl
        : `${origin}${apiRes.downloadUrl}`;

      const fullShareUrl =
        mode === 'MODE_B' && cryptoResult.fragmentKeyB64
          ? `${downloadPath}#key=${cryptoResult.fragmentKeyB64}`
          : downloadPath;

      const uploadResult = {
        fileId: apiRes.fileId,
        ownerToken: apiRes.ownerToken,
        downloadUrl: apiRes.downloadUrl,
        fullShareUrl,
        qrCodePayload: fullShareUrl,
        expiresAt: apiRes.expiresAt,
        sha256Checksum: cryptoResult.sha256Checksum
      };

      // 9. Persist audit record in localStorage for sender dashboard history
      const sentRecord = {
        id: apiRes.fileId,
        fileId: apiRes.fileId,
        filename: metaObj.filename,
        createdAt: new Date().toISOString(),
        expiresAt: apiRes.expiresAt,
        ownerToken: apiRes.ownerToken,
        mode,
        isBurnAfterReading,
        isPasswordProtected
      };

      if (typeof window !== 'undefined' && window.localStorage) {
        try {
          const rawSent = window.localStorage.getItem('vaultx_sent_vaults');
          const sentList = rawSent ? JSON.parse(rawSent) : [];
          sentList.unshift(sentRecord);
          window.localStorage.setItem('vaultx_sent_vaults', JSON.stringify(sentList));

          const rawHist = window.localStorage.getItem('vaultx_history');
          const histList = rawHist ? JSON.parse(rawHist) : [];
          histList.unshift(sentRecord);
          window.localStorage.setItem('vaultx_history', JSON.stringify(histList));
        } catch (_) {
          // Ignore localStorage errors
        }
      }

      setResult(uploadResult);
      setStatus('success');
      return uploadResult;
    } catch (err) {
      setError(err.message || 'Upload failed');
      setStatus('error');
      throw err;
    }
  }, [
    tab,
    file,
    textNote,
    mode,
    recipientUsername,
    recipientInfo,
    expiryMinutes,
    maxDownloads,
    isBurnAfterReading,
    isPasswordProtected,
    password,
    lookupRecipient
  ]);

  return {
    tab,
    setTab,
    mode,
    setMode,
    file,
    setFile,
    textNote,
    setTextNote,
    recipientUsername,
    setRecipientUsername,
    recipientInfo,
    lookupRecipient,
    expiryMinutes,
    setExpiryMinutes,
    maxDownloads,
    setMaxDownloads,
    isBurnAfterReading,
    setIsBurnAfterReading,
    isPasswordProtected,
    setIsPasswordProtected,
    password,
    setPassword,
    status,
    result,
    error,
    executeUpload,
    reset
  };
}

export default useUpload;
