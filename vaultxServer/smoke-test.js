// Run with the server up:  node smoke-test.js
const API = process.env.API || 'http://localhost:5000/api';
let pass = 0, fail = 0;
const check = (name, cond) => { cond ? pass++ : fail++; console.log((cond ? 'PASS ' : 'FAIL ') + name); };
const J = (r) => r.json().catch(() => ({}));
const post = (p, body) => fetch(API + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

async function up(fields) {
  const fd = new FormData();
  fd.append('encryptedBlob', new Blob([crypto.getRandomValues(new Uint8Array(2048))]), 'blob.bin');
  Object.entries(fields).forEach(([k, v]) => fd.append(k, v));
  return J(await fetch(API + '/vault/upload', { method: 'POST', body: fd }));
}

(async () => {
  const u = 'bob_' + Date.now();
  check('register user', (await post('/users/register', { username: u, publicKeyPem: 'PEM', fingerprint: 'AB:CD' })).status === 201);
  check('duplicate user 409', (await post('/users/register', { username: u, publicKeyPem: 'PEM', fingerprint: 'AB:CD' })).status === 409);
  check('get pubkey', (await J(await fetch(`${API}/users/${u}/pubkey`))).fingerprint === 'AB:CD');

  // Demo 2: 1-view password-protected anonymous link
  const a = await up({ ivB64: 'aXY=', encryptedMetaB64: 'bWV0YQ==', shareMode: 'anyone', maxDownloads: 1, password: 'hunter2' });
  check('upload anyone', !!a.fileId && !!a.ownerToken);
  const meta = await J(await fetch(`${API}/vault/${a.fileId}/meta`));
  check('meta says password required', meta.passwordRequired === true && meta.remainingViews === 1);
  check('wrong password 401', (await post(`/vault/${a.fileId}/download`, { password: 'nope' })).status === 401);
  const d1 = await post(`/vault/${a.fileId}/download`, { password: 'hunter2' });
  const d1j = await J(d1);
  check('correct password 200 + blob', d1.status === 200 && d1j.encryptedBlob.length > 100 && d1j.remainingViews === 0);
  check('2nd download 410 (self-destructed)', (await post(`/vault/${a.fileId}/download`, { password: 'hunter2' })).status === 410);
  const logs = await J(await fetch(`${API}/vault/${a.fileId}/logs?token=${a.ownerToken}`));
  const st = logs.logs.map((l) => l.authStatus);
  check('audit log has denied_password + granted + denied_limit_reached', st.includes('denied_password') && st.includes('granted') && st.includes('denied_limit_reached'));
  check('logs reject bad token', (await fetch(`${API}/vault/${a.fileId}/logs?token=bad`)).status === 403);

  // Demo 1: registered user hybrid flow + revoke
  const r = await up({ ivB64: 'aXY=', shareMode: 'registered', wrappedAesKeyB64: 'V1JBUFBFRA==', recipientUsername: u });
  const insp = await J(await fetch(`${API}/vault/${r.fileId}/inspect`));
  check('hex inspector returns ciphertext hex', insp.hexPreview && insp.hexPreview.split(' ').length === 512);
  check('wrong recipient 403', (await post(`/vault/${r.fileId}/download`, { username: 'mallory' })).status === 403);
  const rd = await J(await post(`/vault/${r.fileId}/download`, { username: u }));
  check('recipient gets wrapped key', rd.wrappedAesKeyB64 === 'V1JBUFBFRA==');
  const rv = await fetch(`${API}/vault/${r.fileId}/revoke?token=${r.ownerToken}`, { method: 'DELETE' });
  check('revoke ok', rv.status === 200);
  check('after revoke 410', (await post(`/vault/${r.fileId}/download`, { username: u })).status === 410);

  // Expiry
  const e = await up({ ivB64: 'aXY=', shareMode: 'anyone', expiresAt: Date.now() + 1500 });
  await new Promise((s) => setTimeout(s, 2000));
  check('expired link 410', (await fetch(`${API}/vault/${e.fileId}/meta`)).status === 410);

  // Race: 5 simultaneous downloads, limit 2
  const c = await up({ ivB64: 'aXY=', shareMode: 'anyone', maxDownloads: 2 });
  const rs = await Promise.all(Array.from({ length: 5 }, () => post(`/vault/${c.fileId}/download`, {})));
  check('race: exactly 2 of 5 succeed', rs.filter((x) => x.status === 200).length === 2);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
