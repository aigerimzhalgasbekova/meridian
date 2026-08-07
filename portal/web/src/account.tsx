import { useEffect, useState } from 'react';
import { api, fetchMe, type Me } from './api';
import { useSession } from './App';

export function Profile() {
  const { me, setMe } = useSession();
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  if (!me) return null;

  const changeEmail = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    api('POST', '/api/account/email', { email })
      .then(async () => {
        setNotice(`Verification sent to ${email}. Your current address stays active until it is confirmed.`);
        setEmail('');
        setMe(await fetchMe());
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)));
  };

  const logout = () => {
    void api('POST', '/api/auth/logout').then(() => setMe(null));
  };

  return (
    <div className="card">
      <h1>Profile</h1>
      <dl>
        <dt>Email</dt>
        <dd>
          {me.user.email} {me.user.emailVerified ? <span className="ok">verified</span> : <span className="warn">unverified</span>}
        </dd>
        {me.user.pendingEmail && (
          <>
            <dt>Pending change</dt>
            <dd>{me.user.pendingEmail} <span className="warn">awaiting confirmation</span></dd>
          </>
        )}
      </dl>
      <form onSubmit={changeEmail}>
        <h2>Change email</h2>
        {error && <p className="error">{error}</p>}
        {notice && <p className="notice">{notice}</p>}
        <label>New address <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
        <button>Send verification</button>
      </form>
      <hr />
      <button className="secondary" onClick={logout}>Sign out</button>
    </div>
  );
}

interface SessionRow {
  id: string;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

export function Security() {
  const { me, setMe } = useSession();
  const [error, setError] = useState('');
  const [enroll, setEnroll] = useState<{ secret: string; otpauthUri: string; qrSvg: string } | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  // Every change to the second factor re-authenticates with the password, so a
  // stolen session cookie alone cannot enroll (or remove) an authenticator.
  const [password, setPassword] = useState('');

  const loadSessions = () => {
    void api<{ sessions: SessionRow[] }>('GET', '/api/security/sessions')
      .then((r) => setSessions(r.sessions))
      .catch(() => {});
  };
  useEffect(loadSessions, []);

  if (!me) return null;

  const fail = (err: unknown) => setError(err instanceof Error ? err.message : String(err));

  const startEnroll = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    api<{ secret: string; otpauthUri: string; qrSvg: string }>('POST', '/api/security/totp/setup', { password })
      .then((r) => {
        setEnroll(r);
        setPassword('');
      })
      .catch(fail);
  };

  const regenerateCodes = () => {
    setError('');
    api<{ recoveryCodes: string[] }>('POST', '/api/security/totp/recovery-codes', { password })
      .then(async (r) => {
        setRecoveryCodes(r.recoveryCodes);
        setPassword('');
        setMe(await fetchMe());
      })
      .catch(fail);
  };

  const disableTotp = () => {
    setError('');
    api('POST', '/api/security/totp/disable', { password })
      .then(async () => {
        setPassword('');
        setRecoveryCodes(null);
        setMe(await fetchMe());
      })
      .catch(fail);
  };

  const passwordField = (
    <label>
      Confirm your password
      <input
        type="password"
        value={password}
        onChange={(ev) => setPassword(ev.target.value)}
        required
        autoComplete="current-password"
      />
    </label>
  );

  const activate = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    api<{ recoveryCodes: string[] }>('POST', '/api/security/totp/activate', { code: code.trim() })
      .then(async (r) => {
        setRecoveryCodes(r.recoveryCodes);
        setEnroll(null);
        setMe(await fetchMe());
      })
      .catch(fail);
  };

  const revoke = (id: string) => {
    setError('');
    api('DELETE', `/api/security/sessions/${id}`).then(loadSessions).catch(fail);
  };

  return (
    <div className="card">
      <h1>Security</h1>
      {error && <p className="error">{error}</p>}

      <h2>Two-factor authentication</h2>
      {recoveryCodes && (
        <div className="notice">
          <strong>Recovery codes — save these now, they are shown only once:</strong>
          <ul className="codes">{recoveryCodes.map((c) => <li key={c}><code>{c}</code></li>)}</ul>
        </div>
      )}
      {me.user.totpEnabled ? (
        <>
          <p><span className="ok">Enabled.</span> Signing in requires a code from your authenticator app.</p>
          <p className={me.user.recoveryCodesRemaining <= 2 ? 'warn' : 'muted'}>
            {me.user.recoveryCodesRemaining} unused recovery {me.user.recoveryCodesRemaining === 1 ? 'code' : 'codes'} left.
            {' '}Spending the last one with no authenticator to hand locks you out for good.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              regenerateCodes();
            }}
          >
            {passwordField}
            <button>Generate new recovery codes</button>
            <button className="secondary" type="button" onClick={disableTotp}>Turn off two-factor</button>
          </form>
        </>
      ) : enroll ? (
        <form onSubmit={activate}>
          <p>Scan the QR code with your authenticator app, then enter the current code to activate.</p>
          <img
            className="qr"
            alt={`QR code for authenticator enrollment; manual secret: ${enroll.secret}`}
            src={`data:image/svg+xml;utf8,${encodeURIComponent(enroll.qrSvg)}`}
          />
          <p className="muted">Or enter the secret manually: <code>{enroll.secret}</code></p>
          <label>Code <input value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="one-time-code" /></label>
          <button>Activate</button>
        </form>
      ) : (
        <form onSubmit={startEnroll}>
          {passwordField}
          <button>Set up authenticator app</button>
        </form>
      )}

      <h2>Active sessions</h2>
      <table>
        <thead>
          <tr><th>Started</th><th>Expires</th><th></th></tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.id}>
              <td>{new Date(s.createdAt).toLocaleString()}{s.current && ' (this session)'}</td>
              <td>{new Date(s.expiresAt).toLocaleString()}</td>
              <td>{!s.current && <button className="secondary" onClick={() => revoke(s.id)}>Revoke</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
