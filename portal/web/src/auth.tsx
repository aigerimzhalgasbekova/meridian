import { useEffect, useState } from 'react';
import { api, setCsrf, type Me } from './api';
import { Link, navigate, useSession } from './App';
import { linkToken } from './token';

function useForm(): {
  error: string;
  busy: boolean;
  submit: (fn: () => Promise<void>) => (e: React.FormEvent) => void;
} {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  return {
    error,
    busy,
    submit: (fn) => (e) => {
      e.preventDefault();
      setError('');
      setBusy(true);
      fn()
        .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
        .finally(() => setBusy(false));
    },
  };
}

export function Login() {
  const { setMe } = useSession();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { error, busy, submit } = useForm();

  return (
    <form className="card" onSubmit={submit(async () => {
      const me = await api<Me>('POST', '/api/auth/login', { email, password });
      setCsrf(me.csrfToken);
      setMe(me);
      navigate('/');
    })}>
      <h1>Sign in</h1>
      {error && <p className="error">{error}</p>}
      <label>Email <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" /></label>
      <label>Password <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" /></label>
      <button disabled={busy}>Sign in</button>
      <p><Link to="/forgot">Forgot your password?</Link> · <Link to="/signup">Create account</Link></p>
    </form>
  );
}

export function Signup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [sent, setSent] = useState(false);
  const { error, busy, submit } = useForm();

  // Enumeration-safe: the server returns the same "check your email" response
  // whether or not the address was already registered, so we never auto-login.
  // The copy must be true of both branches — a new address receives a
  // verification link, a taken one receives a reset link — and hint at neither.
  if (sent) {
    return <div className="card"><h1>Check your email</h1>
      <p>We sent a message to {email}. Follow the link in it to continue, then <Link to="/">sign in</Link>.</p></div>;
  }
  return (
    <form className="card" onSubmit={submit(async () => {
      await api('POST', '/api/auth/signup', { email, password });
      setSent(true);
    })}>
      <h1>Create account</h1>
      {error && <p className="error">{error}</p>}
      <label>Email <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" /></label>
      <label>Password <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} autoComplete="new-password" /></label>
      <button disabled={busy}>Create account</button>
      <p>A verification link will be emailed to you.</p>
    </form>
  );
}

export function TotpChallenge() {
  const { setMe } = useSession();
  const [code, setCode] = useState('');
  const { error, busy, submit } = useForm();

  return (
    <form className="card" onSubmit={submit(async () => {
      const me = await api<Me>('POST', '/api/auth/totp', { code: code.trim() });
      setMe(me);
      navigate('/');
    })}>
      <h1>Two-factor authentication</h1>
      {error && <p className="error">{error}</p>}
      <label>Enter the 6-digit code from your authenticator app, or a recovery code.
        <input value={code} onChange={(e) => setCode(e.target.value)} required autoFocus autoComplete="one-time-code" />
      </label>
      <button disabled={busy}>Verify</button>
    </form>
  );
}

export function Forgot() {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const { error, busy, submit } = useForm();

  if (sent) {
    return <div className="card"><h1>Check your email</h1>
      <p>If an account exists for {email}, a reset link is on its way. It expires in 15 minutes.</p></div>;
  }
  return (
    <form className="card" onSubmit={submit(async () => {
      await api('POST', '/api/auth/forgot', { email });
      setSent(true);
    })}>
      <h1>Reset your password</h1>
      {error && <p className="error">{error}</p>}
      <label>Email <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" /></label>
      <button disabled={busy}>Send reset link</button>
    </form>
  );
}

export function Reset() {
  const token = linkToken(location.href);
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);
  const { error, busy, submit } = useForm();

  if (done) {
    return <div className="card"><h1>Password updated</h1>
      <p>All sessions have been signed out. <Link to="/">Sign in</Link> with your new password.</p></div>;
  }
  return (
    <form className="card" onSubmit={submit(async () => {
      await api('POST', '/api/auth/reset', { token, password });
      setDone(true);
    })}>
      <h1>Choose a new password</h1>
      {error && <p className="error">{error}</p>}
      <label>New password <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} autoComplete="new-password" /></label>
      <button disabled={busy}>Set password</button>
    </form>
  );
}

// Reached from the "two-factor was enabled" email. Deliberately reachable
// while a session is mfaPending: the owner it exists for cannot get past the
// step-up, which is the whole lockout being undone.
export function UndoTotp() {
  const token = linkToken(location.href);
  const [done, setDone] = useState(false);
  const { error, busy, submit } = useForm();

  if (done) {
    return <div className="card"><h1>Two-factor turned off</h1>
      <p>All sessions were signed out. <Link to="/">Sign in</Link>, then change your password —
        whoever enabled this knew it.</p></div>;
  }
  return (
    <form className="card" onSubmit={submit(async () => {
      await api('POST', '/api/auth/undo-totp', { token });
      setDone(true);
    })}>
      <h1>Turn off two-factor authentication</h1>
      {error && <p className="error">{error}</p>}
      <p>This removes the authenticator and recovery codes that were just added to your account.</p>
      <button disabled={busy}>Turn it off</button>
    </form>
  );
}

export function VerifyEmail() {
  const token = linkToken(location.href);
  const [state, setState] = useState<'working' | 'ok' | 'error'>('working');
  const [detail, setDetail] = useState('');

  useEffect(() => {
    api<{ email: string }>('POST', '/api/auth/verify-email', { token })
      .then((r) => {
        setDetail(r.email);
        setState('ok');
      })
      .catch((e: unknown) => {
        setDetail(e instanceof Error ? e.message : String(e));
        setState('error');
      });
  }, [token]);

  return (
    <div className="card">
      <h1>Email verification</h1>
      {state === 'working' && <p>Verifying…</p>}
      {state === 'ok' && <p>{detail} is verified. <Link to="/">Continue</Link></p>}
      {state === 'error' && <p className="error">{detail}</p>}
    </div>
  );
}
