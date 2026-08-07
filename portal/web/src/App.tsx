import { createContext, useContext, useEffect, useState } from 'react';
import { fetchMe, type Me } from './api';
import { Forgot, Login, Reset, Signup, TotpChallenge, UndoTotp, VerifyEmail } from './auth';
import { Profile, Security } from './account';

// ponytail: 20-line history-API router instead of react-router.
export function navigate(path: string): void {
  history.pushState(null, '', path);
  dispatchEvent(new PopStateEvent('popstate'));
}

function usePath(): string {
  const [path, setPath] = useState(location.pathname);
  useEffect(() => {
    const onPop = () => setPath(location.pathname);
    addEventListener('popstate', onPop);
    return () => removeEventListener('popstate', onPop);
  }, []);
  return path;
}

interface SessionState {
  me: Me | null;
  setMe: (me: Me | null) => void;
}
const SessionContext = createContext<SessionState>({ me: null, setMe: () => {} });
export const useSession = (): SessionState => useContext(SessionContext);

export function Link({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <a
      href={to}
      onClick={(e) => {
        e.preventDefault();
        navigate(to);
      }}
    >
      {children}
    </a>
  );
}

export default function App() {
  const path = usePath();
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void fetchMe().then((m) => {
      setMe(m);
      setLoading(false);
    });
  }, []);

  if (loading) return <main className="card">Loading…</main>;

  const authed = me !== null && !me.mfaPending;

  let page: React.ReactNode;
  // Before the mfaPending branch: this link is what an owner locked out by a
  // hostile enrollment clicks, and they cannot pass the step-up by definition.
  if (path === '/undo-totp') page = <UndoTotp />;
  else if (me?.mfaPending) page = <TotpChallenge />;
  else if (path === '/signup') page = authed ? <Profile /> : <Signup />;
  else if (path === '/forgot') page = <Forgot />;
  else if (path === '/reset') page = <Reset />;
  else if (path === '/verify-email') page = <VerifyEmail />;
  else if (path === '/security') page = authed ? <Security /> : <Login />;
  else page = authed ? <Profile /> : <Login />;

  return (
    <SessionContext.Provider value={{ me, setMe }}>
      <header>
        <span className="brand">Meridian Portal</span>
        <nav>
          {authed ? (
            <>
              <Link to="/">Profile</Link>
              <Link to="/security">Security</Link>
              <span className="muted">{me.user.email}</span>
            </>
          ) : (
            <>
              <Link to="/">Sign in</Link>
              <Link to="/signup">Create account</Link>
            </>
          )}
        </nav>
      </header>
      <main>{page}</main>
    </SessionContext.Provider>
  );
}
