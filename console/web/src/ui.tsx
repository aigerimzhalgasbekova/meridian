import { useCallback, useEffect, useState } from "react";
import { ApiError } from "./api";
import { TraceView } from "./Trace";

// ErrorBox renders an API failure; a 403 includes the engine's deny trace.
export function ErrorBox({ error, onDismiss }: { error: unknown; onDismiss?: () => void }) {
  if (!error) return null;
  const e = error instanceof ApiError ? error : null;
  return (
    <div className="error-box">
      <div className="error-head">
        <b>{e ? `${e.status} ${e.code}` : "error"}</b> {e?.message ?? String(error)}
        {onDismiss && (
          <button className="btn btn-ghost" onClick={onDismiss}>
            dismiss
          </button>
        )}
      </div>
      {e?.decision && <TraceView decision={e.decision} />}
    </div>
  );
}

// useLoad runs an async loader, exposing data / error / reload.
export function useLoad<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const reload = useCallback(() => {
    load().then(setData, setError);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(reload, [reload]);
  return { data, error, reload, setError };
}
