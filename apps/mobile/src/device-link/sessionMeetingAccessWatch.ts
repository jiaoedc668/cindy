import { ApiError } from '@/api/client';

/** Reconcile an open guest task when the relay can no longer route its revoke frame. */
export function watchSessionMeetingAccess(options: {
  meetingId: string;
  sessionId: string;
  read(): Promise<{ meetingId: string; sessionId: string; status: string }>;
  isCurrent(): boolean;
  onRevoked(): void;
}) {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const current = () => !stopped && options.isCurrent();
  const revoke = () => {
    if (!current()) return;
    stopped = true;
    options.onRevoked();
  };
  const check = async () => {
    if (!current()) return;
    try {
      const detail = await options.read();
      if (!current()) return;
      if (detail.meetingId === options.meetingId && detail.sessionId === options.sessionId
          && detail.status === 'closed') revoke();
    } catch (error) {
      // Timeout, offline, expired login and unsupported routes are not revocation.
      if (error instanceof ApiError && error.status === 404 && error.code === 'NOT_FOUND') revoke();
    } finally {
      // A slow read occupies the only request slot; no interval can pile up reads.
      if (current()) timer = setTimeout(() => void check(), 5_000);
    }
  };
  void check();
  return () => { stopped = true; if (timer !== undefined) clearTimeout(timer); };
}
