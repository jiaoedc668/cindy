import { SESSION_MEETING_CAPABILITY, type DeviceLinkClient } from '@cindy/device-link';
import { getCurrentDbClientSnapshot } from '../localDb/client/current.js';
import { createSessionMeetingJournal } from '../localDb/sessionMeetings.js';
import { activeOwnerScopeKey, getActiveAppSession, isAppSessionBoundaryPending } from '../appSessionState.js';
import { getAuthState, getCurrentUserId, getDeviceId, getActiveAuthRealm } from '../authManager.js';
import { createLogger } from '../logger.js';
import { throwIpcError } from '../utils/ipcValidate.js';
import { sessionMeetingApi } from './sessionMeetingApi.js';
import { SessionMeetingHost } from './sessionMeetingHost.js';
import { setSessionMeetingDispatchHost } from './sessionMeetingDispatch.js';

const log = createLogger('session-meeting');
interface Binding {
  host: SessionMeetingHost;
  stop(): Promise<void>;
  dbEpoch: number;
  current(): boolean;
  rebindIfStable(): void;
}
let binding: Binding | null = null;
let generation = 0;

/** Binds verified authority to one relay owner, account, region and profile database. */
export function startSessionMeetingRuntime(options: {
  client: DeviceLinkClient;
  revoke(meetingId: string, memberId?: string): void;
  changed(meetingId: string): void;
}): void {
  const previous = binding;
  void previous?.stop().catch((error) => log.warn('meeting runtime disposal failed', error));
  const db = getCurrentDbClientSnapshot();
  const ownerAccountId = getCurrentUserId();
  if (!db || !ownerAccountId) return;
  const epoch = ++generation;
  const scope = activeOwnerScopeKey();
  const region = getActiveAuthRealm();
  let stopped = false;
  let preservePeerLinks = false;
  const current = () => !stopped && generation === epoch && getAuthState().isAuthenticated &&
    getCurrentUserId() === ownerAccountId &&
    !isAppSessionBoundaryPending() && activeOwnerScopeKey() === scope && getActiveAuthRealm() === region &&
    getCurrentDbClientSnapshot()?.clientEpoch === db.clientEpoch;
  const host = new SessionMeetingHost({
    api: sessionMeetingApi, journal: createSessionMeetingJournal(db.client),
    ownerAccountId, hostDeviceId: getDeviceId(), isCurrent: current,
    async readSession(sessionId) {
      const rows = await db.client.query<{ id: string; title: string; status: string }>(
        'SELECT id, title, status FROM sessions WHERE id = ? LIMIT 1', [sessionId]);
      return rows[0] ?? null;
    },
    revoke: (meetingId, memberId) => {
      // A stable projection recommit replaces authority captures, not members.
      // Sending a permanent 'revoked' close here would strand valid guests.
      if (!preservePeerLinks) options.revoke(meetingId, memberId);
    },
    changed: options.changed,
  });
  let refreshing = false;
  // A same-account stable projection can advance its generation without
  // transferring the relay lease. Retire the old Host rather than relaxing
  // its captured scope, so already-admitted callbacks remain invalid forever.
  const rebindIfStable = () => {
    if (stopped || generation !== epoch || binding?.host !== host || current() ||
        isAppSessionBoundaryPending() || !getAuthState().isAuthenticated ||
        getCurrentUserId() !== ownerAccountId || getActiveAuthRealm() !== region) return;
    const active = getActiveAppSession();
    const latestDb = getCurrentDbClientSnapshot();
    if (active.mode !== 'cloud' || active.dataOwnerId !== ownerAccountId ||
        latestDb?.client !== db.client || latestDb.clientEpoch !== db.clientEpoch ||
        activeOwnerScopeKey() === scope) return;
    preservePeerLinks = true;
    startSessionMeetingRuntime(options);
  };
  const refresh = async () => {
    if (!current()) { rebindIfStable(); return; }
    if (refreshing || !current() || !options.client.hasServerCapability(SESSION_MEETING_CAPABILITY) ||
        options.client.getStatus() !== 'online') return;
    refreshing = true;
    try { await host.restore(); }
    catch { if (current()) log.debug('meeting authority refresh unavailable; retrying on next tick'); }
    finally { refreshing = false; }
  };
  const timer = setInterval(() => { void refresh(); }, 5_000);
  timer.unref?.();
  binding = { host, dbEpoch: db.clientEpoch, current, rebindIfStable, stop() {
    stopped = true;
    clearInterval(timer);
    if (binding?.host === host) setSessionMeetingDispatchHost(null);
    return host.dispose();
  } };
  setSessionMeetingDispatchHost(host);
  void refresh();
}

/** Ordinary process/relay ownership loss revokes live access but preserves membership. */
export function stopSessionMeetingRuntime(): Promise<void> {
  return binding?.stop() ?? Promise.resolve();
}

export function requireSessionMeetingHost(): SessionMeetingHost {
  binding?.rebindIfStable();
  if (!binding?.current()) throwIpcError('PRECONDITION_FAILED', 'Meeting host is unavailable');
  return binding.host;
}

/** Must be awaited before disposing the outgoing profile; disk failure aborts handover. */
export async function closeSessionMeetingsBeforeLogout(): Promise<void> {
  if (!binding || binding.dbEpoch !== getCurrentDbClientSnapshot()?.clientEpoch) return;
  await binding.host.closeLocallyForBoundary();
  await binding.stop();
}

/** Terminal task state is durable before this runs; never reopen it on a later restore. */
export async function closeSessionMeetingForTask(sessionId: string, database: unknown): Promise<void> {
  if (getCurrentDbClientSnapshot()?.client !== database) return;
  if (!binding || binding.dbEpoch !== getCurrentDbClientSnapshot()?.clientEpoch) return;
  const ids = binding.current() ? binding.host.activeMeetingIds().filter((id) =>
    binding!.host.detail(id)?.sessionId === sessionId) : [];
  await binding.host.closeLocallyForBoundary(sessionId);
  // Network failure is retried from the terminal journal; never undo the task archive.
  for (const id of ids) void sessionMeetingApi.close(id).catch(() => undefined);
}
