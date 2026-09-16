import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type HostRecord = {
  options: { isCurrent(): boolean; revoke(meetingId: string, memberId?: string): void };
  restore: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
};
const state = vi.hoisted(() => ({
  accountId: 'owner', region: 'global', authenticated: true,
  session: { mode: 'cloud', dataOwnerId: 'owner', generation: 1 }, boundary: false,
  db: { client: { query: vi.fn() }, clientEpoch: 1 },
  hosts: [] as HostRecord[], dispatch: vi.fn(),
}));
vi.mock('../../localDb/client/current.js', () => ({ getCurrentDbClientSnapshot: () => state.db }));
vi.mock('../../localDb/sessionMeetings.js', () => ({ createSessionMeetingJournal: () => ({}) }));
vi.mock('../../appSessionState.js', () => ({
  activeOwnerScopeKey: () => [state.session.mode, state.session.dataOwnerId, state.session.generation].join(':'),
  getActiveAppSession: () => ({ ...state.session }), isAppSessionBoundaryPending: () => state.boundary,
}));
vi.mock('../../authManager.js', () => ({
  getAuthState: () => ({ isAuthenticated: state.authenticated }), getCurrentUserId: () => state.accountId,
  getDeviceId: () => 'host-device', getActiveAuthRealm: () => state.region,
}));
vi.mock('../../logger.js', () => ({ createLogger: () => ({ warn: vi.fn(), debug: vi.fn() }) }));
vi.mock('../sessionMeetingApi.js', () => ({ sessionMeetingApi: {} }));
vi.mock('../sessionMeetingDispatch.js', () => ({ setSessionMeetingDispatchHost: state.dispatch }));
vi.mock('../sessionMeetingHost.js', () => ({
  SessionMeetingHost: class {
    restore = vi.fn(async () => undefined);
    // The real Host disposes each existing grant through this callback.
    dispose = vi.fn(async () => { this.options.revoke('meeting-a'); });
    constructor(readonly options: HostRecord['options']) { state.hosts.push(this); }
  },
}));

import { requireSessionMeetingHost, startSessionMeetingRuntime, stopSessionMeetingRuntime } from '../sessionMeetingRuntime';

function start() {
  const client = { hasServerCapability: () => true, getStatus: () => 'online', start: vi.fn(), stop: vi.fn(), revoke: vi.fn() };
  startSessionMeetingRuntime({ client: client as never, revoke: client.revoke, changed: vi.fn() });
  return client;
}

beforeEach(async () => {
  await stopSessionMeetingRuntime();
  vi.useFakeTimers();
  state.accountId = 'owner'; state.region = 'global'; state.authenticated = true; state.boundary = false;
  state.session = { mode: 'cloud', dataOwnerId: 'owner', generation: 1 };
  state.db = { client: { query: vi.fn() }, clientEpoch: 1 };
  state.hosts.length = 0; state.dispatch.mockClear();
});
afterEach(async () => {
  await stopSessionMeetingRuntime();
  vi.useRealTimers();
});

describe('shared runtime stable owner recommit', () => {
  it('rebinds on the existing refresh tick without restarting relay or reviving old captures', async () => {
    const relay = start();
    const original = state.hosts[0];
    const oldCapture = original.options.isCurrent;
    expect(oldCapture()).toBe(true);
    state.session.generation++;
    expect(oldCapture()).toBe(false);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(state.hosts).toHaveLength(2);
    expect(original.dispose).toHaveBeenCalledOnce();
    expect(state.hosts[1].restore).toHaveBeenCalledOnce();
    expect(requireSessionMeetingHost()).toBe(state.hosts[1]);
    expect(oldCapture()).toBe(false);
    expect(relay.start).not.toHaveBeenCalled();
    expect(relay.stop).not.toHaveBeenCalled();
    expect(relay.revoke).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(state.hosts).toHaveLength(2);
  });

  it('rebinds on demand before the next tick and restores authority into a new Host', () => {
    start();
    const original = requireSessionMeetingHost();
    state.session.generation++;
    const replacement = requireSessionMeetingHost();
    expect(replacement).not.toBe(original);
    expect(replacement).toBe(state.hosts[1]);
    expect(state.hosts[1].restore).toHaveBeenCalledOnce();
  });

  it.each(['boundary', 'account', 'stable-owner', 'region', 'database', 'database-epoch', 'signed-out', 'local'])(
    'never rebinds across an unresolved %s boundary', async (change) => {
      start(); state.session.generation++;
      if (change === 'boundary') state.boundary = true;
      if (change === 'account') state.accountId = 'other';
      if (change === 'stable-owner') state.session.dataOwnerId = 'other';
      if (change === 'region') state.region = 'cn';
      if (change === 'database') state.db = { ...state.db, client: { query: vi.fn() } };
      if (change === 'database-epoch') state.db = { ...state.db, clientEpoch: state.db.clientEpoch + 1 };
      if (change === 'signed-out') state.authenticated = false;
      if (change === 'local') state.session.mode = 'local';
      expect(() => requireSessionMeetingHost()).toThrow('PRECONDITION_FAILED');
      await vi.advanceTimersByTimeAsync(10_000);
      expect(state.hosts).toHaveLength(1);
    },
  );

  it('waits for a stable same-owner boundary to finish, then rebinds', async () => {
    start(); state.session.generation++; state.boundary = true;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(state.hosts).toHaveLength(1);
    state.boundary = false;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(state.hosts).toHaveLength(2);
  });

  it('never reacquires a stopped relay owner on demand or by timer', async () => {
    const relay = start();
    await stopSessionMeetingRuntime();
    expect(relay.revoke).toHaveBeenCalledWith('meeting-a', undefined);
    state.session.generation++;
    expect(() => requireSessionMeetingHost()).toThrow('PRECONDITION_FAILED');
    await vi.advanceTimersByTimeAsync(10_000);
    expect(state.hosts).toHaveLength(1);
  });
});
