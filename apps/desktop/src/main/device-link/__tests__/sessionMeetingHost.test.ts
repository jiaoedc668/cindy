import { beforeEach, describe, expect, it, vi } from 'vitest';
import { parseSessionMeetingSnapshot, type SessionMeetingDetail } from '@cindy/device-link';
import type { SessionMeetingJournalEntry } from '../../localDb/sessionMeetings.js';
import { SessionMeetingHost, type SessionMeetingHostOptions } from '../sessionMeetingHost.js';

const detail = (revision = 1): SessionMeetingDetail => ({
  meetingId: 'meeting', sessionId: 'session', ownerAccountId: 'owner', hostDeviceId: 'desktop',
  revision, status: 'active', title: 'Task',
  guests: [
    { memberId: 'member-a', accountId: 'guest-a', deviceIds: ['phone-a'], version: 1 },
    { memberId: 'member-b', accountId: 'guest-b', deviceIds: ['phone-b'], version: 1 },
  ],
  memberLabels: [],
});
const api = {
  create: vi.fn(), list: vi.fn(), get: vi.fn(), invite: vi.fn(), join: vi.fn(),
  remove: vi.fn(), leave: vi.fn(), close: vi.fn(),
};
let records: Map<string, SessionMeetingJournalEntry>;
let options: SessionMeetingHostOptions;
let host: SessionMeetingHost;
let current: boolean;
let serverDetail: SessionMeetingDetail;
const canRead = (member = 'a') => host.authorize('meeting', { accountId: `guest-${member}`, deviceId: `phone-${member}` }, 'session', 'history.read').allowed;
beforeEach(() => {
  for (const fn of Object.values(api)) fn.mockReset();
  current = true;
  serverDetail = detail();
  records = new Map();
  api.create.mockResolvedValue({ meetingId: 'meeting', revision: 1 });
  api.get.mockImplementation(async () => serverDetail);
  api.list.mockImplementation(async () => serverDetail.status === 'active' ? [serverDetail] : []);
  options = {
    api, ownerAccountId: 'owner', hostDeviceId: 'desktop', isCurrent: () => current,
    readSession: vi.fn(async (id) => ({ id, title: 'Task', status: 'active' })),
    revoke: vi.fn(), changed: vi.fn(), journal: {
      async latest() { return structuredClone([...records.values()]); },
      async recordAuthority(snapshot) {
        const previous = records.get(snapshot.meetingId);
        if (previous?.terminal || (previous?.snapshot?.revision ?? 0) >= snapshot.revision) return false;
        records.set(snapshot.meetingId, { meetingId: snapshot.meetingId, sessionId: snapshot.sessionId,
          terminal: snapshot.status === 'closed', snapshot: parseSessionMeetingSnapshot(snapshot) });
        return true;
      },
      async close(identity) {
        records.set(identity.meetingId, { meetingId: identity.meetingId, sessionId: identity.sessionId, terminal: true, snapshot: null });
      },
    },
  };
  host = new SessionMeetingHost(options);
});
describe('task host meeting lifecycle', () => {
  it('does not grant an in-flight restore after the task boundary begins', async () => {
    let release!: () => void;
    options.readSession = vi.fn(async (id) => {
      await new Promise<void>((resolve) => { release = resolve; });
      return { id, title: 'Task', status: 'active' };
    });
    const refreshing = host.refresh('meeting');
    await vi.waitFor(() => expect(release).toBeTypeOf('function'));
    await host.closeLocallyForBoundary('session');
    release();
    await expect(refreshing).rejects.toThrow('closed');
    expect(canRead()).toBe(false);
    expect(host.capturePeer('meeting~meeting~guest~member-a~phone-a')).toBeNull();
  });
  it('durably closes the outgoing profile after its network generation is fenced', async () => {
    await host.open('session');
    current = false;
    await host.dispose();
    await host.closeLocallyForBoundary();
    expect(records.get('meeting')?.terminal).toBe(true);
    expect(api.close).not.toHaveBeenCalled();
    current = true;
    const restored = new SessionMeetingHost(options);
    await restored.restore();
    expect(api.close).toHaveBeenCalledWith('meeting');
    expect(restored.capturePeer('meeting~meeting~guest~member-a~phone-a')).toBeNull();
  });

  it('closes only the archived task and propagates a journal failure', async () => {
    await host.open('session');
    await host.closeLocallyForBoundary('another-task');
    expect(canRead()).toBe(true);
    options.journal.close = vi.fn(async () => { throw new Error('disk failed'); });
    await expect(host.closeLocallyForBoundary('session')).rejects.toThrow('disk failed');
    expect(canRead()).toBe(false);
    await expect(host.dispose()).rejects.toThrow('disk failed');
  });
  it('captures only verified guest peers and revokes just the changed member', async () => {
    await host.open('session');
    expect(host.capturePeer('meeting~meeting~host')).toBeNull();
    expect(host.capturePeer('meeting~meeting~guest~member-a~phone-b')).toBeNull();
    const a = host.capturePeer('meeting~meeting~guest~member-a~phone-a')!;
    const b = host.capturePeer('meeting~meeting~guest~member-b~phone-b')!;
    expect(a.author.accountId).toBe('guest-a');
    expect(a.isCurrent()).toBe(true);
    serverDetail = { ...detail(2), guests: detail().guests.map((member) => member.memberId === 'member-a' ? { ...member, version: 2 } : member) };
    await host.refresh('meeting');
    expect(a.isCurrent()).toBe(false);
    expect(b.isCurrent()).toBe(true);
    expect(options.revoke).toHaveBeenCalledWith('meeting', 'member-a');
    expect(options.revoke).not.toHaveBeenCalledWith('meeting', 'member-b');
    await host.dispose();
    expect(b.isCurrent()).toBe(false);
  });
  it('opens an existing task and requires a server snapshot before granting access', async () => {
    expect(canRead()).toBe(false);
    expect(await host.open('session')).toBe('meeting');
    expect(api.create).toHaveBeenCalledWith('session', 'Task');
    expect(canRead()).toBe(true);
    expect(records.get('meeting')?.snapshot?.revision).toBe(1);
  });
  it('does not authorize from a persisted snapshot while offline', async () => {
    await options.journal.recordAuthority(detail());
    api.list.mockRejectedValue(new Error('offline'));
    await expect(host.restore()).rejects.toThrow('offline');
    expect(canRead()).toBe(false);
  });
  it('restores members without a new join request after the host restarts', async () => {
    await host.open('session');
    await host.dispose();
    host = new SessionMeetingHost(options);
    expect(canRead()).toBe(false);
    await host.restore();
    expect(canRead()).toBe(true);
    expect(api.join).not.toHaveBeenCalled();
  });
  it('rejects another host or a different task returned for the create result', async () => {
    serverDetail = { ...detail(), hostDeviceId: 'other-desktop' };
    await expect(host.open('session')).rejects.toThrow('not hosted');
    serverDetail = { ...detail(), sessionId: 'other-session' };
    await expect(host.open('session')).rejects.toThrow('does not match');
    expect(records.size).toBe(0);
    expect(canRead()).toBe(false);
  });
  it('drops late replies after logout or host disposal', async () => {
    api.get.mockImplementation(async () => { current = false; return detail(); });
    await expect(host.open('session')).rejects.toThrow('generation');
    expect(records.size).toBe(0);
    expect(canRead()).toBe(false);
  });
  it('denies a removed member immediately while other peers continue working', async () => {
    await host.open('session');
    let finish!: () => void;
    api.remove.mockImplementation(() => new Promise<void>((resolve) => { finish = resolve; }));
    const removing = host.remove('meeting', 'member-a');
    expect(canRead()).toBe(false);
    expect(canRead('b')).toBe(true);
    expect(options.revoke).toHaveBeenCalledWith('meeting', 'member-a');
    await vi.waitFor(() => expect(api.remove).toHaveBeenCalled());
    serverDetail = { ...detail(2), guests: [detail().guests[1]] };
    finish();
    await removing;
    expect(canRead()).toBe(false);
    expect(canRead('b')).toBe(true);
  });
  it('retains a removal fence on network failure and recovers it only by reconciliation', async () => {
    await host.open('session');
    api.remove.mockRejectedValue(new Error('offline'));
    api.get.mockRejectedValueOnce(new Error('offline'));
    await expect(host.remove('meeting', 'member-a')).rejects.toThrow('offline');
    expect(canRead()).toBe(false);
    expect(canRead('b')).toBe(true);
    await host.refresh('meeting');
    expect(canRead()).toBe(true);
  });
  it('closes locally before awaiting the server and retries durable closure after restart', async () => {
    await host.open('session');
    api.close.mockRejectedValueOnce(new Error('offline'));
    const closing = host.close('meeting');
    expect(canRead()).toBe(false);
    expect(host.detail('meeting')?.status).toBe('closed');
    await expect(closing).rejects.toThrow('offline');
    await host.dispose();
    host = new SessionMeetingHost(options);
    api.close.mockResolvedValue({ meetingId: 'meeting', status: 'closed' });
    await host.restore();
    expect(api.close).toHaveBeenCalledTimes(2);
    expect(canRead()).toBe(false);
  });
  it('observes meetings closed on another owner device without reviving cached members', async () => {
    await host.open('session');
    serverDetail = { ...detail(2), status: 'closed' };
    await host.restore();
    expect(canRead()).toBe(false);
    expect(records.get('meeting')?.terminal).toBe(true);
  });
  it.each(['dispose', 'account-switch'] as const)('persists closure despite a pending refresh and %s', async (boundary) => {
    await host.open('session');
    let finish!: (value: SessionMeetingDetail) => void;
    api.get.mockImplementationOnce(() => new Promise<SessionMeetingDetail>((resolve) => { finish = resolve; }));
    const refresh = host.refresh('meeting');
    await vi.waitFor(() => expect(finish).toBeDefined());
    const refreshFailed = expect(refresh).rejects.toThrow('generation');
    const closing = host.close('meeting');
    const closeFailed = expect(closing).rejects.toThrow('generation');
    if (boundary === 'account-switch') current = false;
    else await host.dispose();
    // The close record must not wait for the outstanding HTTP request.
    expect(records.get('meeting')?.terminal).toBe(true);
    finish(detail(2));
    await refreshFailed;
    await closeFailed;
    expect(api.close).not.toHaveBeenCalled();
    current = true;
    host = new SessionMeetingHost(options);
    await host.restore();
    expect(canRead()).toBe(false);
    expect(api.close).toHaveBeenCalledOnce();
  });
  it('waits for the bound journal on dispose without waiting for network requests', async () => {
    await host.open('session');
    const persist = options.journal.close;
    let finishWrite!: () => void;
    options.journal.close = vi.fn((identity) => new Promise<void>((resolve) => {
      finishWrite = () => { void persist(identity).then(resolve); };
    }));
    const closing = host.close('meeting');
    const closeFailed = expect(closing).rejects.toThrow('generation');
    let disposed = false;
    const disposing = Promise.resolve(host.dispose()).then(() => { disposed = true; });
    await Promise.resolve();
    expect(disposed).toBe(false);
    expect(canRead()).toBe(false);
    finishWrite();
    await disposing;
    await closeFailed;
    expect(records.get('meeting')?.terminal).toBe(true);
    expect(api.close).not.toHaveBeenCalled();
  });
  it('surfaces journal failure during close and disposal instead of claiming durability', async () => {
    await host.open('session');
    options.journal.close = vi.fn().mockRejectedValue(new Error('disk unavailable'));
    await expect(host.close('meeting')).rejects.toThrow('disk unavailable');
    expect(canRead()).toBe(false);
    expect(api.close).not.toHaveBeenCalled();
    await expect(Promise.resolve(host.dispose())).rejects.toThrow('disk unavailable');
  });
  it('does not let late refresh revive an explicitly closed meeting', async () => {
    await host.open('session');
    let finish!: (value: SessionMeetingDetail) => void;
    api.get.mockImplementationOnce(() => new Promise<SessionMeetingDetail>((resolve) => { finish = resolve; }));
    const refresh = host.refresh('meeting');
    await vi.waitFor(() => expect(finish).toBeDefined());
    const close = host.close('meeting');
    finish(detail(2));
    await expect(refresh).rejects.toThrow('closed');
    await close;
    expect(canRead()).toBe(false);
    expect(records.get('meeting')?.terminal).toBe(true);
  });
  it('keeps a live meeting usable when a background server refresh fails', async () => {
    await host.open('session');
    api.get.mockRejectedValueOnce(new Error('offline'));
    await expect(host.refresh('meeting')).rejects.toThrow('offline');
    expect(canRead()).toBe(true);
  });
});
