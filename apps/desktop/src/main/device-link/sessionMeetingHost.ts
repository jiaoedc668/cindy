import {
  parseSessionMeetingSnapshot, parseMeetingPeer, type SessionMeetingApi, type SessionMeetingCaller,
  type SessionMeetingDetail, type SessionMeetingIdentity, type SessionMeetingQueueItem,
} from '@cindy/device-link';
import type { SessionMeetingJournal } from '../localDb/sessionMeetings.js';
import { SessionMeetingAccess } from './sessionMeetingAccess.js';

interface HostedMeeting {
  identity: SessionMeetingIdentity;
  access: SessionMeetingAccess;
  detail: SessionMeetingDetail | null;
}
export interface SessionMeetingHostOptions {
  api: SessionMeetingApi;
  journal: SessionMeetingJournal;
  ownerAccountId: string;
  hostDeviceId: string;
  /** Bound at construction to this profile/auth/region generation. */
  isCurrent(): boolean;
  readSession(sessionId: string): Promise<{ id: string; title: string; status: string } | null>;
  /** Teardown only the affected meeting/member, not the shared relay connection. */
  revoke(meetingId: string, memberId?: string): void;
  changed(meetingId: string): void;
}

/** One task-hosting Desktop generation. Never grants access from disk alone. */
export class SessionMeetingHost {
  private disposed = false;
  private boundaryClosed = false;
  private readonly closedSessions = new Set<string>();
  private readonly entries = new Map<string, HostedMeeting>();
  private readonly closed = new Set<string>();
  private readonly chains = new Map<string, Promise<unknown>>();
  // Keep failed writes too: disposal must not report durability after a disk error.
  private readonly closeWrites = new Map<string, Promise<void>>();
  private readonly reconciliation = new Map<string, Map<string, () => void>>();
  constructor(private readonly options: SessionMeetingHostOptions) {}

  private assertCurrent(): void {
    if (this.disposed || this.boundaryClosed || !this.options.isCurrent()) throw new Error('Meeting host generation changed');
  }
  private assertSessionOpen(sessionId: string): void {
    this.assertCurrent();
    if (this.closedSessions.has(sessionId)) throw new Error('Shared task was closed');
  }
  private requireEntry(meetingId: string): HostedMeeting {
    this.assertCurrent();
    const entry = this.entries.get(meetingId);
    if (!entry || this.closed.has(meetingId)) throw new Error('Meeting is not active here');
    return entry;
  }
  private serial<T>(meetingId: string, work: () => Promise<T>): Promise<T> {
    const result = (this.chains.get(meetingId) ?? Promise.resolve()).catch(() => undefined).then(() => {
      this.assertCurrent();
      return work();
    });
    this.chains.set(meetingId, result);
    void result.finally(() => { if (this.chains.get(meetingId) === result) this.chains.delete(meetingId); }).catch(() => undefined);
    return result;
  }
  private async accept(detail: SessionMeetingDetail): Promise<void> {
    this.assertCurrent();
    const snapshot = parseSessionMeetingSnapshot(detail);
    this.assertSessionOpen(snapshot.sessionId);
    if (snapshot.ownerAccountId !== this.options.ownerAccountId || snapshot.hostDeviceId !== this.options.hostDeviceId) throw new Error('Meeting is not hosted by this device');
    if (this.closed.has(snapshot.meetingId)) throw new Error('Meeting is closed locally');
    const session = await this.options.readSession(snapshot.sessionId);
    this.assertSessionOpen(snapshot.sessionId);
    if (!session || session.id !== snapshot.sessionId || session.status !== 'active') throw new Error('Meeting task is unavailable');
    const persisted = (await this.options.journal.latest()).find((item) => item.meetingId === snapshot.meetingId);
    this.assertSessionOpen(snapshot.sessionId);
    if (persisted?.terminal || this.closed.has(snapshot.meetingId)) throw new Error('Meeting is closed locally');
    if (persisted?.snapshot) {
      const check = new SessionMeetingAccess(persisted.snapshot);
      check.applyVerifiedSnapshot(persisted.snapshot);
      check.applyVerifiedSnapshot(snapshot);
      if (persisted.snapshot.revision > snapshot.revision) return;
    }
    let entry = this.entries.get(snapshot.meetingId);
    if (entry) {
      // Validate before writing a conflicting identity/revision into the journal.
      for (const key of ['meetingId', 'sessionId', 'ownerAccountId', 'hostDeviceId'] as const) {
        if (entry.identity[key] !== snapshot[key]) throw new Error('Meeting scope changed');
      }
    }
    await this.options.journal.recordAuthority(snapshot);
    this.assertSessionOpen(snapshot.sessionId);
    if (this.closed.has(snapshot.meetingId)) return;
    // A local close could have been persisted by another host callback while
    // this write awaited; never treat a rejected insert as permission to grant.
    const latest = (await this.options.journal.latest()).find((item) => item.meetingId === snapshot.meetingId);
    this.assertSessionOpen(snapshot.sessionId);
    if (!latest || latest.terminal && snapshot.status !== 'closed' || this.closed.has(snapshot.meetingId)) return;
    if (!latest.snapshot || latest.snapshot.revision !== snapshot.revision) return;
    if (!entry) {
      entry = { identity: snapshot, access: new SessionMeetingAccess(snapshot), detail: null };
      this.entries.set(snapshot.meetingId, entry);
    }
    if (entry.access.applyVerifiedSnapshot(snapshot) || entry.detail === null) {
      for (const previous of entry.detail?.guests ?? []) {
        const current = snapshot.guests.find((guest) => guest.memberId === previous.memberId);
        if (!current || current.version !== previous.version) this.options.revoke(snapshot.meetingId, previous.memberId);
      }
      entry.detail = detail;
      if (snapshot.status === 'closed') {
        entry.access.close();
        this.closed.add(snapshot.meetingId);
        this.options.revoke(snapshot.meetingId);
      }
      this.options.changed(snapshot.meetingId);
    }
  }
  private async refreshNow(meetingId: string): Promise<void> {
    this.assertCurrent();
    await this.accept(await this.options.api.get(meetingId));
    for (const release of this.reconciliation.get(meetingId)?.values() ?? []) release();
    this.reconciliation.delete(meetingId);
  }
  refresh(meetingId: string): Promise<void> { return this.serial(meetingId, () => this.refreshNow(meetingId)); }

  async open(sessionId: string): Promise<string> {
    this.assertSessionOpen(sessionId);
    const session = await this.options.readSession(sessionId);
    this.assertSessionOpen(sessionId);
    if (!session || session.id !== sessionId || session.status !== 'active') throw new Error('Meeting task is unavailable');
    const created = await this.options.api.create(sessionId, session.title);
    if (this.boundaryClosed || this.closedSessions.has(sessionId)) {
      await this.options.api.close(created.meetingId);
      throw new Error('Shared task was closed');
    }
    this.assertSessionOpen(sessionId);
    await this.serial(created.meetingId, async () => {
      const detail = await this.options.api.get(created.meetingId);
      if (detail.sessionId !== sessionId) throw new Error('Meeting task does not match');
      await this.accept(detail);
    });
    const detail = this.entries.get(created.meetingId)?.detail;
    if (!detail || detail.sessionId !== sessionId || detail.status !== 'active') throw new Error('Meeting could not be opened');
    return created.meetingId;
  }

  async restore(): Promise<void> {
    this.assertCurrent();
    const journal = await this.options.journal.latest();
    this.assertCurrent();
    const active = await this.options.api.list();
    this.assertCurrent();
    const owned = active.filter((item) => item.ownerAccountId === this.options.ownerAccountId && item.hostDeviceId === this.options.hostDeviceId);
    for (const item of journal) {
      if (item.terminal) this.closed.add(item.meetingId);
      else if (item.snapshot && !owned.some((meeting) => meeting.meetingId === item.meetingId)) {
        this.closed.add(item.meetingId);
        this.entries.get(item.meetingId)?.access.close();
        this.options.revoke(item.meetingId);
        await this.options.journal.close(item.snapshot);
        this.assertCurrent();
      }
    }
    for (const item of owned) {
      this.assertCurrent();
      if (this.closed.has(item.meetingId)) {
        // Retry a previous explicit close that was persisted before connectivity
        // failed. A process restart itself never closes an active meeting.
        await this.options.api.close(item.meetingId);
      } else await this.refresh(item.meetingId);
    }
  }

  detail(meetingId: string): SessionMeetingDetail | null {
    this.assertCurrent();
    return this.entries.get(meetingId)?.detail ?? null;
  }
  authorize(meetingId: string, caller: SessionMeetingCaller, sessionId: string, operation: string, queueItem?: SessionMeetingQueueItem) {
    if (this.disposed || !this.options.isCurrent() || this.closed.has(meetingId)) return { allowed: false as const, reason: 'meeting-unavailable' as const };
    return this.entries.get(meetingId)?.access.authorize(caller, sessionId, operation, queueItem) ?? { allowed: false as const, reason: 'meeting-unavailable' as const };
  }

  invite(meetingId: string) {
    return this.serial(meetingId, async () => {
      this.requireEntry(meetingId);
      const invitation = await this.options.api.invite(meetingId);
      this.assertCurrent();
      return invitation;
    });
  }
  remove(meetingId: string, memberId: string): Promise<void> {
    const release = this.requireEntry(meetingId).access.suspendMember(memberId);
    this.options.revoke(meetingId, memberId);
    return this.serial(meetingId, async () => {
      try {
        this.requireEntry(meetingId);
        await this.options.api.remove(meetingId, memberId);
      } finally {
        // On an ambiguous timeout, regain permission only from a fresh authority
        // response. If reconciliation also fails, this member stays suspended.
        try {
          await this.refreshNow(meetingId);
          release();
        } catch (error) {
          let pending = this.reconciliation.get(meetingId);
          if (!pending) this.reconciliation.set(meetingId, pending = new Map());
          const previous = pending.get(memberId);
          pending.set(memberId, () => { previous?.(); release(); });
          throw error;
        }
      }
    });
  }
  close(meetingId: string): Promise<void> {
    this.assertCurrent();
    const entry = this.entries.get(meetingId);
    if (!entry) throw new Error('Meeting is not hosted here');
    this.closed.add(meetingId);
    entry.access.close();
    if (entry.detail) entry.detail = Object.freeze({ ...entry.detail, status: 'closed' });
    // Start the profile-bound write before callbacks can dispose this host. It
    // must not queue behind HTTP or be cancelled by an account generation check.
    const persisted = this.options.journal.close(entry.identity);
    this.closeWrites.set(meetingId, persisted);
    const closing = persisted.then(async () => {
      this.assertCurrent();
      await this.options.api.close(meetingId);
    });
    this.options.revoke(meetingId);
    this.options.changed(meetingId);
    return closing;
  }
  /** Only resolve relay-stamped logical peers against verified host authority. */
  capturePeer(source: string) {
    const peer = parseMeetingPeer(source);
    if (!peer || peer.role !== 'guest' || this.disposed || !this.options.isCurrent()) return null;
    const entry = this.entries.get(peer.meetingId);
    const member = entry?.detail?.guests.find((guest) => guest.memberId === peer.memberId);
    if (!entry || !member || this.closed.has(peer.meetingId)) return null;
    const caller = Object.freeze({ accountId: member.accountId, deviceId: peer.deviceId });
    const captured = entry.access.capture(caller, entry.identity.sessionId, 'history.read');
    if (!captured.decision.allowed) return null;
    const author = Object.freeze({
      meetingId: peer.meetingId, sessionId: entry.identity.sessionId,
      memberId: member.memberId, accountId: member.accountId,
      displayName: entry.detail!.memberLabels.find((label) => label.memberId === member.memberId)?.displayName ?? member.accountId,
    });
    const isCurrent = () => !this.disposed && this.options.isCurrent() && captured.isCurrent();
    return {
      author, isCurrent,
      authorize: (operation: string, queueItem?: SessionMeetingQueueItem) =>
        isCurrent() && entry.access.authorize(caller, author.sessionId, operation, queueItem).allowed,
    };
  }

  activeMeetingIds(): string[] {
    this.assertCurrent();
    return [...this.entries].filter(([id, entry]) => !this.closed.has(id) && entry.detail?.status === 'active').map(([id]) => id);
  }

  /** Account teardown has already fenced network scopes. Durability must not depend on them. */
  async closeLocallyForBoundary(sessionId?: string): Promise<void> {
    // Fence in-flight accept/open before the first journal await.
    if (sessionId) this.closedSessions.add(sessionId);
    else this.boundaryClosed = true;
    const identities = new Map<string, SessionMeetingIdentity>();
    for (const [id, entry] of this.entries) {
      if (sessionId && entry.identity.sessionId !== sessionId) continue;
      identities.set(id, entry.identity);
      this.closed.add(id);
      entry.access.close();
      if (entry.detail) entry.detail = Object.freeze({ ...entry.detail, status: 'closed' });
      this.options.revoke(id);
      this.options.changed(id);
    }
    // Also close meetings not restored yet (e.g. logout during authority fetch).
    for (const item of await this.options.journal.latest()) {
      if (item.terminal || !item.snapshot || sessionId && item.sessionId !== sessionId) continue;
      if (item.snapshot.ownerAccountId !== this.options.ownerAccountId || item.snapshot.hostDeviceId !== this.options.hostDeviceId) continue;
      identities.set(item.meetingId, item.snapshot);
      this.closed.add(item.meetingId);
    }
    for (const [id, identity] of identities) {
      const write = this.options.journal.close(identity);
      this.closeWrites.set(id, write);
      await write;
    }
  }

  /**
   * Revokes synchronously. Await before releasing the old profile database or
   * replacing this host; only local close writes drain, never HTTP requests.
   * App exit itself does not close active meetings.
   */
  async dispose(): Promise<void> {
    this.disposed = true;
    for (const [meetingId, entry] of this.entries) {
      entry.access.close();
      this.options.revoke(meetingId);
    }
    this.entries.clear();
    const writes = await Promise.allSettled(this.closeWrites.values());
    for (const write of writes) if (write.status === 'rejected') throw write.reason;
  }
}
