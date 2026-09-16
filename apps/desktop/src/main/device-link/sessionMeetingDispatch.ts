import { isMeetingPeer, parseMeetingPeer, isSessionMeetingAttachment, type InvokePayload, type SessionMeetingQueueItem } from '@cindy/device-link';
import type { SessionMeetingHost } from './sessionMeetingHost.js';

export type SessionMeetingPeerCapture = NonNullable<ReturnType<SessionMeetingHost['capturePeer']>>;
let host: SessionMeetingHost | null = null;
let readQueueItem: ((sessionId: string, clientId: string) => (SessionMeetingQueueItem & { attachments?: unknown }) | undefined) | null = null;
export function setSessionMeetingQueueReader(value: typeof readQueueItem): void { readQueueItem = value; }
export function setSessionMeetingDispatchHost(value: SessionMeetingHost | null): void { host = value; }
export function captureSessionMeetingPeer(source: string): SessionMeetingPeerCapture | null {
  return host?.capturePeer(source) ?? null;
}

/** A newly invited device can arrive before the periodic authority refresh. */
export async function refreshSessionMeetingPeer(source: string): Promise<void> {
  const peer = parseMeetingPeer(source);
  const capturedHost = host;
  if (!peer || peer.role !== 'guest' || !capturedHost) throw new Error('Shared task host unavailable');
  await capturedHost.refresh(peer.meetingId);
  if (host !== capturedHost) throw new Error('Shared task host changed');
}

// Deliberately separate from the same-account allowlist: adding a full-device
// channel must never implicitly grant that capability to meeting guests.
const sessionReads = new Set([
  'local-db:sessions:get', 'local-db:messages:list', 'local-db:messages:view',
  'local-db:messages:view-intent', 'local-db:messages:work-details',
  'local-db:messages:around', 'local-db:messages:around-client-id',
  'local-db:messages:estimatedSessionValue', 'maker:input:get-projection',
  'maker:session-in-turn', 'maker:session-background-activity',
  'maker:session-background-tasks:list', 'maker:get-context-usage',
  'maker:get-pending-interactions', 'maker:get-session-agent-switch-intent',
]);
const inputEdits = new Set(['maker:input:update-text', 'maker:input:update-content', 'maker:input:set-edit-lock']);
const agentSettings = new Set(['maker:set-model', 'maker:set-effort', 'maker:set-fast-mode', 'maker:set-thinking-enabled', 'maker:switch-session-agent']);

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function deny(): never { throw new Error('[PERMISSION_DENIED] Meeting task access denied'); }

/** Existing attachments can survive a text edit without being re-uploaded. The
 * set comes exclusively from this member's current host-owned pending row. */
export function sessionMeetingOwnedQueueReferences(capture: SessionMeetingPeerCapture, clientId: unknown): ReadonlySet<string> {
  const result = new Set<string>();
  const item = typeof clientId === 'string' ? readQueueItem?.(capture.author.sessionId, clientId) : undefined;
  if (!item || !capture.authorize('input.edit', item)) return result;
  if (Array.isArray(item.attachments)) for (const file of item.attachments) {
    const row = record(file);
    for (const key of ['path', 'url']) if (typeof row?.[key] === 'string') result.add(row[key] as string);
  }
  return result;
}

/** Input reference metadata is consumed before Agent execution, under host authority. */
export function assertSessionMeetingReferences(value: unknown, sessionId: string, depth = 0, meetingId?: string, existing: ReadonlySet<string> = new Set()): void {
  if (depth > 32) deny();
  if (Array.isArray(value)) {
    for (const child of value) assertSessionMeetingReferences(child, sessionId, depth + 1, meetingId, existing);
    return;
  }
  const row = record(value);
  if (!row) return;
  for (const [key, child] of Object.entries(row)) {
    if (['sessionId', 'parentSessionId', 'sourceSessionId', 'targetSessionId'].includes(key) && child !== sessionId) deny();
    if (key === 'botId' || key === 'hostSnapshot') deny();
    // Native Agent tools retain normal task permissions; client references are
    // direct host reads and must come from this task's authorized upload area.
    if ((key === 'path' || key === 'url') && child !== undefined && child !== null && child !== '' &&
        !(typeof child === 'string' && (existing.has(child) || meetingId && isSessionMeetingAttachment(child, meetingId)))) deny();
    // Persisted reference chips are another input to host-side hydration.
    if (key === 'persistedContent' && typeof child === 'string') {
      let parsed: unknown;
      try { parsed = JSON.parse(child); } catch { continue; }
      assertSessionMeetingReferences(parsed, sessionId, depth + 1, meetingId, existing);
    } else if (child && typeof child === 'object') assertSessionMeetingReferences(child, sessionId, depth + 1, meetingId, existing);
  }
}

/** Validate the actual channel shape; unknown channels fail closed. */
export function assertSessionMeetingInvoke(
  capture: SessionMeetingPeerCapture, payload: InvokePayload, queueItem?: SessionMeetingQueueItem,
  phase: 'invoke' | 'result' = 'invoke',
): void {
  if (!capture.isCurrent()) deny();
  const { channel } = payload;
  const args = payload.args ?? [];
  if (!Array.isArray(args)) deny();
  const sessionId = capture.author.sessionId;
  if (channel === 'device-link:media:fetch') {
    const request = record(args[0]);
    if (args.length !== 1 || !request || typeof request.url !== 'string' ||
        Object.keys(request).some((key) => !['url', 'skipCache', 'thumbnail'].includes(key)) ||
        !capture.authorize('attachment.read')) deny();
    // The media handler validates ledger/workdir ownership before reading bytes.
    return;
  }
  // Display-only catalogs used by the existing remote composer. The provider
  // response goes through dispatch's normal credential-free projection.
  if (channel === 'maker:get-capabilities' || channel === 'maker:provider:list') {
    if (args.length > 1 || !capture.authorize('history.read')) deny();
    if (channel === 'maker:get-capabilities' && !['claude-code', 'codex', 'pi'].includes(String(args[0]))) deny();
    if (channel === 'maker:provider:list' && args[0] !== undefined) {
      const options = record(args[0]);
      if (!options || Object.keys(options).some((key) => key !== 'capabilities') ||
          !Array.isArray(options.capabilities) || options.capabilities.some((item) => typeof item !== 'string')) deny();
    }
    return;
  }
  if (channel === 'device-link:subscribe' || channel === 'device-link:unsubscribe') {
    const topics = record(args[0])?.topics;
    if (!Array.isArray(topics) || topics.length > 1 || topics.some((topic) => topic !== `session:${sessionId}`)) deny();
    if (!capture.authorize('events.subscribe')) deny();
    return;
  }
  if (args[0] !== sessionId) deny();
  const operation = sessionReads.has(channel) ? 'history.read'
    : ['maker:input:enqueue', 'maker:input:steer', 'maker:input:resume', 'maker:input:set-expanded'].includes(channel) ? 'input.send'
    : channel === 'maker:input:stop' ? 'agent.stop'
    : channel === 'maker:input:remove' ? 'input.withdraw'
    : inputEdits.has(channel) ? 'input.edit'
    : agentSettings.has(channel) ? 'agent.configure' : null;
  if (!operation) deny();
  if (phase === 'result') {
    if (!capture.authorize('history.read')) deny();
  } else {
    if (!capture.authorize(operation, queueItem ?? (typeof args[1] === 'string'
      ? readQueueItem?.(sessionId, args[1]) : undefined))) deny();
    const existing = sessionMeetingOwnedQueueReferences(capture, typeof args[1] === 'string' ? args[1] : record(args[1])?.clientId);
    assertSessionMeetingReferences(args.slice(1), sessionId, 0, capture.author.meetingId, existing);
  }
}

/** Synchronous last-mile gate, including batches, delayed pushes and offline replay. */
export function captureSessionMeetingPush(source: string, channel: string, payload: unknown): (() => boolean) | null {
  if (!isMeetingPeer(source)) return () => true;
  const capture = captureSessionMeetingPeer(source);
  if (!capture || !capture.authorize('events.subscribe')) return null;
  const sessionId = capture.author.sessionId;
  const row = record(payload);
  if (row?.sessionId !== sessionId) return null;
  // Never forward a device/account projection just because it has a sessionId.
  if (!(channel.startsWith('maker:') || channel.startsWith('local-db:messages:') ||
      channel === 'local-db:sessions:patched' || channel === 'local-db:session:error-persisted' ||
      channel.startsWith('usage:message-') || channel === 'usage:session-spend-changed' || channel === 'usage:session-tokens-changed')) return null;
  if (channel === 'maker:event:batch' && (!Array.isArray(row.events) || row.events.some((event) => record(event)?.sessionId !== sessionId))) return null;
  return () => capture.isCurrent();
}
