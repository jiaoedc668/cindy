// @vitest-environment jsdom
import { act, createElement, useEffect } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({
  listOrcaWorkersByLead: vi.fn(),
  colors: {
    surface: 'SURFACE',
    border: 'BORDER',
    textPrimary: 'TEXT_PRIMARY',
    textSecondary: 'TEXT_SECONDARY',
    textTertiary: 'TEXT_TERTIARY',
    statusAccent: 'ACCENT',
    statusDone: 'DONE',
    statusError: 'ERROR',
  },
}));

vi.mock('react-native', () => ({
  AppState: { currentState: 'active', addEventListener: () => ({ remove() {} }) },
  ScrollView: ({ children }: any) => createElement('div', {}, children),
  View: ({ children, style, testID }: any) =>
    createElement('div', { 'data-testid': testID, 'data-style': JSON.stringify(style) }, children),
  Pressable: ({ children, onPress, testID }: any) =>
    createElement(
      'button',
      { onClick: onPress, 'data-testid': testID },
      typeof children === 'function' ? children({ pressed: false }) : children,
    ),
  StyleSheet: { create: (v: any) => v, hairlineWidth: 1 },
}));
vi.mock('expo-router', () => ({ useFocusEffect: (cb: () => void) => useEffect(cb, [cb]) }));
vi.mock('lucide-react-native', () => ({
  ChevronDown: () => createElement('i', { 'data-icon': 'down' }),
  ChevronRight: () => createElement('i', { 'data-icon': 'right' }),
}));
vi.mock('@/components/AppText', () => ({
  Text: ({ children }: any) => createElement('span', {}, children),
}));
vi.mock('@/theme', () => ({ useTheme: () => ({ colors: h.colors }) }));
vi.mock('@/i18n', () => ({ i18n: { t: (key: string) => key } }));
vi.mock('@/theme/tokens', () => ({
  fontWeight: { semibold: '600' },
  iconSize: { sm: 8, md: 16 },
  iconStroke: { regular: 2 },
  lineHeight: { listBody: 20 },
  radius: { container: 12, micro: 3 },
  typeScale: { body: 14, caption: 12 },
}));

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });

const { OrcaWorkerStatusCard } = await import('@/session/OrcaWorkerStatusCard');

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  h.listOrcaWorkersByLead.mockReset();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.useRealTimers();
});

async function render(workers: unknown[], onOpenWorker?: (id: string) => void) {
  h.listOrcaWorkersByLead.mockResolvedValue(workers);
  await act(async () => {
    root.render(
      createElement(OrcaWorkerStatusCard as any, {
        leadSessionId: 'lead-1',
        maker: { listOrcaWorkersByLead: h.listOrcaWorkersByLead } as any,
        onOpenWorker,
      }),
    );
  });
}

const attentionDot = () => container.querySelector('[data-testid="session.orcaWorkers.attention"]');
const toggle = () =>
  container.querySelector('[data-testid="session.orcaWorkers.toggle"]') as HTMLButtonElement;

function backgroundColorOf(el: Element | null | undefined): string | undefined {
  const raw = el?.getAttribute('data-style');
  if (!raw) return undefined;
  return [JSON.parse(raw)].flat(Infinity).find((s: any) => s?.backgroundColor)?.backgroundColor;
}

function dotColorOf(name: string): string | undefined {
  const row = [...container.querySelectorAll('button, div')]
    .filter((el) => el.textContent?.startsWith(name))
    .pop();
  return backgroundColorOf(row?.querySelector('div[data-style]'));
}

it('拿到非空快照前不渲染,避免在测量区里先撑开再收起', async () => {
  h.listOrcaWorkersByLead.mockReturnValue(new Promise(() => {}));
  await act(async () => {
    root.render(
      createElement(OrcaWorkerStatusCard as any, {
        leadSessionId: 'lead-1',
        maker: { listOrcaWorkersByLead: h.listOrcaWorkersByLead } as any,
      }),
    );
  });
  expect(container.innerHTML).toBe('');
});

it('空团队不渲染', async () => {
  await render([]);
  expect(container.innerHTML).toBe('');
});

it('状态点按语义分流:idle 走中性色,不与运行中撞色', async () => {
  await render([
    { id: 'a', label: 'w-idle', status: 'idle', sessionId: 's-a' },
    { id: 'b', label: 'w-running', status: 'running', sessionId: 's-b' },
    { id: 'c', label: 'w-done', status: 'done', sessionId: 's-c' },
    { id: 'd', label: 'w-error', status: 'error', sessionId: 's-d' },
    { id: 'e', label: 'w-unknown', sessionId: 's-e' },
  ]);
  await act(async () => toggle().click());
  expect(dotColorOf('w-idle')).toBe('TEXT_TERTIARY');
  expect(dotColorOf('w-running')).toBe('ACCENT');
  expect(dotColorOf('w-done')).toBe('DONE');
  expect(dotColorOf('w-error')).toBe('ERROR');
  expect(dotColorOf('w-unknown')).toBe('TEXT_TERTIARY');
});

it('done 与 error 都触发折叠态提示;仅 idle/running 不提示', async () => {
  await render([{ id: 'a', label: 'w', status: 'idle', sessionId: 's-a' }]);
  expect(attentionDot()).toBeNull();

  await act(async () => root.unmount());
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await render([{ id: 'a', label: 'w', status: 'done', sessionId: 's-a' }]);
  expect(attentionDot()).not.toBeNull();
});

it('打开 Worker 即视为已查看,提示随之清除', async () => {
  const onOpenWorker = vi.fn();
  await render([{ id: 'a', label: 'w-done', status: 'done', sessionId: 's-a' }], onOpenWorker);
  expect(attentionDot()).not.toBeNull();

  await act(async () => toggle().click());
  const row = container.querySelector(
    '[data-testid="session.orcaWorkers.worker.s-a"]',
  ) as HTMLButtonElement;
  await act(async () => row.click());
  expect(onOpenWorker).toHaveBeenCalledWith('s-a');

  // 收起后不应再提示:已查看过这个 done。
  await act(async () => toggle().click());
  expect(attentionDot()).toBeNull();
});

it('已查看后状态再变动,重新提示(边沿语义,非一次性静音)', async () => {
  vi.useFakeTimers();
  const onOpenWorker = vi.fn();
  await render([{ id: 'a', label: 'w', status: 'done', sessionId: 's-a' }], onOpenWorker);
  await act(async () => toggle().click());
  await act(async () => {
    (container.querySelector(
      '[data-testid="session.orcaWorkers.worker.s-a"]',
    ) as HTMLButtonElement).click();
  });
  await act(async () => toggle().click());
  expect(attentionDot()).toBeNull();

  // 远端状态从 done 变成 error:已查看登记的是 done,比对不上 → 重新提示。
  h.listOrcaWorkersByLead.mockResolvedValue([
    { id: 'a', label: 'w', status: 'error', sessionId: 's-a' },
  ]);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(5000);
  });
  expect(attentionDot()).not.toBeNull();
});
