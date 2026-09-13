import { useEffect, useState } from 'react';
import { ActivityIndicator, Pressable, StyleSheet, View } from 'react-native';
import { ChevronDown, ChevronRight } from 'lucide-react-native';
import { Text } from '@/components/AppText';
import { useTheme } from '@/theme';
import { i18n } from '@/i18n';
import type { MobileMakerTransport } from '@/device-link/mobileMakerTransport';
import { fontWeight, iconSize, iconStroke, lineHeight, radius, typeScale } from '@/theme/tokens';

type Worker = { id?: string; label?: string; role?: string; status?: string; sessionId?: string };

const workerStatusKeys = new Set(['running', 'idle', 'done', 'error', 'archived']);

function statusLabel(status: string | undefined): string {
  const key = status && workerStatusKeys.has(status) ? status : 'unknown';
  return i18n.t(`session.presentation.collaboration.workerStatus.${key}`);
}

function workersFrom(value: unknown): Worker[] {
  if (Array.isArray(value)) return value.filter((v): v is Worker => !!v && typeof v === 'object');
  if (value && typeof value === 'object' && Array.isArray((value as { workers?: unknown }).workers)) {
    return workersFrom((value as { workers: unknown }).workers);
  }
  return [];
}

export function OrcaWorkerStatusCard({ leadSessionId, maker, onOpenWorker }: {
  leadSessionId: string;
  maker: MobileMakerTransport;
  /** 打开该 Worker 的会话;只读口径由 collaboration.ts 按 orcaRole 判定。 */
  onOpenWorker?: (workerSessionId: string) => void;
}) {
  const { colors } = useTheme();
  const [workers, setWorkers] = useState<Worker[] | null>(null);
  const [failed, setFailed] = useState(false);
  // 对齐桌面右侧栏「协同」tab:默认不展开,靠 attention 点把用户拉回来。
  // 桌面关闭 tab ≡ 结束协同(disableOrca);手机版第一版只读,这里只是视图折叠。
  const [expanded, setExpanded] = useState(false);
  useEffect(() => {
    let active = true;
    let loaded = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setWorkers(null);
    setFailed(false);
    // 换 Lead 等于换一份列表,展开状态不能跟着漏过去。
    setExpanded(false);
    const load = async () => {
      try {
        const next = workersFrom(await maker.listOrcaWorkersByLead(leadSessionId));
        if (active) { loaded = true; setWorkers(next); setFailed(false); }
      } catch {
        if (active && !loaded) setFailed(true);
      } finally {
        if (active) timer = setTimeout(() => void load(), 5000);
      }
    };
    void load();
    return () => {
      active = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [leadSessionId, maker]);
  if (workers === null && !failed) return <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}><ActivityIndicator /></View>;
  if (workers === null) return null;
  if (!workers.length) return null;
  const title = i18n.t('session.presentation.collaboration.workersTitle', { n: workers.length });
  const needsAttention = workers.some((worker) => worker.status === 'error');
  const Chevron = expanded ? ChevronDown : ChevronRight;
  return <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ expanded }}
      accessibilityLabel={needsAttention
        ? `${title} · ${i18n.t('session.presentation.collaboration.workerStatus.error')}`
        : title}
      onPress={() => setExpanded((value) => !value)}
      style={styles.header}
      testID="session.orcaWorkers.toggle"
    >
      <Text style={[styles.title, { color: colors.textPrimary }]}>{title}</Text>
      {!expanded && needsAttention
        ? <View style={[styles.attentionDot, { backgroundColor: colors.statusError }]} testID="session.orcaWorkers.attention" />
        : null}
      <Chevron accessible={false} color={colors.textTertiary} size={iconSize.md} strokeWidth={iconStroke.regular} />
    </Pressable>
    {expanded ? workers.map((worker, index) => {
      const name = worker.label ?? worker.role ?? `Worker ${index + 1}`;
      const workerSessionId = worker.sessionId;
      const body = <>
        <View style={[styles.dot, { backgroundColor: worker.status === 'error' ? colors.statusError : worker.status === 'done' ? colors.statusDone : colors.statusAccent }]} />
        <Text numberOfLines={1} style={[styles.name, { color: colors.textPrimary }]}>{name}</Text>
        <Text style={[styles.status, { color: colors.textSecondary }]}>{statusLabel(worker.status)}</Text>
      </>;
      const key = worker.id ?? workerSessionId ?? index;
      // 没有 sessionId 的 Worker 无处可跳,保持静态行,不做假的可点外观。
      return onOpenWorker && workerSessionId
        ? <Pressable
            key={key}
            accessibilityRole="button"
            accessibilityLabel={`${name} · ${statusLabel(worker.status)}`}
            onPress={() => onOpenWorker(workerSessionId)}
            style={({ pressed }) => [styles.row, styles.rowPressable, pressed && { opacity: 0.6 }]}
            testID={`session.orcaWorkers.worker.${workerSessionId}`}
          >
            {body}
            <ChevronRight accessible={false} color={colors.textTertiary} size={iconSize.sm} strokeWidth={iconStroke.regular} />
          </Pressable>
        : <View key={key} style={styles.row}>{body}</View>;
    }) : null}
  </View>;
}

const styles = StyleSheet.create({ card: { marginHorizontal: 12, marginBottom: 8, padding: 10, borderWidth: StyleSheet.hairlineWidth, borderRadius: radius.container }, header: { flexDirection: 'row', alignItems: 'center', gap: 7, minHeight: 44 }, title: { flex: 1, fontSize: typeScale.body, fontWeight: fontWeight.semibold }, attentionDot: { width: 6, height: 6, borderRadius: radius.micro }, row: { flexDirection: 'row', alignItems: 'center', gap: 7, minHeight: lineHeight.listBody }, rowPressable: { minHeight: 44 }, dot: { width: iconSize.sm, height: iconSize.sm, borderRadius: radius.micro }, name: { flex: 1, fontSize: typeScale.body }, status: { fontSize: typeScale.caption } });
