import { useCallback, useEffect, useMemo, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import {
  Alert,
  Badge,
  Button,
  Card,
  Collapse,
  Descriptions,
  Segmented,
  Select,
  Space,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  ApartmentOutlined,
  BranchesOutlined,
  ClockCircleOutlined,
  ReloadOutlined,
  SwapOutlined,
} from '@ant-design/icons';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '@/api/client';
import type {
  TransactionEvent,
  TransactionOperation,
  TransactionPhase,
} from '@/api/types';
import { EmptyPlaceholder } from '@/components/EmptyPlaceholder';
import { PageHeader } from '@/components/PageHeader';
import { useApi } from '@/hooks/useApi';
import { useTheme } from '@/hooks/useTheme';

const { Text } = Typography;

const OPERATION_LABELS: Record<TransactionOperation, string> = {
  source: 'Source',
  source_end: 'Source ended',
  fork: 'Fork',
  merge: 'Merge',
  switch: 'Switch',
  keep: 'Keep',
  discard: 'Discard',
  delete: 'Delete',
};

const OPERATION_COLORS: Record<TransactionOperation, string> = {
  source: 'blue',
  source_end: 'default',
  fork: 'cyan',
  merge: 'green',
  switch: 'purple',
  keep: 'geekblue',
  discard: 'orange',
  delete: 'red',
};

interface OperationGroup {
  operationId: string;
  operation: TransactionOperation;
  phase: TransactionPhase;
  events: TransactionEvent[];
  sourceRunId: string | null;
  targetRunIds: string[];
  workspace: string | null;
  occurredAt: number;
  completedAt: number;
  summary: string;
  errorMessage: string | null;
  metadata: Record<string, unknown>;
}

interface LineageGroup {
  root: string;
  workspace: string | null;
  operations: OperationGroup[];
  events: TransactionEvent[];
}

function mergeEvents(current: TransactionEvent[], incoming: TransactionEvent[]): TransactionEvent[] {
  const byId = new Map(current.map(event => [event.transaction_event_id, event]));
  incoming.forEach(event => byId.set(event.transaction_event_id, event));
  return [...byId.values()].sort((left, right) =>
    left.occurred_at - right.occurred_at
      || left.transaction_event_id - right.transaction_event_id,
  );
}

function groupOperations(events: TransactionEvent[]): OperationGroup[] {
  const grouped = new Map<string, TransactionEvent[]>();
  events.forEach(event => {
    const bucket = grouped.get(event.operation_id) ?? [];
    bucket.push(event);
    grouped.set(event.operation_id, bucket);
  });

  return [...grouped.entries()].map(([operationId, operationEvents]) => {
    operationEvents.sort((a, b) =>
      a.occurred_at - b.occurred_at || a.transaction_event_id - b.transaction_event_id,
    );
    const latest = operationEvents[operationEvents.length - 1];
    const targets = [...new Set(operationEvents
      .map(event => event.target_run_id)
      .filter((runId): runId is string => Boolean(runId)))];
    return {
      operationId,
      operation: latest.operation,
      phase: latest.phase,
      events: operationEvents,
      sourceRunId: latest.source_run_id,
      targetRunIds: targets,
      workspace: latest.workspace,
      occurredAt: operationEvents[0].occurred_at,
      completedAt: latest.occurred_at,
      summary: latest.summary,
      errorMessage: latest.error_message,
      metadata: latest.metadata ?? {},
    };
  }).sort((a, b) => b.occurredAt - a.occurredAt);
}

function buildLineages(events: TransactionEvent[]): LineageGroup[] {
  const parentByRun = new Map<string, string>();
  events
    .filter(event => event.operation === 'fork' && event.phase === 'succeeded')
    .forEach(event => {
      if (event.source_run_id && event.target_run_id) {
        parentByRun.set(event.target_run_id, event.source_run_id);
      }
    });

  const rootOf = (runId: string): string => {
    const seen = new Set<string>();
    let current = runId;
    while (parentByRun.has(current) && !seen.has(current)) {
      seen.add(current);
      current = parentByRun.get(current)!;
    }
    return current;
  };

  const operations = groupOperations(events);
  const grouped = new Map<string, LineageGroup>();
  operations.forEach(operation => {
    const seed = operation.sourceRunId ?? operation.targetRunIds[0] ?? operation.operationId;
    const root = rootOf(seed);
    const group = grouped.get(root) ?? {
      root,
      workspace: operation.workspace,
      operations: [],
      events: [],
    };
    group.operations.push(operation);
    group.events.push(...operation.events);
    group.workspace ??= operation.workspace;
    grouped.set(root, group);
  });

  return [...grouped.values()].sort((a, b) =>
    (b.operations[0]?.occurredAt ?? 0) - (a.operations[0]?.occurredAt ?? 0),
  );
}

function shortRunId(runId: string): string {
  if (runId.length <= 24) return runId;
  return `${runId.slice(0, 12)}…${runId.slice(-8)}`;
}

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleString();
}

function phaseTag(phase: TransactionPhase) {
  if (phase === 'succeeded') return <Tag color="success">Succeeded</Tag>;
  if (phase === 'failed') return <Tag color="error">Failed</Tag>;
  return <Tag color="processing">Running</Tag>;
}

function operationDuration(operation: OperationGroup): string | null {
  if (operation.phase === 'started') return null;
  const millis = Math.max(0, operation.completedAt - operation.occurredAt);
  if (millis < 1_000) return `${millis} ms`;
  if (millis < 60_000) return `${(millis / 1_000).toFixed(1)} s`;
  return `${Math.floor(millis / 60_000)}m ${Math.floor((millis % 60_000) / 1_000)}s`;
}

function LineageSummary({ group }: { group: LineageGroup }) {
  const successful = group.operations.filter(operation => operation.phase === 'succeeded');
  const forks = new Set(successful
    .filter(operation => operation.operation === 'fork')
    .flatMap(operation => operation.targetRunIds));
  const merges = successful.filter(operation =>
    operation.operation === 'merge' && operation.metadata.dry_run !== true,
  ).length;
  const discarded = successful.filter(operation => operation.operation === 'discard').length;
  const active = successful.find(operation => operation.operation === 'switch')?.sourceRunId;

  return (
    <Space size={4} wrap>
      <Tag>{forks.size} fork{forks.size === 1 ? '' : 's'}</Tag>
      <Tag color="green">{merges} merged</Tag>
      <Tag color="orange">{discarded} discarded</Tag>
      {active && <Tag color="purple">Active: {shortRunId(active)}</Tag>}
    </Space>
  );
}

function RunLink({ runId }: { runId: string }) {
  const navigate = useNavigate();
  return (
    <Tooltip title={`View ${runId} in Timeline`}>
      <Button
        type="link"
        size="small"
        style={{ paddingInline: 2, height: 'auto', fontFamily: 'monospace' }}
        onClick={event => {
          event.stopPropagation();
          navigate(`/timeline?session=${encodeURIComponent(runId)}`);
        }}
      >
        {shortRunId(runId)}
      </Button>
    </Tooltip>
  );
}

function OperationRelation({ operation }: { operation: OperationGroup }) {
  const source = operation.sourceRunId;
  const targets = operation.targetRunIds.filter(target => target !== source);
  if (!source) return <Text type="secondary">Environment-wide operation</Text>;

  if (operation.operation === 'fork') {
    return (
      <Space size={4} wrap>
        <RunLink runId={source} />
        <BranchesOutlined />
        <Text type="secondary">forked to</Text>
        {targets.map(target => <RunLink key={target} runId={target} />)}
      </Space>
    );
  }
  if (operation.operation === 'merge') {
    return (
      <Space size={4} wrap>
        <RunLink runId={source} />
        <SwapOutlined />
        <Text type="secondary">merged into</Text>
        {targets.map(target => <RunLink key={target} runId={target} />)}
      </Space>
    );
  }
  return <RunLink runId={source} />;
}

function OperationDetails({ operation }: { operation: OperationGroup }) {
  const duration = operationDuration(operation);
  const jobId = typeof operation.metadata.job_id === 'string' ? operation.metadata.job_id : null;
  const statusCommand = typeof operation.metadata.status_command === 'string'
    ? operation.metadata.status_command : null;
  const verifiedBehaviors = [
    operation.metadata.reaping_init === true ? 'Reaping init' : null,
    operation.metadata.tooling_preserved === true ? 'Tooling preserved' : null,
    operation.metadata.pane_visible === true ? 'Visible tmux pane' : null,
    operation.metadata.source_reattached === true ? 'Source reattached' : null,
    operation.metadata.progress_pane_hidden === true ? 'Progress pane hidden' : null,
    operation.metadata.file_control_bridge === true ? 'File-control fallback' : null,
    operation.metadata.duplicate_schedule_prevented === true ? 'Duplicate prevented' : null,
    operation.metadata.prompt_sent === true ? 'Prompt handed off' : null,
    operation.metadata.recursive_fork_suggestion === false ? 'No recursive fork' : null,
  ].filter((label): label is string => Boolean(label));
  return (
    <div>
      {operation.errorMessage && (
        <Alert
          type="error"
          showIcon
          message={operation.errorMessage}
          style={{ marginBottom: 12, whiteSpace: 'pre-wrap' }}
        />
      )}
      <Descriptions size="small" column={2} bordered>
        <Descriptions.Item label="Operation ID" span={2}>
          <Text copyable code>{operation.operationId}</Text>
        </Descriptions.Item>
        <Descriptions.Item label="Started">{formatTime(operation.occurredAt)}</Descriptions.Item>
        <Descriptions.Item label="Duration">{duration ?? 'In progress'}</Descriptions.Item>
        <Descriptions.Item label="Workspace" span={2}>
          <Text copyable>{operation.workspace ?? 'Unknown'}</Text>
        </Descriptions.Item>
        {operation.metadata.scope != null && (
          <Descriptions.Item label="Merge scope">{String(operation.metadata.scope)}</Descriptions.Item>
        )}
        {operation.metadata.dry_run === true && (
          <Descriptions.Item label="Mode"><Tag color="gold">Dry run</Tag></Descriptions.Item>
        )}
        {operation.metadata.force === true && (
          <Descriptions.Item label="Validation"><Tag color="warning">Forced</Tag></Descriptions.Item>
        )}
        {typeof operation.metadata.changed === 'number' && (
          <Descriptions.Item label="Changes">
            {String(operation.metadata.changed)} total · {String(operation.metadata.upserted ?? 0)} upserted · {String(operation.metadata.deleted ?? 0)} deleted
          </Descriptions.Item>
        )}
        {jobId && (
          <Descriptions.Item label="Async job"><Text copyable code>{jobId}</Text></Descriptions.Item>
        )}
        {typeof operation.metadata.status === 'string' && (
          <Descriptions.Item label="Runtime status">
            <Tag color={operation.metadata.status === 'succeeded' ? 'success' : 'processing'}>
              {operation.metadata.status}
            </Tag>
          </Descriptions.Item>
        )}
        {typeof operation.metadata.attach === 'string' && (
          <Descriptions.Item label="Visible attachment">{operation.metadata.attach}</Descriptions.Item>
        )}
        {operation.metadata.host_control === true && (
          <Descriptions.Item label="Control path">Signed host-control bridge</Descriptions.Item>
        )}
        {statusCommand && (
          <Descriptions.Item label="Status command" span={2}>
            <Text copyable code>{statusCommand}</Text>
          </Descriptions.Item>
        )}
        {verifiedBehaviors.length > 0 && (
          <Descriptions.Item label="Verified behavior" span={2}>
            <Space size={[4, 4]} wrap>
              {verifiedBehaviors.map(label => <Tag key={label} color="blue">{label}</Tag>)}
            </Space>
          </Descriptions.Item>
        )}
        {Array.isArray(operation.metadata.paths) && operation.metadata.paths.length > 0 && (
          <Descriptions.Item label="Selected paths" span={2}>
            {(operation.metadata.paths as unknown[]).map(String).join(', ')}
          </Descriptions.Item>
        )}
      </Descriptions>
      {operation.events.length > 1 && (
        <div style={{ marginTop: 14 }}>
          <Text strong style={{ display: 'block', marginBottom: 8 }}>Lifecycle progress</Text>
          {operation.events.map((event, index) => (
            <div
              key={event.transaction_event_id}
              style={{
                display: 'grid',
                gridTemplateColumns: '112px 86px minmax(0, 1fr)',
                gap: 8,
                alignItems: 'center',
                padding: '6px 0',
                borderTop: index === 0 ? undefined : '1px solid rgba(128, 128, 128, 0.16)',
              }}
            >
              <Text type="secondary" style={{ fontSize: 11 }}>
                {new Date(event.occurred_at).toLocaleTimeString()}
              </Text>
              {phaseTag(event.phase)}
              <div style={{ minWidth: 0 }}>
                <Text>{event.summary}</Text>
                {typeof event.metadata?.status === 'string' && (
                  <Text type="secondary" style={{ display: 'block', fontSize: 11 }}>
                    Job status: {event.metadata.status}
                  </Text>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function HistoryView({ group }: { group: LineageGroup }) {
  return (
    <div style={{ position: 'relative' }}>
      {group.operations.map((operation, index) => (
        <div
          key={operation.operationId}
          style={{ display: 'grid', gridTemplateColumns: '34px minmax(0, 1fr)' }}
        >
          <div style={{ position: 'relative', display: 'flex', justifyContent: 'center' }}>
            {index < group.operations.length - 1 && (
              <div style={{ position: 'absolute', top: 24, bottom: -24, width: 2, background: '#8c8c8c55' }} />
            )}
            <div style={{
              zIndex: 1,
              marginTop: 15,
              width: 12,
              height: 12,
              borderRadius: '50%',
              background: operation.phase === 'failed' ? '#ff4d4f'
                : operation.phase === 'started' ? '#1677ff' : '#52c41a',
              boxShadow: '0 0 0 3px rgba(128,128,128,0.15)',
            }} />
          </div>
          <Collapse
            ghost
            size="small"
            style={{ marginBottom: 6 }}
            items={[{
              key: operation.operationId,
              label: (
                <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr auto', gap: 10, alignItems: 'center' }}>
                  <Text type="secondary" style={{ fontSize: 11 }}>{formatTime(operation.occurredAt)}</Text>
                  <div style={{ minWidth: 0 }}>
                    <Space size={4} wrap>
                      <Tag color={OPERATION_COLORS[operation.operation]}>
                        {OPERATION_LABELS[operation.operation]}
                      </Tag>
                      <OperationRelation operation={operation} />
                    </Space>
                    <Text type="secondary" ellipsis style={{ display: 'block', fontSize: 11 }}>
                      {operation.summary}
                    </Text>
                  </div>
                  {phaseTag(operation.phase)}
                </div>
              ),
              children: <OperationDetails operation={operation} />,
            }]}
          />
        </div>
      ))}
    </div>
  );
}

type GraphStateStatus =
  | 'normal'
  | 'merged'
  | 'active'
  | 'superseded'
  | 'discarded'
  | 'deleted'
  | 'ended';

interface GraphStateNode {
  kind: 'state';
  id: string;
  runId: string;
  version: number;
  caption: string;
  status: GraphStateStatus;
  column: number;
  lane: number;
}

interface GraphOperationNode {
  kind: 'operation';
  id: string;
  operation: OperationGroup;
  column: number;
  lane: number;
  validatedBy?: OperationGroup;
}

type DependencyNode = GraphStateNode | GraphOperationNode;

interface DependencyEdge {
  id: string;
  fromId: string;
  toId: string;
  color: string;
  dashed: boolean;
  summary: string;
  fromOffset?: number;
  toOffset?: number;
}

interface DependencyGraphModel {
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  operations: OperationGroup[];
  laneCount: number;
  maxColumn: number;
}

const STATE_WIDTH = 190;
const STATE_HEIGHT = 64;
const OPERATION_WIDTH = 96;
const OPERATION_HEIGHT = 64;
const COLUMN_GAP = 230;
const LANE_GAP = 122;

function operationRunKey(operation: OperationGroup): string {
  return `${operation.sourceRunId ?? ''}->${operation.targetRunIds[0] ?? ''}`;
}

function operationParent(operation: OperationGroup): string | null {
  return [...operation.events].reverse()
    .find(event => event.parent_run_id)?.parent_run_id ?? null;
}

function buildDependencyGraph(group: LineageGroup): DependencyGraphModel {
  const operations = groupOperations(group.events)
    .sort((left, right) => left.occurredAt - right.occurredAt);
  const mergedRuns = new Set(operations
    .filter(operation => operation.operation === 'merge'
      && operation.phase === 'succeeded'
      && operation.metadata.dry_run !== true)
    .map(operation => operation.sourceRunId)
    .filter((runId): runId is string => Boolean(runId)));
  const activeRuns = new Set(operations
    .filter(operation => operation.operation === 'switch' && operation.phase === 'succeeded')
    .map(operation => operation.sourceRunId)
    .filter((runId): runId is string => Boolean(runId)));
  const removedRuns = new Set(operations
    .filter(operation => (operation.operation === 'discard' || operation.operation === 'delete')
      && operation.phase === 'succeeded')
    .map(operation => operation.sourceRunId)
    .filter((runId): runId is string => Boolean(runId)));

  const forkTargets = operations
    .filter(operation => operation.operation === 'fork')
    .flatMap(operation => operation.events
      .filter(event => event.phase === 'succeeded' && event.target_run_id)
      .map(event => event.target_run_id!));
  const outcomeRank = (runId: string) => mergedRuns.has(runId) ? 0
    : activeRuns.has(runId) ? 1
      : removedRuns.has(runId) ? 2 : 3;
  const orderedTargets = [...new Set(forkTargets)].sort((left, right) =>
    outcomeRank(left) - outcomeRank(right)
      || forkTargets.indexOf(left) - forkTargets.indexOf(right),
  );
  const lanes = new Map<string, number>([[group.root, 0]]);
  orderedTargets.forEach((runId, index) => lanes.set(runId, index + 1));
  let nextLane = orderedTargets.length + 1;
  const laneOf = (runId: string): number => {
    const existing = lanes.get(runId);
    if (existing != null) return existing;
    const lane = nextLane++;
    lanes.set(runId, lane);
    return lane;
  };

  // A successful validation immediately before a real merge is represented as
  // a badge on that merge. The exact dry-run operation remains in History.
  const hiddenDryRuns = new Set<string>();
  const validationByMerge = new Map<string, OperationGroup>();
  const pendingValidation = new Map<string, OperationGroup>();
  operations.forEach(operation => {
    if (operation.operation !== 'merge') return;
    if (operation.metadata.dry_run === true) {
      if (operation.phase === 'succeeded') pendingValidation.set(operationRunKey(operation), operation);
      return;
    }
    const validation = pendingValidation.get(operationRunKey(operation));
    if (validation) {
      hiddenDryRuns.add(validation.operationId);
      validationByMerge.set(operation.operationId, validation);
      pendingValidation.delete(operationRunKey(operation));
    }
  });

  const nodes: DependencyNode[] = [];
  const edges: DependencyEdge[] = [];
  const currentState = new Map<string, GraphStateNode>();
  const versions = new Map<string, number>();
  const cursor = new Map<string, number>();
  let stateSequence = 0;
  let edgeSequence = 0;

  const addState = (
    runId: string,
    column: number,
    caption: string,
    status: GraphStateStatus = 'normal',
    incrementVersion = false,
  ): GraphStateNode => {
    const version = (versions.get(runId) ?? 0) + (incrementVersion ? 1 : 0);
    versions.set(runId, version);
    const state: GraphStateNode = {
      kind: 'state',
      id: `state:${runId}:${stateSequence++}`,
      runId,
      version,
      caption,
      status,
      column,
      lane: laneOf(runId),
    };
    nodes.push(state);
    currentState.set(runId, state);
    cursor.set(runId, column);
    return state;
  };
  const ensureState = (runId: string): GraphStateNode => currentState.get(runId)
    ?? addState(runId, 0, runId === group.root ? 'source' : 'observed state');
  const addOperation = (
    operation: OperationGroup,
    column: number,
    lane: number,
  ): GraphOperationNode => {
    const node: GraphOperationNode = {
      kind: 'operation',
      id: `operation:${operation.operationId}`,
      operation,
      column,
      lane,
      validatedBy: validationByMerge.get(operation.operationId),
    };
    nodes.push(node);
    return node;
  };
  const addEdge = (
    from: DependencyNode,
    to: DependencyNode,
    operation: OperationGroup,
    fromOffset?: number,
    toOffset?: number,
  ) => {
    const dryRun = operation.operation === 'merge' && operation.metadata.dry_run === true;
    const failed = operation.phase === 'failed';
    const color = failed ? '#ff4d4f' : dryRun ? '#d89614'
      : operation.operation === 'merge' ? '#52c41a'
        : operation.operation === 'switch' ? '#9254de'
          : operation.operation === 'discard' ? '#fa8c16'
            : operation.operation === 'delete' ? '#ff4d4f'
              : operation.operation === 'source_end' ? '#8c8c8c' : '#1677ff';
    edges.push({
      id: `edge:${edgeSequence++}`,
      fromId: from.id,
      toId: to.id,
      color,
      dashed: failed || dryRun,
      summary: operation.summary,
      fromOffset,
      toOffset,
    });
  };

  ensureState(group.root);
  operations.forEach(operation => {
    if (operation.operation === 'source' || hiddenDryRuns.has(operation.operationId)) return;
    const sourceRun = operation.sourceRunId ?? group.root;
    const source = ensureState(sourceRun);
    const parentRun = operationParent(operation);

    if (operation.operation === 'fork') {
      const operationColumn = (cursor.get(sourceRun) ?? source.column) + 1;
      const operationNode = addOperation(operation, operationColumn, laneOf(sourceRun));
      addEdge(source, operationNode, operation);
      const successfulTargets = [...new Set(operation.events
        .filter(event => event.phase === 'succeeded' && event.target_run_id)
        .map(event => event.target_run_id!))];
      if (successfulTargets.length > 0) {
        const continuation = addState(sourceRun, operationColumn + 1, 'fork baseline');
        addEdge(operationNode, continuation, operation, -12);
        successfulTargets.forEach((targetRun, index) => {
          const target = addState(targetRun, operationColumn + 1, 'fork');
          const spread = (index - (successfulTargets.length - 1) / 2) * 9;
          addEdge(operationNode, target, operation, spread);
        });
      } else {
        cursor.set(sourceRun, operationColumn);
      }
      return;
    }

    if (operation.operation === 'merge') {
      const targetRun = operation.targetRunIds[0] ?? parentRun;
      const target = targetRun ? ensureState(targetRun) : null;
      const operationColumn = Math.max(
        cursor.get(sourceRun) ?? source.column,
        targetRun ? (cursor.get(targetRun) ?? target?.column ?? 0) : 0,
      ) + 1;
      const operationNode = addOperation(
        operation,
        operationColumn,
        operation.phase === 'succeeded' && operation.metadata.dry_run !== true && targetRun
          ? laneOf(targetRun) : laneOf(sourceRun),
      );
      if (target && target.id !== source.id) addEdge(target, operationNode, operation, undefined, -11);
      addEdge(source, operationNode, operation, undefined, target ? 11 : undefined);
      cursor.set(sourceRun, operationColumn);
      if (targetRun) cursor.set(targetRun, operationColumn);
      if (operation.phase === 'succeeded' && operation.metadata.dry_run !== true && targetRun) {
        source.status = 'merged';
        const mergedState = addState(targetRun, operationColumn + 1, 'after merge', 'normal', true);
        addEdge(operationNode, mergedState, operation);
      } else if (operation.phase === 'failed') {
        const unchangedState = addState(sourceRun, operationColumn + 1, 'unchanged · merge failed');
        addEdge(operationNode, unchangedState, operation);
      }
      return;
    }

    if (operation.operation === 'switch') {
      const parent = parentRun && parentRun !== sourceRun ? ensureState(parentRun) : null;
      const operationColumn = Math.max(
        cursor.get(sourceRun) ?? source.column,
        parentRun ? (cursor.get(parentRun) ?? parent?.column ?? 0) : 0,
      ) + 1;
      const operationNode = addOperation(operation, operationColumn, laneOf(sourceRun));
      if (parent) addEdge(parent, operationNode, operation, undefined, -11);
      addEdge(source, operationNode, operation, undefined, parent ? 11 : undefined);
      const activeState = addState(sourceRun, operationColumn + 1, 'active source', 'active');
      addEdge(operationNode, activeState, operation, 10);
      if (parent && parentRun) {
        const supersededState = addState(parentRun, operationColumn + 1, 'superseded', 'superseded');
        addEdge(operationNode, supersededState, operation, -10);
      }
      return;
    }

    const operationColumn = (cursor.get(sourceRun) ?? source.column) + 1;
    const operationNode = addOperation(operation, operationColumn, laneOf(sourceRun));
    addEdge(source, operationNode, operation);
    cursor.set(sourceRun, operationColumn);
    if (operation.phase !== 'succeeded') return;
    if (operation.operation === 'discard') {
      const discarded = addState(sourceRun, operationColumn + 1, 'discarded', 'discarded');
      addEdge(operationNode, discarded, operation);
    } else if (operation.operation === 'delete') {
      const deleted = addState(sourceRun, operationColumn + 1, 'deleted · history retained', 'deleted');
      addEdge(operationNode, deleted, operation);
    } else if (operation.operation === 'source_end') {
      const ended = addState(sourceRun, operationColumn + 1, 'source ended', 'ended');
      addEdge(operationNode, ended, operation);
    }
  });

  return {
    nodes,
    edges,
    operations,
    laneCount: Math.max(1, nextLane),
    maxColumn: Math.max(0, ...nodes.map(node => node.column)),
  };
}

function DependencyGraph({ group }: { group: LineageGroup }) {
  const { isDark } = useTheme();
  const navigate = useNavigate();
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [selectedOperation, setSelectedOperation] = useState<string | null>(null);
  const graph = useMemo(() => buildDependencyGraph(group), [group]);
  const positioned = new Map(graph.nodes.map(node => {
    const width = node.kind === 'state' ? STATE_WIDTH : OPERATION_WIDTH;
    const height = node.kind === 'state' ? STATE_HEIGHT : OPERATION_HEIGHT;
    return [node.id, {
      node,
      width,
      height,
      x: 34 + node.column * COLUMN_GAP,
      y: 42 + node.lane * LANE_GAP,
    }] as const;
  }));
  const width = Math.max(760, 68 + graph.maxColumn * COLUMN_GAP + STATE_WIDTH);
  const height = Math.max(250, 88 + graph.laneCount * LANE_GAP);
  const selected = selectedOperation
    ? graph.operations.find(operation => operation.operationId === selectedOperation)
    : null;

  const related = new Set<string>();
  if (hoveredNode) {
    related.add(hoveredNode);
    const visit = (direction: 'forward' | 'backward') => {
      const pending = [hoveredNode];
      while (pending.length > 0) {
        const current = pending.pop()!;
        graph.edges.forEach(edge => {
          const next = direction === 'forward' && edge.fromId === current ? edge.toId
            : direction === 'backward' && edge.toId === current ? edge.fromId : null;
          if (next && !related.has(next)) {
            related.add(next);
            pending.push(next);
          }
        });
      }
    };
    visit('forward');
    visit('backward');
  }

  const markerKey = group.root.replace(/[^a-zA-Z0-9_-]/g, '-');
  const markerColors = [
    ['blue', '#1677ff'],
    ['green', '#52c41a'],
    ['purple', '#9254de'],
    ['orange', '#fa8c16'],
    ['red', '#ff4d4f'],
    ['gold', '#d89614'],
    ['gray', '#8c8c8c'],
  ] as const;
  const markerName = (color: string) => markerColors.find(([, value]) => value === color)?.[0] ?? 'gray';

  return (
    <div>
      <Space size={6} wrap style={{ marginBottom: 12 }}>
        <Text type="secondary" style={{ fontSize: 11 }}>Read left to right</Text>
        <Tag color="blue">State snapshot</Tag>
        <Tag color="green">Merged</Tag>
        <Tag color="purple">Active</Tag>
        <Tag color="red">Failed / deleted</Tag>
        <Text type="secondary" style={{ fontSize: 11 }}>Dashed = no state change</Text>
      </Space>
      <div style={{ overflowX: 'auto', border: `1px solid ${isDark ? '#303030' : '#f0f0f0'}`, borderRadius: 8 }}>
        <svg width={width} height={height} style={{ display: 'block', fontFamily: 'sans-serif' }}>
          <defs>
            {markerColors.map(([name, color]) => (
              <marker
                key={name}
                id={`transaction-arrow-${markerKey}-${name}`}
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill={color} />
              </marker>
            ))}
          </defs>
          {graph.edges.map(edge => {
            const from = positioned.get(edge.fromId);
            const to = positioned.get(edge.toId);
            if (!from || !to) return null;
            const startX = from.x + from.width;
            const startY = from.y + from.height / 2 + (edge.fromOffset ?? 0);
            const endX = to.x;
            const endY = to.y + to.height / 2 + (edge.toOffset ?? 0);
            const midX = startX + Math.max(18, (endX - startX) / 2);
            const dimmed = hoveredNode != null
              && (!related.has(edge.fromId) || !related.has(edge.toId));
            return (
              <path
                key={edge.id}
                d={`M ${startX} ${startY} H ${midX} V ${endY} H ${endX}`}
                fill="none"
                stroke={edge.color}
                strokeWidth={2}
                strokeDasharray={edge.dashed ? '6 5' : undefined}
                markerEnd={`url(#transaction-arrow-${markerKey}-${markerName(edge.color)})`}
                opacity={dimmed ? 0.14 : 0.9}
              >
                <title>{edge.summary}</title>
              </path>
            );
          })}
          {graph.nodes.map(node => {
            const position = positioned.get(node.id)!;
            const dimmed = hoveredNode != null && !related.has(node.id);
            if (node.kind === 'operation') {
              const failed = node.operation.phase === 'failed';
              const dryRun = node.operation.operation === 'merge' && node.operation.metadata.dry_run === true;
              const stroke = failed ? '#ff4d4f' : dryRun ? '#d89614'
                : node.operation.operation === 'merge' ? '#52c41a'
                  : node.operation.operation === 'switch' ? '#9254de'
                    : node.operation.operation === 'discard' ? '#fa8c16'
                      : node.operation.operation === 'delete' ? '#ff4d4f' : '#1677ff';
              const label = dryRun ? 'Validate' : OPERATION_LABELS[node.operation.operation];
              const asyncJob = typeof node.operation.metadata.job_id === 'string';
              const hasSubtitle = Boolean(node.validatedBy || asyncJob || failed);
              return (
                <g
                  key={node.id}
                  transform={`translate(${position.x} ${position.y})`}
                  opacity={dimmed ? 0.2 : 1}
                  onMouseEnter={() => setHoveredNode(node.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  onClick={() => setSelectedOperation(node.operation.operationId)}
                  style={{ cursor: 'pointer' }}
                >
                  <polygon
                    points={`0,${OPERATION_HEIGHT / 2} ${OPERATION_WIDTH / 2},0 ${OPERATION_WIDTH},${OPERATION_HEIGHT / 2} ${OPERATION_WIDTH / 2},${OPERATION_HEIGHT}`}
                    fill={isDark ? '#1f1f1f' : '#ffffff'}
                    stroke={stroke}
                    strokeWidth={2}
                    strokeDasharray={failed || dryRun ? '5 4' : undefined}
                  />
                  <text
                    x={OPERATION_WIDTH / 2}
                    y={hasSubtitle ? 27 : 34}
                    textAnchor="middle"
                    fontSize={11}
                    fontWeight={600}
                    fill={isDark ? '#f0f0f0' : '#262626'}
                  >
                    {label}
                  </text>
                  {node.validatedBy && (
                    <text x={OPERATION_WIDTH / 2} y={43} textAnchor="middle" fontSize={8} fill="#d89614">
                      ✓ validated
                    </text>
                  )}
                  {!node.validatedBy && asyncJob && (
                    <text x={OPERATION_WIDTH / 2} y={43} textAnchor="middle" fontSize={8} fill="#1677ff">
                      async job
                    </text>
                  )}
                  {failed && (
                    <text x={OPERATION_WIDTH / 2} y={50} textAnchor="middle" fontSize={8} fill="#ff4d4f">
                      failed
                    </text>
                  )}
                  <title>{node.operation.summary} · Click for details</title>
                </g>
              );
            }

            const palette = node.status === 'active'
              ? { fill: isDark ? '#2b1d4f' : '#f2e8ff', stroke: '#9254de' }
              : node.status === 'merged'
                ? { fill: isDark ? '#193d2a' : '#f6ffed', stroke: '#52c41a' }
                : node.status === 'superseded' || node.status === 'ended'
                  ? { fill: isDark ? '#262626' : '#fafafa', stroke: '#8c8c8c' }
                  : node.status === 'discarded'
                    ? { fill: isDark ? '#4a3218' : '#fff7e6', stroke: '#fa8c16' }
                    : node.status === 'deleted'
                      ? { fill: isDark ? '#3a2020' : '#fff1f0', stroke: '#ff4d4f' }
                      : { fill: isDark ? '#16283d' : '#e6f4ff', stroke: '#1677ff' };
            return (
              <g
                key={node.id}
                transform={`translate(${position.x} ${position.y})`}
                opacity={dimmed ? 0.2 : 1}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => navigate(`/timeline?session=${encodeURIComponent(node.runId)}`)}
                style={{ cursor: 'pointer' }}
              >
                <rect
                  width={STATE_WIDTH}
                  height={STATE_HEIGHT}
                  rx={8}
                  fill={palette.fill}
                  stroke={palette.stroke}
                  strokeWidth={node.status === 'active' ? 2 : 1.5}
                  strokeDasharray={node.status === 'superseded' || node.status === 'deleted' ? '5 4' : undefined}
                />
                <text x={12} y={25} fontSize={12} fontWeight={600} fill={isDark ? '#f0f0f0' : '#262626'}>
                  {shortRunId(node.runId)}
                </text>
                <text x={12} y={46} fontSize={10} fill={isDark ? '#bfbfbf' : '#595959'}>
                  {`S${node.version} · ${node.caption}`}
                </text>
                <title>Open {node.runId} in Timeline</title>
              </g>
            );
          })}
        </svg>
      </div>
      <Text type="secondary" style={{ display: 'block', marginTop: 8, fontSize: 11 }}>
        A repeated run name is a later snapshot of the same environment, not another container.
        Hover to trace its ancestors and descendants; select a state for Timeline or an operation for details.
      </Text>
      {selected && (
        <Card
          size="small"
          title={`${OPERATION_LABELS[selected.operation]} operation`}
          extra={<Button type="text" size="small" onClick={() => setSelectedOperation(null)}>Close</Button>}
          style={{ marginTop: 12 }}
        >
          <OperationRelation operation={selected} />
          <div style={{ marginTop: 10 }}>
            <OperationDetails operation={selected} />
          </div>
        </Card>
      )}
    </div>
  );
}

export default function Transactions() {
  const [searchParams] = useSearchParams();
  const linkedOperation = searchParams.get('operation');
  const fetchEvents = useCallback(() => api.transactionEvents(1_000, 0), []);
  const { data, loading, error, refetch } = useApi(fetchEvents);
  const [events, setEvents] = useState<TransactionEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [view, setView] = useState<'History' | 'Dependencies'>('Dependencies');
  const [operationFilter, setOperationFilter] = useState<TransactionOperation | undefined>();
  const [phaseFilter, setPhaseFilter] = useState<TransactionPhase | undefined>();

  useEffect(() => {
    if (data) setEvents(current => mergeEvents(current, data));
  }, [data]);

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    listen<TransactionEvent>('transaction-event', event => {
      setEvents(current => mergeEvents(current, [event.payload]));
    }).then(stop => {
      if (cancelled) stop();
      else {
        unlisten = stop;
        setConnected(true);
      }
    }).catch(() => setConnected(false));
    return () => {
      cancelled = true;
      unlisten?.();
      setConnected(false);
    };
  }, []);

  const lineages = useMemo(() => buildLineages(events)
    .map(group => ({
      ...group,
      operations: group.operations.filter(operation =>
        (!operationFilter || operation.operation === operationFilter)
          && (!phaseFilter || operation.phase === phaseFilter)
          && (!linkedOperation || operation.operationId === linkedOperation),
      ),
    }))
    .filter(group => group.operations.length > 0),
  [events, linkedOperation, operationFilter, phaseFilter]);

  return (
    <div>
      <PageHeader
        title="Transactions"
        description="History and dependencies for transactional environments."
        extra={(
          <Space wrap>
            <Badge status={connected ? 'processing' : 'default'} text={connected ? 'Live' : 'Offline'} />
            <Segmented
              size="small"
              value={view}
              onChange={value => setView(value as 'History' | 'Dependencies')}
              options={[
                { label: 'Dependencies', value: 'Dependencies', icon: <ApartmentOutlined /> },
                { label: 'History', value: 'History', icon: <ClockCircleOutlined /> },
              ]}
            />
            <Select
              allowClear
              size="small"
              placeholder="Operation"
              value={operationFilter}
              onChange={setOperationFilter}
              style={{ width: 130 }}
              options={Object.entries(OPERATION_LABELS).map(([value, label]) => ({ value, label }))}
            />
            <Select
              allowClear
              size="small"
              placeholder="Status"
              value={phaseFilter}
              onChange={setPhaseFilter}
              style={{ width: 120 }}
              options={[
                { value: 'started', label: 'Running' },
                { value: 'succeeded', label: 'Succeeded' },
                { value: 'failed', label: 'Failed' },
              ]}
            />
            <Button size="small" icon={<ReloadOutlined />} onClick={refetch}>Refresh</Button>
          </Space>
        )}
      />

      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
      {linkedOperation && (
        <Alert
          type="info"
          showIcon
          message="Showing the transaction selected from Live Feed"
          description={<Text code>{linkedOperation}</Text>}
          style={{ marginBottom: 16 }}
        />
      )}
      <Card size="small" loading={loading && events.length === 0}>
        {lineages.length === 0 ? (
          <EmptyPlaceholder description="No transactional environment activity recorded yet." />
        ) : (
          <Collapse
            defaultActiveKey={lineages.slice(0, 3).map(group => group.root)}
            items={lineages.map(group => ({
              key: group.root,
              label: (
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center' }}>
                  <div style={{ minWidth: 0 }}>
                    <Text strong style={{ fontFamily: 'monospace' }}>{shortRunId(group.root)}</Text>
                    <Text type="secondary" ellipsis style={{ display: 'block', fontSize: 11 }}>
                      {group.workspace ?? 'Unknown workspace'}
                    </Text>
                  </div>
                  <LineageSummary group={group} />
                </div>
              ),
              children: view === 'History'
                ? <HistoryView group={group} />
                : <DependencyGraph group={group} />,
            }))}
          />
        )}
      </Card>
    </div>
  );
}
