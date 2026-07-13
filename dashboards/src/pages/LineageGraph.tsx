import { useState } from 'react';
import { Card, Col, Row, Typography } from 'antd';
import { PageHeader }       from '@/components/PageHeader';
import { EmptyPlaceholder } from '@/components/EmptyPlaceholder';
import { useApi }           from '@/hooks/useApi';
import { api }              from '@/api/client';
import { useTheme }         from '@/hooks/useTheme';
import type { ArtifactFact, ArtifactEdge } from '@/api/types';

// ---------------------------------------------------------------------------
// Layout constants — match the original dashboard
// ---------------------------------------------------------------------------
const NODE_W  = 132;
const NODE_H  = 84;
const COLS    = 3;
const COL_GAP = 240;
const ROW_GAP = 180;
const MARGIN  = 40;
const SVG_W   = MARGIN * 2 + (COLS - 1) * COL_GAP + NODE_W;

// ---------------------------------------------------------------------------
// Colours
// ---------------------------------------------------------------------------
const NODE_COLORS: Record<string, { fill: string; text: string; tag: string }> = {
  deny:      { fill: '#5c1a1a', text: '#ffcccc', tag: '#ff6666' },
  ask:       { fill: '#5c3a1a', text: '#ffddb3', tag: '#ffaa44' },
  sensitive: { fill: '#4a3800', text: '#ffe88a', tag: '#ffc107' },
  benign:    { fill: '#1a2a3a', text: '#b0c8e0', tag: '#4a90c4' },
};

// ---------------------------------------------------------------------------
// Helpers (ported from original dashboard)
// ---------------------------------------------------------------------------

function basename(uri: string): string {
  const s = (uri || '').replace(/^file:\/\//, '').replace(/\/+$/, '');
  const i = s.lastIndexOf('/');
  return i >= 0 ? s.slice(i + 1) : s;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function classifyArtifact(fact: ArtifactFact): string {
  if (fact.risk_level)          return 'sensitive';
  if (fact.is_memory_artifact)  return 'sensitive';
  if (fact.is_control_plane)    return 'sensitive';
  if (fact.is_persistent_target)return 'sensitive';
  return 'benign';
}

function nodeEdgePoint(
  node: { x: number; y: number },
  target: { x: number; y: number },
): { x: number; y: number } {
  const cx = node.x + NODE_W / 2, cy = node.y + NODE_H / 2;
  const tx = target.x + NODE_W / 2, ty = target.y + NODE_H / 2;
  const dx = tx - cx, dy = ty - cy;
  if (dx === 0 && dy === 0) return { x: cx, y: cy };
  const scale = Math.min(
    dx === 0 ? Infinity : (NODE_W / 2) / Math.abs(dx),
    dy === 0 ? Infinity : (NODE_H / 2) / Math.abs(dy),
  );
  return { x: cx + dx * scale, y: cy + dy * scale };
}

function edgePath(
  start: { x: number; y: number },
  end:   { x: number; y: number },
): string {
  const dx = end.x - start.x, dy = end.y - start.y;
  if (Math.abs(dx) >= Math.abs(dy)) {
    const mid = start.x + dx / 2;
    return `M${start.x} ${start.y} C${mid} ${start.y} ${mid} ${end.y} ${end.x} ${end.y}`;
  }
  const mid = start.y + dy / 2;
  return `M${start.x} ${start.y} C${start.x} ${mid} ${end.x} ${mid} ${end.x} ${end.y}`;
}

// ---------------------------------------------------------------------------
// SVG Graph component
// ---------------------------------------------------------------------------

function ArtifactGraph({
  facts,
  edges,
  selectedUri,
  onSelect,
  isDark,
}: {
  facts:       ArtifactFact[];
  edges:       ArtifactEdge[];
  selectedUri: string | null;
  onSelect:    (uri: string) => void;
  isDark:      boolean;
}) {
  const visible = facts.slice(0, 6);
  const rows    = Math.ceil(visible.length / COLS);
  const svgH    = MARGIN * 2 + (rows - 1) * ROW_GAP + NODE_H + 40;

  if (!visible.length) {
    return <EmptyPlaceholder description="No artifact facts recorded yet." />;
  }

  // Compute node positions.
  const pos = new Map<string, { x: number; y: number }>();
  visible.forEach((fact, i) => {
    pos.set(fact.uri, {
      x: MARGIN + (i % COLS) * COL_GAP,
      y: MARGIN + Math.floor(i / COLS) * ROW_GAP,
    });
  });

  // Draw edges.
  const edgeEls: React.ReactNode[] = [];
  const labelEls: React.ReactNode[] = [];
  let edgesDrawn = 0;

  edges.forEach((edge, ei) => {
    const from = pos.get(edge.src_uri);
    const to   = pos.get(edge.dst_uri);
    if (!from || !to) return;

    const start = nodeEdgePoint(from, to);
    const end   = nodeEdgePoint(to, from);
    const touchesSelected = selectedUri && (edge.src_uri === selectedUri || edge.dst_uri === selectedUri);
    const stroke = touchesSelected ? '#e53935' : (isDark ? '#4a6a8a' : '#aac');

    edgeEls.push(
      <path
        key={`edge-${ei}`}
        d={edgePath(start, end)}
        stroke={stroke}
        strokeWidth={touchesSelected ? 2 : 1.5}
        fill="none"
        markerEnd="url(#arrowhead)"
        opacity={0.8}
      >
        <title>{`${basename(edge.src_uri)} → ${basename(edge.dst_uri)} · ${edge.type}`}</title>
      </path>,
    );

    labelEls.push(
      <text
        key={`label-${ei}`}
        x={(start.x + end.x) / 2}
        y={(start.y + end.y) / 2 - 6}
        textAnchor="middle"
        fontSize={10}
        fill={isDark ? '#8aaccc' : '#667'}
      >
        {edge.type}
      </text>,
    );
    edgesDrawn++;
  });

  // Draw nodes.
  const nodeEls = visible.map((fact, _i) => {
    const p     = pos.get(fact.uri)!;
    const klass = classifyArtifact(fact);
    const sel   = fact.uri === selectedUri;
    const c     = NODE_COLORS[klass] ?? NODE_COLORS.benign;

    return (
      <g
        key={fact.uri}
        transform={`translate(${p.x} ${p.y})`}
        onClick={() => onSelect(fact.uri)}
        style={{ cursor: 'pointer' }}
      >
        <title>{fact.uri.replace(/^file:\/\//, '')}</title>
        <rect
          width={NODE_W}
          height={NODE_H}
          rx={8}
          fill={c.fill}
          stroke={sel ? '#e53935' : (isDark ? '#2a4a6a' : '#aac')}
          strokeWidth={sel ? 2.5 : 1}
        />
        <text x={16} y={32} fontSize={13} fontWeight={600} fill={c.text}>
          {truncate(basename(fact.uri), 14)}
        </text>
        <text x={16} y={52} fontSize={10} fill={isDark ? '#6a8aaa' : '#88a'}>
          {(fact.last_modified_source || fact.kind || '').slice(0, 20)}
        </text>
        <text x={16} y={70} fontSize={10} fontWeight={600} fill={c.tag}>
          {klass.toUpperCase()}
        </text>
      </g>
    );
  });

  if (!edgesDrawn && visible.length) {
    labelEls.push(
      <text key="no-edges" x={MARGIN} y={svgH - 12} fontSize={12} fill={isDark ? '#555' : '#aaa'}>
        No recorded lineage edges yet — run agents to create file relationships.
      </text>,
    );
  }

  return (
    <svg width="100%" viewBox={`0 0 ${SVG_W} ${svgH}`} style={{ fontFamily: 'sans-serif' }}>
      <defs>
        <marker id="arrowhead" viewBox="0 0 10 10" refX="9" refY="5"
          markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill={isDark ? '#4a6a8a' : '#aac'} />
        </marker>
      </defs>
      {edgeEls}
      {nodeEls}
      {labelEls}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function LineageGraph() {
  const { isDark } = useTheme();
  const [selectedUri, setSelectedUri] = useState<string | null>(null);

  const { data, loading } = useApi(api.artifactGraph);
  const facts = data?.facts ?? [];
  const edges = data?.edges ?? [];

  return (
    <div>
      <PageHeader
        title="Lineage Graph"
        description="Artifact relationships and provenance tracked by Gensee."
      />

      <Row gutter={[16, 16]}>
        {/* Artifact list */}
        <Col xs={24} lg={8}>
          <Card size="small" title={`Artifacts (${facts.length})`} loading={loading}>
            {facts.length === 0 ? (
              <EmptyPlaceholder description="No artifact facts recorded yet." />
            ) : (
              <div style={{ overflowY: 'auto', maxHeight: 480 }}>
                {facts.map(f => {
                  const sel  = f.uri === selectedUri;
                  const name = basename(f.uri);
                  return (
                    <div
                      key={f.uri}
                      onClick={() => setSelectedUri(sel ? null : f.uri)}
                      style={{
                        padding:      '6px 8px',
                        cursor:       'pointer',
                        borderRadius: 4,
                        marginBottom: 2,
                        background:   sel
                          ? (isDark ? '#1a3a5a' : '#e6f0ff')
                          : 'transparent',
                        borderLeft: `3px solid ${sel ? '#e53935' : 'transparent'}`,
                      }}
                    >
                      <Typography.Text
                        strong={sel}
                        style={{ fontSize: 12, display: 'block' }}
                        ellipsis={{ tooltip: f.uri }}
                      >
                        {name}
                      </Typography.Text>
                      <Typography.Text type="secondary" style={{ fontSize: 10 }}>
                        {f.kind}
                        {f.last_modified_source ? ` · ${f.last_modified_source}` : ''}
                        {f.risk_level ? ` · ⚠ ${f.risk_level}` : ''}
                      </Typography.Text>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </Col>

        {/* Graph canvas */}
        <Col xs={24} lg={16}>
          <Card
            size="small"
            title="Lineage Graph"
            loading={loading}
            style={{ minHeight: 400 }}
          >
            <ArtifactGraph
              facts={facts}
              edges={edges}
              selectedUri={selectedUri}
              onSelect={uri => setSelectedUri(prev => prev === uri ? null : uri)}
              isDark={isDark}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
