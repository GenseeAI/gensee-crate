import { query, escInt, clampLimit } from '../../db.mjs';

/**
 * GET /api/v1/artifacts
 * GET /api/v1/artifacts/:id/lineage
 */
export async function handleArtifacts(params, artifactId = null) {
  if (artifactId === 'graph') {
    return buildFullGraph();
  }
  if (artifactId != null) {
    return buildLineageGraph(artifactId);
  }

  const limit  = clampLimit(params.limit, 500);
  const offset = Math.max(parseInt(params.offset ?? '0', 10) || 0, 0);

  return query(`
    SELECT * FROM artifacts
     ORDER BY artifact_id DESC
     LIMIT ${limit} OFFSET ${offset}
  `);
}

async function buildLineageGraph(id) {
  const artifactId = escInt(id);

  // Fetch the artifact itself.
  const artifacts = await query(`
    SELECT artifact_id, kind, uri FROM artifacts WHERE artifact_id = ${artifactId}
  `);

  if (!artifacts.length) return { nodes: [], edges: [] };

  // Fetch all relations touching this artifact.
  const relations = await query(`
    SELECT * FROM relations
     WHERE (src_kind = 'artifact' AND src_id = ${artifactId})
        OR (dst_kind = 'artifact' AND dst_id = ${artifactId})
  `);

  // Collect every referenced artifact ID so we can look up their URIs.
  const relatedIds = new Set([artifactId]);
  for (const r of relations) {
    if (r.src_kind === 'artifact') relatedIds.add(r.src_id);
    if (r.dst_kind === 'artifact') relatedIds.add(r.dst_id);
  }

  const allArtifacts = await query(`
    SELECT artifact_id, kind, uri FROM artifacts
     WHERE artifact_id IN (${[...relatedIds].join(',')})
  `);

  const nodes = allArtifacts.map(a => ({
    id:    String(a.artifact_id),
    kind:  a.kind,
    label: a.uri.replace('file://', ''),
    uri:   a.uri,
  }));

  const edges = relations
    .filter(r => r.src_kind === 'artifact' && r.dst_kind === 'artifact')
    .map(r => ({
      source:        String(r.src_id),
      target:        String(r.dst_id),
      relation_type: r.relation_type,
      confidence:    r.confidence,
    }));

  return { nodes, edges };
}

/**
 * GET /api/v1/artifacts/graph
 * Returns all artifact_facts + all artifact-to-artifact relations for the full
 * lineage graph view (mirrors the original dashboards/web/ implementation).
 */
async function buildFullGraph() {
  const [facts, edges] = await Promise.all([
    query(`
      SELECT kind, uri, current_digest, last_seen_at,
             is_agent_authored, risk_level, is_memory_artifact,
             is_control_plane, is_persistent_target, last_modified_source
        FROM artifact_facts
       ORDER BY last_seen_at DESC
       LIMIT 80
    `),
    query(`
      SELECT r.relation_type AS type, r.confidence,
             sa.uri AS src_uri, da.uri AS dst_uri
        FROM relations r
        JOIN artifacts sa ON r.src_kind = 'artifact' AND r.src_id = sa.artifact_id
        JOIN artifacts da ON r.dst_kind = 'artifact' AND r.dst_id = da.artifact_id
       ORDER BY r.relation_id DESC
       LIMIT 200
    `),
  ]);
  return { facts, edges };
}
