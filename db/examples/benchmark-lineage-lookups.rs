//! Reproduce the PR #117 producer-lookup cost comparison without private data.
//! cargo run --release -p gensee-crate-db --example benchmark-lineage-lookups
use gensee_crate_db::sqlite::SqliteStore;
use rusqlite::{params, Connection};
use std::time::Instant;

fn query(conn: &Connection, sql: &str, artifact: i64) -> Vec<i64> {
    conn.prepare(sql)
        .unwrap()
        .query_map([artifact], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn measure(label: &str, expected: &[i64], mut operation: impl FnMut() -> Vec<i64>) {
    for _ in 0..3 {
        assert_eq!(operation(), expected);
    }
    let mut times = Vec::new();
    for _ in 0..21 {
        let started = Instant::now();
        let result = operation();
        times.push(started.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(result, expected);
    }
    times.sort_by(f64::total_cmp);
    println!(
        "{label}: median_ms={:.4} p95_ms={:.4} rows={}",
        times[10],
        times[19],
        expected.len()
    );
}

fn main() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../schema.sql")).unwrap();
    conn.execute_batch(
        "BEGIN;
         INSERT INTO sessions(session_id,agent_id,first_event_at) VALUES ('bench','test',0);
         WITH RECURSIVE ids(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ids WHERE n<60000)
         INSERT INTO requests(request_id,session_id,original_user_prompt,created_at)
            SELECT n,'bench','synthetic',0 FROM ids;
         INSERT INTO relations(src_kind,src_id,dst_kind,dst_id,relation_type,created_at)
            SELECT 'request',request_id,'artifact',
                   CASE WHEN request_id<=100 THEN 1 ELSE request_id END,'produced',0
            FROM requests;
         WITH RECURSIVE ids(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ids WHERE n<800000)
         INSERT INTO relations(src_kind,src_id,dst_kind,dst_id,relation_type,created_at)
            SELECT 'system_event',n,'artifact',1,'observed',0 FROM ids;
         COMMIT;",
    )
    .unwrap();
    // Include one-time index construction in the report, outside query timing.
    conn.execute_batch("DROP INDEX idx_relations_artifact_producer")
        .unwrap();
    let started = Instant::now();
    conn.execute_batch("CREATE INDEX idx_relations_artifact_producer ON relations(dst_kind,dst_id,src_kind,relation_type,src_id)").unwrap();
    println!("fixture: requests=60000 relations=860000 popular_sensor_edges=800000 in_memory=true encrypted=false analyzed=false index_build_ms={:.2}", started.elapsed().as_secs_f64()*1000.0);
    let store = SqliteStore::new(conn);
    let scan_requests = "SELECT DISTINCT relations.src_id FROM requests
        CROSS JOIN relations INDEXED BY sqlite_autoindex_relations_1
          ON relations.src_kind='request' AND relations.src_id=requests.request_id
         AND relations.dst_kind='artifact' AND relations.dst_id=?1 AND relations.relation_type='produced'
        WHERE requests.original_user_prompt IS NOT NULL ORDER BY relations.src_id";
    // The autoindex reference above deliberately reproduces the superseded
    // baseline; production code depends only on the explicitly named index.
    let destination_index = "SELECT DISTINCT relations.src_id FROM relations INDEXED BY idx_relations_dst
        JOIN requests ON requests.request_id=relations.src_id
        WHERE src_kind='request' AND dst_kind='artifact' AND dst_id=?1
          AND relation_type='produced' AND requests.original_user_prompt IS NOT NULL ORDER BY relations.src_id";
    for (case, artifact) in [("popular", 1), ("rare", 60000), ("absent", 999999)] {
        let expected = query(store.connection(), destination_index, artifact);
        measure(&format!("{case}/29cd7dd-scan-requests"), &expected, || {
            query(store.connection(), scan_requests, artifact)
        });
        measure(&format!("{case}/destination-index"), &expected, || {
            query(store.connection(), destination_index, artifact)
        });
        measure(&format!("{case}/covering-production"), &expected, || {
            store.producer_request_ids_for_artifact(artifact).unwrap()
        });
    }
    // A larger unrelated request history must not turn rare lookups into a scan.
    store
        .connection()
        .execute(
            "WITH RECURSIVE ids(n) AS (VALUES(60001) UNION ALL SELECT n+1 FROM ids WHERE n<120000)
         INSERT INTO requests(request_id,session_id,original_user_prompt,created_at)
            SELECT n,'bench','synthetic',0 FROM ids",
            params![],
        )
        .unwrap();
    measure("rare/covering-production-120k-requests", &[60000], || {
        store.producer_request_ids_for_artifact(60000).unwrap()
    });
}
