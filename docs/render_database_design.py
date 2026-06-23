#!/usr/bin/env python3
"""Render Gensee database design diagrams as standalone SVG images."""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Iterable


OUT_DIR = Path(__file__).resolve().parent
WIDTH = 1600
HEIGHT = 900


@dataclass(frozen=True)
class Box:
    key: str
    text: str
    x: int
    y: int
    w: int
    h: int
    color: str


class Svg:
    def __init__(self, title: str):
        self.parts: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}">',
            "<defs>",
            '<marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">',
            '<path d="M0,0 L0,6 L9,3 z" fill="#374151"/>',
            "</marker>",
            '<style>text{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;fill:#111827}.small{font-size:20px;fill:#374151}.tiny{font-size:16px;fill:#4b5563}.boxtext{font-size:20px}.title{font-size:34px;font-weight:700}.note{font-size:21px;fill:#374151}</style>',
            "</defs>",
            '<rect width="1600" height="900" fill="white"/>',
            f'<text class="title" x="48" y="62">{escape(title)}</text>',
        ]

    def box(self, box: Box) -> None:
        self.parts.append(
            f'<rect x="{box.x}" y="{box.y}" width="{box.w}" height="{box.h}" rx="14" fill="{box.color}" stroke="#203040" stroke-width="2"/>'
        )
        lines = box.text.split("\n")
        start_y = box.y + box.h / 2 - (len(lines) - 1) * 14
        for index, line in enumerate(lines):
            weight = " font-weight=\"700\"" if index == 0 else ""
            self.parts.append(
                f'<text class="boxtext" text-anchor="middle" x="{box.x + box.w / 2:.1f}" y="{start_y + index * 28:.1f}"{weight}>{escape(line)}</text>'
            )

    def text(self, x: int, y: int, text: str, class_name: str = "note") -> None:
        self.parts.append(f'<text class="{class_name}" x="{x}" y="{y}">{escape(text)}</text>')

    def arrow(
        self,
        boxes: dict[str, Box],
        src: str,
        dst: str,
        src_side: str = "right",
        dst_side: str = "left",
        label: str | None = None,
        color: str = "#374151",
        curve: int = 0,
    ) -> None:
        x1, y1 = anchor(boxes[src], src_side)
        x2, y2 = anchor(boxes[dst], dst_side)
        if curve:
            mx = (x1 + x2) / 2
            my = (y1 + y2) / 2 + curve
            path = f"M{x1:.1f},{y1:.1f} Q{mx:.1f},{my:.1f} {x2:.1f},{y2:.1f}"
        else:
            path = f"M{x1:.1f},{y1:.1f} L{x2:.1f},{y2:.1f}"
        self.parts.append(
            f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2.4" marker-end="url(#arrow)"/>'
        )
        if label:
            lx = (x1 + x2) / 2
            ly = (y1 + y2) / 2 + (curve / 2 if curve else 0)
            tw = max(70, len(label) * 11)
            self.parts.append(
                f'<rect x="{lx - tw / 2:.1f}" y="{ly - 20:.1f}" width="{tw}" height="28" rx="8" fill="white" opacity="0.9"/>'
            )
            self.parts.append(
                f'<text class="tiny" text-anchor="middle" x="{lx:.1f}" y="{ly:.1f}" fill="{color}">{escape(label)}</text>'
            )

    def legend(self, items: Iterable[tuple[str, str]], x: int, y: int) -> None:
        for index, (label, color) in enumerate(items):
            yy = y + index * 34
            self.parts.append(
                f'<rect x="{x}" y="{yy}" width="22" height="22" rx="5" fill="{color}" stroke="#203040" stroke-width="1"/>'
            )
            self.parts.append(f'<text class="tiny" x="{x + 34}" y="{yy + 18}">{escape(label)}</text>')

    def save(self, path: Path) -> None:
        path.write_text("\n".join(self.parts + ["</svg>\n"]), encoding="utf-8")


def anchor(box: Box, side: str) -> tuple[float, float]:
    if side == "left":
        return box.x, box.y + box.h / 2
    if side == "right":
        return box.x + box.w, box.y + box.h / 2
    if side == "top":
        return box.x + box.w / 2, box.y
    if side == "bottom":
        return box.x + box.w / 2, box.y + box.h
    return box.x + box.w / 2, box.y + box.h / 2


def draw_boxes(svg: Svg, boxes: dict[str, Box]) -> None:
    for box in boxes.values():
        svg.box(box)


def capture_flow() -> None:
    svg = Svg("Gensee Database Design: Capture, Persistence, Retrieval")
    colors = {
        "input": "#dbeafe",
        "intent": "#dcfce7",
        "object": "#fef3c7",
        "graph": "#ede9fe",
        "risk": "#fee2e2",
        "query": "#e0f2fe",
    }
    boxes = {
        "hook": Box("hook", "Agent hooks\nUserPromptSubmit\nPreToolUse\nPostToolUse\nStop", 60, 125, 245, 130, colors["input"]),
        "bash": Box("bash", "Bash parser\nfile intents", 60, 310, 245, 90, colors["input"]),
        "native": Box("native", "Native file tools\nRead / Write / Edit", 60, 455, 245, 95, colors["input"]),
        "watch": Box("watch", "Workspace / FSEvents\nfile effects", 60, 600, 245, 95, colors["input"]),
        "es": Box("es", "EndpointSecurity\neslogger events", 60, 735, 245, 95, colors["input"]),
        "session": Box("session", "sessions\nagent runtime\nsession ownership", 455, 130, 245, 105, colors["intent"]),
        "request": Box("request", "requests\nhuman intent\nprompt + response", 455, 300, 245, 120, colors["intent"]),
        "agent": Box("agent", "agent_events\nagent/tool intent\nhooks + file_intent", 455, 485, 245, 125, colors["intent"]),
        "system": Box("system", "system_events\nobserved impact\nfilesystem/process", 455, 690, 245, 125, colors["intent"]),
        "artifact": Box("artifact", "artifacts\nfiles/resources\nkind + uri + digest", 865, 310, 250, 125, colors["object"]),
        "relation": Box("relation", "relations\nlineage edges\nproduced, consumed_by\nderived_from, caused", 865, 555, 250, 145, colors["graph"]),
        "policy": Box("policy", "Safety policy\nallow / ask / deny", 1260, 260, 250, 105, colors["risk"]),
        "alert": Box("alert", "alerts\nseverity + action\nrule_id + evidence", 1260, 455, 250, 120, colors["risk"]),
        "timeline": Box("timeline", "gensee timeline\nprompts, tools\neffects, alerts", 1260, 665, 250, 125, colors["query"]),
    }
    draw_boxes(svg, boxes)
    edges = [
        ("hook", "session", "creates/updates"),
        ("hook", "request", "prompt/response"),
        ("hook", "agent", "hook events"),
        ("bash", "agent", "file_intent"),
        ("native", "agent", "tool event"),
        ("watch", "system", "workspace effect"),
        ("es", "system", "OS event"),
        ("request", "artifact", "acts on"),
        ("agent", "artifact", "reads/writes"),
        ("system", "artifact", "observes"),
        ("request", "relation", "lineage"),
        ("agent", "relation", "caused/observed"),
        ("system", "relation", "impact edge"),
        ("artifact", "relation", "artifact lineage", "bottom", "top"),
        ("agent", "policy", "PreToolUse"),
        ("policy", "alert", "finding", "bottom", "top"),
        ("policy", "agent", "decision", "left", "right"),
        ("alert", "timeline", "rendered", "bottom", "top"),
        ("relation", "timeline", "queried"),
    ]
    for edge in edges:
        if len(edge) == 3:
            svg.arrow(boxes, edge[0], edge[1], label=edge[2])
        else:
            svg.arrow(boxes, edge[0], edge[1], edge[3], edge[4], edge[2])
    svg.legend(
        [
            ("Capture inputs", colors["input"]),
            ("Intent / impact tables", colors["intent"]),
            ("Durable object table", colors["object"]),
            ("Lineage graph", colors["graph"]),
            ("Policy and alerts", colors["risk"]),
            ("Retrieval surfaces", colors["query"]),
        ],
        60,
        805,
    )
    svg.save(OUT_DIR / "gensee_database_capture_flow.svg")


def schema_relationships() -> None:
    svg = Svg("Gensee Database Design: Tables and Relationships")
    table = "#eef2ff"
    graph = "#fef3c7"
    alert = "#fee2e2"
    boxes = {
        "sessions": Box("sessions", "sessions\nPK session_id\nagent_id, first/last_event_at", 90, 165, 315, 120, table),
        "requests": Box("requests", "requests\nPK request_id\nFK session_id\nprompt, final_response", 640, 155, 315, 140, table),
        "agent": Box("agent", "agent_events\nPK event_id\nFK request_id\ntool JSON", 365, 405, 315, 140, table),
        "system": Box("system", "system_events\nPK event_id\nFK request_id\nargs JSON", 900, 405, 315, 140, table),
        "artifacts": Box("artifacts", "artifacts\nPK artifact_id\nUNIQUE kind, uri, digest\nmetadata JSON", 90, 665, 315, 145, graph),
        "relations": Box("relations", "relations\nsrc_kind/src_id -> dst_kind/dst_id\nrelation_type + confidence\nJSON evidence", 640, 650, 355, 170, graph),
        "alerts": Box("alerts", "alerts\nrequest_id optional entity ref\nseverity/action/rule_id\npath + evidence JSON", 1190, 650, 315, 170, alert),
    }
    draw_boxes(svg, boxes)
    svg.text(90, 112, "Ownership is direct: sessions -> requests -> events. Relations are reserved for lineage and causality.")
    svg.arrow(boxes, "sessions", "requests", label="1:N", color="#2563eb")
    svg.arrow(boxes, "requests", "agent", "bottom", "top", "1:N", color="#2563eb")
    svg.arrow(boxes, "requests", "system", "bottom", "top", "1:N", color="#2563eb")
    svg.arrow(boxes, "requests", "alerts", "right", "top", "0:N", color="#dc2626", curve=80)
    svg.arrow(boxes, "requests", "relations", "bottom", "top", "node ref", color="#7c3aed")
    svg.arrow(boxes, "agent", "relations", "bottom", "left", "node ref", color="#7c3aed")
    svg.arrow(boxes, "system", "relations", "bottom", "top", "node ref", color="#7c3aed")
    svg.arrow(boxes, "artifacts", "relations", label="node ref", color="#7c3aed")
    svg.arrow(boxes, "alerts", "agent", "left", "right", "optional entity", color="#dc2626", curve=-75)
    svg.arrow(boxes, "alerts", "system", "left", "right", "optional entity", color="#dc2626", curve=70)
    svg.arrow(boxes, "alerts", "artifacts", "left", "right", "optional entity", color="#dc2626", curve=110)
    svg.text(90, 855, "Known limit: artifacts usually dedupe by path today because digest is often empty, so content versions are not yet distinct.", "small")
    svg.save(OUT_DIR / "gensee_database_schema_relationships.svg")


def policy_flagging() -> None:
    svg = Svg("How Things Get Flagged: Versioned Policy Engine")
    colors = {
        "start": "#dbeafe",
        "decision": "#fef9c3",
        "block": "#fecaca",
        "ask": "#fed7aa",
        "allow": "#dcfce7",
        "store": "#e0f2fe",
        "data": "#ede9fe",
    }
    boxes = {
        "policy_file": Box("policy_file", "default-policy.json\nversioned rules as data\nGENSEE_POLICY_FILE\noverride", 70, 115, 305, 130, colors["data"]),
        "allowlist": Box("allowlist", "Runtime allowlist\nGENSEE_POLICY_ALLOW\n_PATH_PREFIXES", 70, 285, 305, 110, colors["data"]),
        "pre": Box("pre", "Active input\nPreToolUse hook\nBash/native tool payload", 70, 455, 280, 125, colors["start"]),
        "passive": Box("passive", "Passive input\nfile intents, workspace effects\nsystem events", 70, 645, 280, 125, colors["start"]),
        "loader": Box("loader", "Policy::global()\nload once\nembedded or override", 485, 155, 260, 115, colors["data"]),
        "subjects": Box("subjects", "Subject extraction\noperation + path\nraw payload text", 485, 430, 260, 130, colors["start"]),
        "engine": Box("engine", "Policy evaluator\nsingle source of truth\nCLI + store both call this", 820, 320, 285, 140, colors["decision"]),
        "path_rules": Box("path_rules", "Path rules\nprotected secrets\ncredential hints\npersistence writes", 805, 105, 285, 135, colors["decision"]),
        "category_rules": Box("category_rules", "Operation rules\ndestructive\noutside workspace\nmetadata, wildcard", 805, 515, 285, 135, colors["decision"]),
        "url_rules": Box("url_rules", "URL rules\ncloud metadata endpoints\nscan tool payload text", 805, 700, 285, 115, colors["decision"]),
        "block": Box("block", "BLOCK / deny\nprotected secret\noutside workspace\nmetadata URL", 1210, 170, 300, 145, colors["block"]),
        "ask": Box("ask", "ASK\ncredential hint\npersistence write\nmetadata / wildcard", 1210, 395, 300, 145, colors["ask"]),
        "allow": Box("allow", "ALLOW\nno findings\nsampler may start", 1210, 620, 300, 110, colors["allow"]),
        "alerts": Box("alerts", "alerts table\nrequest_id + entity ref\nrule_id + evidence", 1210, 760, 300, 105, colors["store"]),
    }
    draw_boxes(svg, boxes)
    svg.text(70, 78, "Rules moved from hardcoded CLI/store predicates into a versioned policy document. Strongest action wins: block > ask > allow.")
    svg.arrow(boxes, "policy_file", "loader", label="parse")
    svg.arrow(boxes, "allowlist", "engine", "right", "left", color="#7c3aed", curve=-55)
    svg.arrow(boxes, "pre", "subjects")
    svg.arrow(boxes, "passive", "subjects")
    svg.arrow(boxes, "loader", "engine", "bottom", "top")
    svg.arrow(boxes, "subjects", "engine")
    svg.arrow(boxes, "path_rules", "engine", "bottom", "top")
    svg.arrow(boxes, "category_rules", "engine", "top", "bottom")
    svg.arrow(boxes, "url_rules", "engine", "top", "bottom")
    svg.arrow(boxes, "engine", "block", color="#dc2626")
    svg.arrow(boxes, "engine", "ask", color="#ea580c")
    svg.arrow(boxes, "engine", "allow", color="#16a34a")
    svg.arrow(boxes, "block", "alerts", "right", "right", color="#dc2626", curve=210)
    svg.arrow(boxes, "ask", "alerts", "right", "right", color="#ea580c", curve=135)
    svg.text(70, 860, "Active PreToolUse findings become agent allow/ask/deny decisions. Passive observations emit recommendation alerts only.", "small")
    svg.save(OUT_DIR / "gensee_database_policy_flagging.svg")


def index_html() -> None:
    body = "\n".join(
        f'<h2>{title}</h2><img src="{name}" alt="{title}"/>'
        for title, name in [
            ("Capture, Persistence, Retrieval", "gensee_database_capture_flow.svg"),
            ("Tables and Relationships", "gensee_database_schema_relationships.svg"),
            ("Flagging and Enforcement", "gensee_database_policy_flagging.svg"),
        ]
    )
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Gensee Database Design Diagrams</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #111827; }}
    h1 {{ margin-bottom: 8px; }}
    h2 {{ margin-top: 40px; }}
    img {{ width: 100%; max-width: 1400px; border: 1px solid #e5e7eb; }}
    @media print {{ h2 {{ break-before: page; }} img {{ max-width: 100%; }} }}
  </style>
</head>
<body>
  <h1>Gensee Database Design Diagrams</h1>
  <p>Exported from docs/render_database_design.py.</p>
  {body}
</body>
</html>
"""
    (OUT_DIR / "gensee_database_design.html").write_text(html, encoding="utf-8")


if __name__ == "__main__":
    capture_flow()
    schema_relationships()
    policy_flagging()
    index_html()
