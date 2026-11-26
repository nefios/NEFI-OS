"""NEFI OS - rapporto di incidente (HTML autonomo, stampabile; il Security Center lo salva anche in PDF).

Funzioni pure: dal caso, dalla sua cronologia e dalle prove collegate al testo del rapporto.
Nessuna dipendenza da Qt: si prova con tests/test_response.py.
"""
import html
import time

DESCRIBE = {
    "incident-opened": "Incident opened", "incident-closed": "Incident closed", "note": "Note",
    "severity-changed": "Severity changed", "category-changed": "Category changed", "status-changed": "Status changed",
    "assignee-changed": "Assignee changed", "linked": "Item linked", "playbook-started": "Playbook started",
    "playbook-step": "Playbook step", "playbook-action-started": "Automatic action started",
    "host-isolated": "Host isolated from the network", "host-isolation-confirmed": "Isolation confirmed",
    "host-released": "Network isolation removed", "host-released-auto": "Isolation removed automatically",
    "host-isolation-reapplied": "Isolation applied again", "process-frozen": "Process suspended",
    "process-resumed": "Process resumed", "process-terminated": "Process terminated",
    "file-quarantined": "File quarantined", "file-restored": "File restored from quarantine",
    "quarantined-file-deleted": "Quarantined file deleted", "ioc-blocked": "Indicator blocked",
    "ioc-unblocked": "Indicator unblocked", "ioc-sweep": "Search for blocked hashes",
    "recovery-check": "Recovery checks run", "recovery-item": "Recovery item updated",
}
CONTAINMENT = ("host-isolated", "host-released", "host-released-auto", "process-frozen", "process-resumed",
               "process-terminated", "file-quarantined", "file-restored", "quarantined-file-deleted",
               "ioc-blocked", "ioc-unblocked")


def esc(x):
    return html.escape(str(x if x is not None else ""))


def details_text(rec):
    d = rec.get("details") or {}
    if rec.get("action") == "note":
        return d.get("text", "")
    if rec.get("action", "").endswith("-changed"):
        return f"{d.get('old', '')} → {d.get('new', '')}"
    return ", ".join(f"{k}: {v}" for k, v in d.items())


def duration(start, end):
    """'2 d 3 h' tra due date ISO, oppure ''."""
    try:
        a = time.mktime(time.strptime(start[:19], "%Y-%m-%dT%H:%M:%S"))
        b = time.mktime(time.strptime(end[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return ""
    mins = max(0, int(b - a) // 60)
    d, h, m = mins // 1440, mins % 1440 // 60, mins % 60
    return " ".join(x for x in (f"{d} d" if d else "", f"{h} h" if h else "", f"{m} min" if not d else "") if x)


def table(headers, rows):
    if not rows:
        return "<p class='none'>None.</p>"
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>" for r in rows)
    # gli attributi servono a Qt (PDF), che del CSS delle tabelle capisce poco; i browser usano il CSS
    return f"<table width='100%' border='1' cellspacing='0' cellpadding='4'><tr>{head}</tr>{body}</table>"


def build(case, timeline, evidence, playbook, recovery, labels, chain_ok=None, host=""):
    """-> HTML del rapporto.
    evidence: voci dell'indice DFIR del caso;  playbook: definizione (o None);
    recovery: [(testo, stato)];  labels: {"categories": {...}}"""
    t = lambda x: str(x or "")[:19].replace("T", " ")                      # noqa: E731
    cat = labels.get("categories", {}).get(case.get("category"), case.get("category", ""))
    notes = [r for r in timeline if r.get("action") == "note"]
    actions = [r for r in timeline if r.get("action") in CONTAINMENT]
    first_contain = next((r for r in timeline if r.get("action") in ("host-isolated", "process-frozen",
                          "process-terminated", "file-quarantined", "ioc-blocked")), None)
    facts = [("Incident", case.get("id")), ("Machine", host), ("Severity", str(case.get("severity", "")).upper()),
             ("Category", cat), ("Status", case.get("status")), ("Opened", f"{t(case.get('opened'))} by {case.get('opened_by', '')}"),
             ("Handled by", case.get("assignee", "")),
             ("Time to first containment", duration(case.get("opened"), first_contain["ts"]) if first_contain else "no containment action"),
             ("Closed", t(case.get("closed")) or "still open"),
             ("Duration", duration(case.get("opened"), case.get("closed")) if case.get("closed") else "")]
    steps = []
    if playbook:
        state = (case.get("playbook") or {}).get("steps", {})
        for s in playbook["steps"]:
            st = state.get(s["id"], {})
            steps.append([s.get("phase", ""), s["title"], st.get("state", "not done"), st.get("by", ""), t(st.get("ts")),
                          st.get("note", "")])
    chain = "" if chain_ok is None else (
        "<p class='ok'>Timeline integrity verified: no record was removed or changed.</p>" if chain_ok else
        "<p class='bad'>WARNING: the timeline failed its integrity check. Records may have been removed or changed.</p>")
    css = ("body{font-family:sans-serif;color:#1c2b2d;margin:32px;font-size:13px}h1{font-size:22px;margin-bottom:2px}"
           "h2{font-size:15px;margin-top:26px;border-bottom:2px solid #14b874;padding-bottom:3px}"
           "table{border-collapse:collapse;width:100%;margin-top:6px}th,td{border:1px solid #c9d6d7;padding:5px 7px;"
           "text-align:left;vertical-align:top}th{background:#e9f3f1}.facts td:first-child{width:210px;font-weight:bold;"
           "background:#f4f8f8}.none{color:#667}.ok{color:#0a7a4b}.bad{color:#b3261e;font-weight:bold}"
           ".sub{color:#566;margin-top:0}.foot{margin-top:30px;color:#667;font-size:11px}")
    parts = [f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Incident report {esc(case.get('id'))}</title>"
             f"<style>{css}</style></head><body>",
             f"<h1>Incident report — {esc(case.get('title'))}</h1>",
             f"<p class='sub'>{esc(case.get('id'))} · generated {time.strftime('%Y-%m-%d %H:%M')} by NEFI Security Center</p>",
             "<h2>1. Summary</h2><table class='facts' width='100%' border='1' cellspacing='0' cellpadding='4'>" + "".join(
                 f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in facts if v) + "</table>"]
    if case.get("description"):
        parts.append(f"<p><b>Description.</b> {esc(case['description'])}</p>")
    if case.get("summary"):
        parts.append(f"<p><b>Closing summary.</b> {esc(case['summary'])}</p>")
    parts += ["<h2>2. Containment and eradication actions</h2>",
              table(["Time", "Action", "Details", "By"], [[t(r.get("ts")), DESCRIBE.get(r["action"], r["action"]),
                                                          details_text(r), r.get("account", "")] for r in actions]),
              "<h2>3. Evidence</h2>",
              table(["Evidence ID", "Kind", "Collected (UTC)", "Operator", "Size (bytes)", "Signed"],
                    [[e.get("evidence_id"), e.get("kind"), e.get("collected_utc"), e.get("operator"), e.get("size"),
                      "yes" if e.get("signed") else "NO"] for e in evidence]),
              "<p class='none'>The SHA-256 of every file is in the signed manifest of each item "
              "(DFIR &gt; Evidence &amp; Custody).</p>" if evidence else ""]
    if playbook:
        parts += [f"<h2>4. Playbook: {esc(playbook['title'])}</h2>",
                  table(["Phase", "Step", "State", "By", "Time", "Note"], steps)]
    parts += ["<h2>5. Recovery checklist</h2>", table(["Item", "State"], [[label, {"done": "done", "na": "not applicable",
                                                                                  "todo": "NOT DONE"}[st]]
                                                                          for label, st in recovery]),
              "<h2>6. Analyst notes</h2>",
              table(["Time", "By", "Note"], [[t(r.get("ts")), r.get("account", ""), details_text(r)] for r in notes]),
              "<h2>7. Full timeline</h2>", chain,
              table(["Time", "Event", "Details", "By"], [[t(r.get("ts")), DESCRIBE.get(r.get("action"), r.get("action")),
                                                         details_text(r), r.get("account", "")] for r in timeline]),
              "<p class='foot'>Times are local time of the machine. This report is generated from the incident record "
              "kept by NEFI OS (append-only, hash-chained timeline). It describes what was recorded on this machine; "
              "it is not a legal assessment.</p></body></html>"]
    return "\n".join(parts)
