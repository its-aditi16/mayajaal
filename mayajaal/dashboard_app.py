"""Security team view. Run with: mayajaal dashboard

Reads shared state directly. Anything that changes state goes through the control API, so
the dashboard has no way to block someone that skips the checks or the audit log."""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import altair as alt
import httpx
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mayajaal.alerts import build_card  # noqa: E402
from mayajaal.config import Settings  # noqa: E402
from mayajaal.models import Incident  # noqa: E402
from mayajaal.store import Store  # noqa: E402
from mayajaal.traps.registry import BY_ID  # noqa: E402

st.set_page_config(page_title="Mayajaal", page_icon=":spider_web:", layout="wide")

STATUS = {
    "detected": (":orange", "Analysing"), "proving": (":orange", "Testing fix"), "shadow": (":blue", "Shadow mode"),
    "awaiting_approval": (":red", "Needs approval"), "blocked": (":green", "Blocked"),
    "declined": (":gray", "Declined"), "needs_human": (":red", "Needs a person"), "error": (":red", "Error"),
}
LABEL = {"ai_agent": "AI agent", "human": "Human", "uncertain": "Uncertain"}


@st.cache_resource
def connect() -> tuple[Settings, Store]:
    settings = Settings()
    return settings, Store(settings.db_path)


settings, store = connect()


def when(ts: float | None) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%d %b %H:%M:%S") if ts else "-"


def trap_name(trap_id: str) -> str:
    return BY_ID[trap_id].title if trap_id in BY_ID else trap_id


def call_control(path: str) -> str | None:
    """Returns an error message, or None if it worked."""
    try:
        response = httpx.post(f"{settings.public_base_url.rstrip('/')}{path}", params={"actor": "dashboard"},
                              headers={"authorization": f"Bearer {settings.admin}"}, timeout=30)
    except httpx.HTTPError as exc:
        return f"Worker not reachable at {settings.public_base_url}: {exc}"
    return None if response.is_success else response.json().get("detail", response.text)


def service_status() -> dict | None:
    try:
        return httpx.get(f"{settings.public_base_url.rstrip('/')}/healthz", timeout=2).json()
    except (httpx.HTTPError, ValueError):
        return None


def render_overview(incidents: list[Incident]) -> None:
    active = store.fixes(("active",))
    identities = sum(1 for f in active for r in f.rules if r.kind != "technique")
    recognised = sum(1 for i in incidents if i.recollection)
    cols = st.columns(5)
    cols[0].metric("Attackers caught", len(incidents))
    cols[1].metric("Labelled AI", sum(i.classification.label == "ai_agent" for i in incidents))
    cols[2].metric("Recognised from memory", recognised)
    cols[3].metric("Identities locked out", identities)
    cols[4].metric("Waiting on you", sum(i.status in ("awaiting_approval", "needs_human") for i in incidents))


def render_decision(incident: Incident) -> None:
    fix = store.get_fix(incident.fix_id) if incident.fix_id else None
    if not fix:
        return
    if fix.status == "awaiting_approval":
        st.warning("This fix passed every check and is waiting for your decision. Nothing is blocked until you approve.")
        left, right, _ = st.columns([1, 1, 4])
        if left.button("Approve block", type="primary", key=f"approve-{fix.id}"):
            st.session_state["control_error"] = call_control(f"/api/fixes/{fix.id}/approve")
            st.rerun()
        if right.button("Decline", key=f"decline-{fix.id}"):
            st.session_state["control_error"] = call_control(f"/api/fixes/{fix.id}/decline")
            st.rerun()
    elif fix.status == "active":
        st.success(f"Blocked. Approved by {fix.approved_by} on {when(fix.approved_at)}. "
                   f"Attempts since: {incident.hits_after_block}.")
        if st.button("Revoke this block", key=f"revoke-{fix.id}"):
            st.session_state["control_error"] = call_control(f"/api/fixes/{fix.id}/revoke")
            st.rerun()
    elif incident.status == "needs_human":
        st.error("No fix passed its checks, so nothing was blocked. The traps stay live. A person needs to look at this.")


def render_card(incident: Incident) -> None:
    """Exactly what build_card sends to Teams, so the approver's view is visible without Teams."""
    fix = store.get_fix(incident.fix_id) if incident.fix_id else None
    if not fix or fix.status not in ("awaiting_approval", "active", "declined"):
        return
    connected = bool(settings.teams_webhook_url)
    title = "Approval card sent to Teams" if connected else "Preview of the Teams approval card (Teams not connected)"
    with st.expander(title):
        for block in build_card(incident, fix, "#", "#")["body"]:
            if block["type"] == "FactSet":
                st.table(pd.DataFrame(block["facts"]).set_index("title").rename_axis(None).rename(
                    columns={"value": "Detail"}))
            else:
                st.write(block["text"])
        st.caption("Buttons on the card: Approve block, Decline")


def render_incident(incident: Incident) -> None:
    colour, text = STATUS[incident.status]
    c = incident.classification
    st.subheader(f"{incident.id}  {colour}[{text}]")
    st.caption(f"First seen {when(incident.created)}")
    render_decision(incident)

    if incident.recollection:
        rec = incident.recollection
        via = f", same {' and '.join(rec.identity_match)}" if rec.identity_match else ""
        st.info(f"**Mayajaal has seen this attacker before.** {rec.similarity:.0%} behaviour match with "
                f"{rec.incident_id}{via}, recalled via `{rec.backend}`.")

    source = (incident.explanation_source or "pending").replace("template", "recorded facts")
    st.markdown(f"**What happened** ({source})")
    st.write(incident.explanation or "Analysis still running.")
    render_card(incident)

    who, touched, fix_tab, log = st.tabs(["Who is it", "What it touched", "The fix", "Timeline"])
    with who:
        st.metric("Verdict", LABEL[c.label], f"score {c.score}", delta_color="off")
        for reason in c.reasons:
            st.markdown(f"- {reason}")
        st.markdown("**Probe order** (survives a new IP and a new identity)")
        st.code(" -> ".join(incident.signature) or "none")
        if incident.screened_items:
            st.warning(f"{incident.screened_items} prompt injection attempt(s) were removed before the AI read the "
                       f"evidence ({incident.shield_backend}).")

    with touched:
        radius = incident.blast_radius
        cols = st.columns(4)
        cols[0].metric("Requests", radius.get("requests", 0))
        cols[1].metric("Real data reads", radius.get("data_reads", 0))
        cols[2].metric("Stolen key uses", radius.get("stolen_token_uses", 0))
        cols[3].metric("Addresses", len(radius.get("ips_masked", [])))
        st.markdown("**Traps taken:** " + (", ".join(trap_name(t) for t in incident.traps_fired) or "none"))
        st.markdown("**Real data reached:** " + (", ".join(f"`{r}`" for r in radius.get("data_routes", [])) or "none"))
        records = store.activity_by_ids(incident.activity_ids)
        st.dataframe(pd.DataFrame([{
            "Time": when(r.ts), "Request": f"{r.method} {r.path}", "Query": r.query, "Status": r.status,
            "Kind": r.sensitivity, "Bait": r.trap_id or "", "Blocked by": r.blocked_by or "", "From": r.ip_masked,
        } for r in records]), width="stretch", hide_index=True)

    with fix_tab:
        fixes = [f for f in store.fixes() if f.incident_id == incident.id]
        if not fixes:
            st.write("No fix drafted yet.")
        for fix in reversed(fixes):
            st.markdown(f"**{fix.id}**: from `{fix.source}`, status `{fix.status}`"
                        + (f", reused from `{fix.reused_from}`" if fix.reused_from else ""))
            if fix.rationale:
                st.caption(fix.rationale)
            st.dataframe(pd.DataFrame([{
                "Kind": r.kind, "Rule": r.title,
                "Matches": " AND ".join(f"{x.field} {x.op} {x.value[:40]}" for x in r.conditions),
            } for r in fix.rules]), width="stretch", hide_index=True)
            if fix.report:
                st.caption(f"Tested on: {fix.report.backend}, took {fix.report.duration_seconds}s")
                for check in fix.report.checks:
                    st.markdown(f"{':green[PASS]' if check.passed else ':red[FAIL]'} **{check.name}**: {check.detail}")
            if fix.shadow_started:
                st.markdown(f"**Shadow mode:** {fix.shadow_hits_attacker} attacker request(s) matched, "
                            f"{fix.shadow_hits_other} from anyone else")

    with log:
        for entry in incident.timeline:
            st.markdown(f"`{when(entry.ts)}` **{entry.stage}** {entry.message}")


def render_learning_curve() -> None:
    # Only attackers a person actually blocked: a declined visit, such as a curious human, is not an attack.
    proven = [i for i in store.incidents() if i.analysis_seconds is not None and i.status == "blocked"]
    if not proven:
        st.write("The learning curve appears after the first blocked attacker.")
        return
    first_seen = [i for i in proven if not i.recollection]
    recognised = [i for i in proven if i.recollection]

    def mean(values: list[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    st.subheader("Before and after memory")

    def watch(incident: Incident) -> float:
        fix = store.get_fix(incident.fix_id)
        return fix.shadow_seconds if fix else 0.0

    before, after = st.columns(2)
    for column, title, group in ((before, "Seen for the first time", first_seen),
                                 (after, "Recognised from memory", recognised)):
        with column:
            st.markdown(f"**{title}** ({len(group)} attack(s))")
            st.metric("AI calls needed", f"{mean([i.ai_calls for i in group]):.1f}" if group else "-")
            st.metric("Watch-only wait", f"{mean([watch(i) for i in group]):g}s" if group else "-")
    st.caption("Recognised attackers need no AI drafting, so no attacker data goes to an outside model, and their proven "
               "fix needs a shorter watch-only wait. Testing does not get faster: every fix is still fully re-tested "
               "against all earlier attacks, and still needs a person's approval.")

    rows = pd.DataFrame([{
        "Attack": number, "Who": LABEL[i.classification.label],
        "Recognised": f"Yes, {i.recollection.similarity:.0%} match" if i.recollection else "No",
        "Remembered from": i.recollection.incident_id if i.recollection else "-",
        "Fix from": store.get_fix(i.fix_id).source if store.get_fix(i.fix_id) else "-",
        "AI calls": i.ai_calls, "Watch-only (s)": watch(i), "Testing (s)": i.analysis_seconds,
        "Real data reads": i.blast_radius.get("data_reads", 0),
    } for number, i in enumerate(proven, start=1)])
    st.subheader("AI calls needed, attack by attack")
    base = alt.Chart(rows).encode(
        x=alt.X("Attack:O", title="Attack", axis=alt.Axis(labelAngle=0, grid=False)),
        y=alt.Y("AI calls:Q", title="AI calls", scale=alt.Scale(domain=[0, max(2, int(rows["AI calls"].max()))]),
                axis=alt.Axis(tickMinStep=1, format="d")),
        tooltip=["Attack", "Recognised", "Fix from", "AI calls"])
    bars = base.mark_bar(size=36, cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
    labels = base.mark_text(dy=-8).encode(text="AI calls:Q")
    st.altair_chart(bars + labels, width="stretch")
    st.dataframe(rows, width="stretch", hide_index=True)


def render_memory() -> None:
    render_learning_curve()
    st.subheader("What memory has concluded")
    st.markdown("Written by AI from remembered attacks. It can be wrong, so check before acting: a person decides "
                "whether to deploy any trap it suggests.")
    if st.button("Ask memory what it has learned"):
        error = call_control("/api/reflect")
        st.toast(error or "Reflecting. This can take a minute.")
    observations = store.observations()
    if not observations:
        st.write("No observations yet. They appear after a few attacks.")
    for row in observations:
        with st.container(border=True):
            st.caption(f"{when(row['ts'])}, via {row['source']}")
            st.write(row["text"])


@st.fragment(run_every=3)
def live_view() -> None:
    incidents = list(reversed(store.incidents()))
    error = st.session_state.pop("control_error", None)
    if error:
        st.error(error)
    render_overview(incidents)
    st.divider()
    if not incidents:
        st.info("No traps have fired. Run `mayajaal demo` to see an attack.")
        return
    labels = {i.id: f"{i.id}  |  {LABEL[i.classification.label]}  |  {STATUS[i.status][1]}" for i in incidents}
    chosen = st.selectbox("Incident", list(labels), format_func=labels.get)
    render_incident(next(i for i in incidents if i.id == chosen))


# Keeps Streamlit's own promotional pop-up off a security console.
st.markdown('<style>[data-testid="stSkillsNudge"] {display: none}</style>', unsafe_allow_html=True)
st.title("Mayajaal")
st.caption("A honeypot with memory")

with st.sidebar:
    st.header("System")
    status = service_status()
    if status:
        st.success("Worker running")
        st.markdown(f"**Memory:** `{status['memory']}`\n\n**Defender AI:** `{status['defender_ai']}`\n\n"
                    f"**Prompt screen:** `{status['prompt_screen']}`\n\n**Teams:** `{status['teams']}`\n\n"
                    f"**Sentinel:** `{status['sentinel']}`")
        if status["memory"] != "hindsight":
            st.warning("Hindsight is not connected, so memory is using the basic local fallback.")
    else:
        st.warning("Worker not running. Showing saved data; approvals are unavailable.")

attacks, memory, audit = st.tabs(["Attacks", "What memory learned", "Audit log"])
with attacks:
    live_view()
with memory:
    render_memory()
with audit:
    rows = store.audit_rows()
    if rows:
        st.dataframe(pd.DataFrame([{"Time": when(r["ts"]), "Who": r["actor"], "Action": r["action"],
                                    "Target": r["target"], "Detail": r["detail"]} for r in rows]),
                     width="stretch", hide_index=True)
    else:
        st.write("Nothing yet.")
