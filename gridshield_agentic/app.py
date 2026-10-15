"""Authenticated GridShield officer dashboard and approval endpoints."""
import hmac
import os
import re
import secrets
from contextlib import ExitStack
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash

load_dotenv(interpolate=False)

app = Flask(__name__)
secret_key = os.getenv("GRIDSHIELD_WEB_SECRET_KEY", "")
officer_username = os.getenv("GRIDSHIELD_OFFICER_USERNAME", "")
officer_password_hash = os.getenv("GRIDSHIELD_OFFICER_PASSWORD_HASH", "")
if not secret_key or not officer_username or not officer_password_hash:
    raise RuntimeError("Configure GRIDSHIELD_WEB_SECRET_KEY, GRIDSHIELD_OFFICER_USERNAME, and GRIDSHIELD_OFFICER_PASSWORD_HASH in .env")
if os.getenv("GRIDSHIELD_REPOSITORY", "json").strip().lower() != "postgres":
    raise RuntimeError("Set GRIDSHIELD_REPOSITORY=postgres to enable the persistent officer approval dashboard")

app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("GRIDSHIELD_HTTPS_ONLY", "false").lower() == "true",
    MAX_CONTENT_LENGTH=16 * 1024,
)

LOGIN_PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>GridShield Officer Login</title></head><body><h1>GridShield</h1><h2>Officer Login</h2>{% if error %}<p role="alert">{{ error }}</p>{% endif %}<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><label>Username <input name="username" required autocomplete="username"></label><br><br><label>Password <input type="password" name="password" required autocomplete="current-password"></label><br><br><button type="submit">Log in</button></form></body></html>'''


DASHBOARD_PAGE = '''<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GridShield Officer Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1100px;
            margin: 2rem auto;
            padding: 0 1rem;
        }

        section {
            margin: 2rem 0;
        }

        article {
            border: 1px solid #ccc;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            overflow-wrap: anywhere;
        }

        form {
            display: inline-block;
            margin: .3rem;
        }

        button {
            padding: .5rem .7rem;
            cursor: pointer;
        }

        .muted {
            color: #555;
        }

        .investigate-link {
            display: inline-block;
            margin: 1rem 0;
            padding: .75rem 1rem;
            background: #e8f1ff;
            color: #174ea6;
            border: 1px solid #b7d0ff;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
        }

        .investigate-link:hover {
            background: #d7e6ff;
        }
    </style>
</head>

<body>
    <h1>GridShield Officer Dashboard</h1>

    <p>
        Authenticated officer:
        <strong>{{ username }}</strong>
    </p>

    <!-- NEW: Link to suspicious-event investigation and plots -->
    <p>
        <a class="investigate-link"
           href="{{ url_for('investigate') }}">
            Open suspicious-event investigation and plots
        </a>
    </p>

    {% if error %}
        <p role="alert">{{ error }}</p>
    {% endif %}

    {% if message %}
        <p role="status">{{ message }}</p>
    {% endif %}

    <section>
        <h2>Attack verification queue ({{ reviews|length }})</h2>

        {% if reviews %}
            {% for item in reviews %}
                <article>
                    <h3>Event {{ item.event_id }}</h3>

                    <p>
                        Attack probability:
                        {{ '%.2f'|format(item.attack_probability) }}
                    </p>

                    <p>Route: {{ item.confidence_route }}</p>

                    <details>
                        <summary>Measurements</summary>
                        <pre>{{ item.measurements|tojson(indent=2) }}</pre>
                    </details>

                    {% for decision in [
                        'confirmed_attack',
                        'not_attack',
                        'unresolved',
                        'pending_review'
                    ] %}
                        <form
                            method="post"
                            action="{{ url_for(
                                'review_event',
                                event_id=item.event_id
                            ) }}"
                        >
                            <input
                                type="hidden"
                                name="csrf_token"
                                value="{{ csrf_token }}"
                            >

                            <button
                                name="decision"
                                value="{{ decision }}"
                            >
                                {{ decision.replace('_', ' ') }}
                            </button>
                        </form>
                    {% endfor %}
                </article>
            {% endfor %}
        {% else %}
            <p class="muted">
                No incidents are awaiting attack verification.
            </p>
        {% endif %}
    </section>

    <section>
        <h2>Candidate model deployment approval queue ({{ deployments|length }})</h2>
        <p class="muted">Only candidates with a passing evaluation and a live approval interrupt are listed. Approval records consent only; it does not activate or replace the current model.</p>
        {% if deployments %}
            {% for item in deployments %}
                <article>
                    <h3>Candidate {{ item.candidate_model_version }}</h3>
                    <p>Evaluation: <strong>{{ item.evaluation_status }}</strong></p>
                    <p>Source workflow event: {{ item.event_id }}</p>
                    <p>Accuracy: {{ item.metrics.accuracy if item.metrics and item.metrics.accuracy is defined else 'n/a' }}</p>
                    <p>Macro F1: {{ item.metrics.macro_average.f1_score if item.metrics and item.metrics.macro_average and item.metrics.macro_average.f1_score is defined else 'n/a' }}</p>
                    <p>Evaluation report: {{ item.report_path }}</p>
                    <form method="post" action="{{ url_for('deployment_decision', candidate_version=item.candidate_model_version) }}">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                        <button name="decision" value="approved">Approve candidate (no activation)</button>
                        <button name="decision" value="rejected">Reject candidate</button>
                    </form>
                </article>
            {% endfor %}
        {% else %}
            <p class="muted">No evaluated candidates are currently waiting for deployment approval.</p>
        {% endif %}
    </section>

    <section>
        <h2>Data admission queue ({{ admissions|length }})</h2>

        {% if admissions %}
            {% for item in admissions %}
                <article>
                    <h3>Event {{ item.event_id }}</h3>

                    <p>
                        Confirmed attack · Probability
                        {{ '%.2f'|format(item.attack_probability) }}
                    </p>

                    <details>
                        <summary>Measurements</summary>
                        <pre>{{ item.measurements|tojson(indent=2) }}</pre>
                    </details>

                    {% for decision in ['approved', 'rejected'] %}
                        <form
                            method="post"
                            action="{{ url_for(
                                'admission_event',
                                event_id=item.event_id
                            ) }}"
                        >
                            <input
                                type="hidden"
                                name="csrf_token"
                                value="{{ csrf_token }}"
                            >

                            <button
                                name="decision"
                                value="{{ decision }}"
                            >
                                {{ decision }}
                            </button>
                        </form>
                    {% endfor %}
                </article>
            {% endfor %}
        {% else %}
            <p class="muted">
                No confirmed attacks are awaiting data admission.
            </p>
        {% endif %}
    </section>

    <form method="post" action="{{ url_for('logout') }}">
        <input
            type="hidden"
            name="csrf_token"
            value="{{ csrf_token }}"
        >
        <button type="submit">Log out</button>
    </form>
</body>
</html>'''



OFFICER_NAV = """
<nav>
  <a href="/dashboard">Home</a> |
  <a href="/reviews">Attack review</a> |
  <a href="/admissions">Data admission</a> |
  <a href="/deployments">Model deployment approval</a> |
  <a href="/investigate">Investigation &amp; plots</a>
</nav>
<hr>
"""



ATTACK_REVIEWS_PAGE = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GridShield — Attack Review</title></head>
<body>
<h1>GridShield — Attack Review</h1>
<p>Officer: <strong>{{ username }}</strong></p>
""" + OFFICER_NAV + """
<p>Pending attack reviews: {{ reviews|length }}</p>
{% for item in reviews %}
  <article>
    <h3>Event {{ item.event_id }}</h3>
    <p>Attack probability: {{ "%.2f"|format(item.attack_probability) }}</p>
    <p>Route: {{ item.confidence_route }}</p>
    <details><summary>Measurements</summary>
      <pre>{{ item.measurements|tojson(indent=2) }}</pre>
    </details>
    {% for decision in ["confirmed_attack", "not_attack", "unresolved", "pending_review"] %}
      <form method="post" action="{{ url_for('review_event', event_id=item.event_id) }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button name="decision" value="{{ decision }}">{{ decision }}</button>
      </form>
    {% endfor %}
  </article>
{% else %}
  <p>No incidents are awaiting attack verification.</p>
{% endfor %}
</body></html>
"""

DATA_ADMISSIONS_PAGE = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GridShield — Data Admission</title></head>
<body>
<h1>GridShield — Data Admission</h1>
<p>Officer: <strong>{{ username }}</strong></p>
""" + OFFICER_NAV + """
<p>Pending admissions: {{ admissions|length }}</p>
{% for item in admissions %}
  <article>
    <h3>Event {{ item.event_id }}</h3>
    <p>Confirmed attack · Probability {{ "%.2f"|format(item.attack_probability) }}</p>
    <details><summary>Measurements</summary>
      <pre>{{ item.measurements|tojson(indent=2) }}</pre>
    </details>
    {% for decision in ["approved", "rejected"] %}
      <form method="post" action="{{ url_for('admission_event', event_id=item.event_id) }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button name="decision" value="{{ decision }}">{{ decision }}</button>
      </form>
    {% endfor %}
  </article>
{% else %}
  <p>No incidents are awaiting data admission.</p>
{% endfor %}
</body></html>
"""

DEPLOYMENTS_PAGE = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>GridShield — Model Deployment Approval</title></head>
<body>
<h1>GridShield — Model Deployment Approval</h1>
<p>Officer: <strong>{{ username }}</strong></p>
""" + OFFICER_NAV + """
<p>Only candidates with a passing evaluation and a live approval interrupt are listed.
Approval does not activate or replace the current model.</p>
<p>Pending candidates: {{ deployments|length }}</p>
{% for item in deployments %}
  <article>
    <h3>Candidate {{ item.candidate_model_version }}</h3>
    <p>Evaluation: {{ item.evaluation_status }}</p>
    <p>Source event: {{ item.event_id }}</p>
    <p>Accuracy: {{ item.metrics.accuracy if item.metrics and item.metrics.accuracy is defined else 'n/a' }}</p>
    <p>Evaluation report: {{ item.report_path }}</p>
    <form method="post" action="{{ url_for('deployment_decision', candidate_version=item.candidate_model_version) }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <button name="decision" value="approved">Approve candidate (no activation)</button>
      <button name="decision" value="rejected">Reject candidate</button>
    </form>
  </article>
{% else %}
  <p>No evaluated candidates are currently waiting for deployment approval.</p>
{% endfor %}
</body></html>
"""


# Keep the pool/checkpointer alive for the complete Flask process lifetime.
_graph = None
_graph_context = None
_repository = None

def _services():
    global _graph, _graph_context, _repository
    if _graph is None:
        from gridshield.postgres_checkpointer import postgres_checkpointer
        from gridshield.repository import PostgresSampleRepository
        from gridshield.workflow import build_graph
        _graph_context = ExitStack()
        saver = _graph_context.enter_context(postgres_checkpointer())
        _graph = build_graph(checkpointer=saver)
        _repository = PostgresSampleRepository()
    return _graph, _repository


def valid_csrf_token():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("officer_authenticated"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def _event_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", value):
        abort(400, description="Invalid event ID.")
    return value


def _pending_interrupt(graph, event_id, expected_type):
    """Only allow resuming the event's expected, currently paused stage."""
    config = {"configurable": {"thread_id": event_id}}
    snapshot = graph.get_state(config)
    for task in getattr(snapshot, "tasks", ()):
        for item in getattr(task, "interrupts", ()):
            payload = getattr(item, "value", {}) or {}
            if payload.get("event_id") == event_id and payload.get("request_type") == expected_type:
                return config
    abort(409, description="This event has no matching active workflow approval interrupt.")


def _pending_deployment_candidates(graph):
    """Discover only passing reports whose LangGraph thread is paused for approval."""
    import json
    from pathlib import Path

    project_root = Path(__file__).resolve().parent
    report_dir = project_root / "reports"
    candidate_dir = (project_root / "artifacts" / "candidates").resolve()
    if not report_dir.exists():
        return []

    pending = []
    for report_path in sorted(report_dir.glob("evaluation_*.json"), reverse=True):
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            version = report.get("candidate_model_version")
            event_id = report.get("event_id")
            if (report.get("evaluation_status") != "passed" or
                    not isinstance(version, str) or not version or
                    not isinstance(event_id, str) or not event_id):
                continue
            model_raw = report.get("candidate_model_path")
            features_raw = report.get("candidate_feature_columns_path")
            if not model_raw or not features_raw:
                continue
            model_path = Path(model_raw).resolve()
            features_path = Path(features_raw).resolve()
            if (candidate_dir not in model_path.parents or
                    candidate_dir not in features_path.parents or
                    not model_path.is_file() or not features_path.is_file()):
                continue
            try:
                _pending_interrupt(graph, event_id, "model_deployment")
            except Exception:
                continue
            report["report_path"] = str(report_path)
            pending.append(report)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            app.logger.warning("Skipping invalid evaluation report: %s", report_path)
    return pending


def _validated_candidate_report(candidate_version, graph):
    """Resolve a candidate by version and revalidate policy, paths, and paused interrupt."""
    import json
    from pathlib import Path

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", candidate_version or ""):
        abort(400, description="Invalid candidate version.")
    project_root = Path(__file__).resolve().parents[1]
    report_dir = project_root / "reports"
    candidate_dir = (project_root / "artifacts" / "candidates").resolve()
    matches = []
    for report_path in report_dir.glob("evaluation_*.json") if report_dir.exists() else []:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if report.get("candidate_model_version") == candidate_version:
                matches.append((report_path, report))
        except (OSError, ValueError, TypeError):
            continue
    if len(matches) != 1:
        abort(404, description="Candidate report was not found or is ambiguous.")
    report_path, report = matches[0]
    report["report_path"] = str(report_path)
    if report.get("evaluation_status") != "passed":
        abort(409, description="Only candidates that passed evaluation can be approved.")
    event_id = report.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        abort(409, description="Candidate report has no workflow event identity.")
    for key in ("candidate_model_path", "candidate_feature_columns_path"):
        raw = report.get(key)
        if not raw:
            abort(409, description="Candidate artifacts are missing from the report.")
        path = Path(raw).resolve()
        if candidate_dir not in path.parents or not path.is_file():
            abort(409, description="Candidate artifacts are missing or outside the candidate directory.")
    config = _pending_interrupt(graph, event_id, "model_deployment")
    return report, event_id, config


def _numeric_measurement_keys(events):
    keys = set()
    for event in events:
        measurements = event.get("measurements") or {}
        if isinstance(measurements, dict):
            for key, value in measurements.items():
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    keys.add(key)
    return sorted(keys)



INVESTIGATE_PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GridShield Investigation</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body { font-family: Arial, sans-serif; max-width: 1400px;
       margin: 2rem auto; padding: 0 1rem; color: #182230; }
.panel { border: 1px solid #d8dee8; border-radius: 10px;
         padding: 1rem; margin: 1rem 0; }
input { padding: .6rem; margin: .3rem; max-width: 100%; }
button { padding: .65rem 1rem; cursor: pointer; }
.charts { display: grid; grid-template-columns: repeat(auto-fit,
         minmax(340px, 1fr)); gap: 1rem; }
.chart { height: 300px; }
table { border-collapse: collapse; width: 100%; }
th, td { border-bottom: 1px solid #ddd; padding: .55rem;
         text-align: left; }
.error { color: #a32121; }
small { color: #536171; }
</style>
</head>
<body>
<h1>GridShield — Suspicious Event Investigation</h1>
<p>Authenticated officer: <strong>{{ username }}</strong></p>
<p><a href="{{ url_for('dashboard') }}">Return to officer dashboard</a></p>
{% if message %}<p role="status">{{ message }}</p>{% endif %}

<section class="panel">
  <h2>Select event data</h2>
  <form method="get">
    <label>Single event ID
      <input name="event_id" value="{{ single_id }}"
             placeholder="e.g. candidate-human-review-001" size="35">
    </label>
    <p>Or enter inclusive ranges based on the trailing numeric part of event IDs.</p>
    <label>Ranges
      <input name="ranges" value="{{ ranges_text }}"
             placeholder="100-120,130-135" size="35">
    </label>
    <button type="submit">Load and plot</button>
  </form>
  <p><small>With no selection, the page shows recent events strictly between 30% and 70% attack probability. Ranges match the trailing numeric suffix (for example, suffix 001 is in range 1-1) and include events at any confidence. If different event-ID prefixes share a suffix, all matching events are included.</small></p>
  {% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
</section>

<section class="panel">
  <h2>Selected events ({{ events|length }})</h2>
  {% if events %}
  <form method="post" action="{{ url_for('bulk_review_events') }}"
        onsubmit="return confirm('Apply this attack-verification decision to every selected pending event?');">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="hidden" name="decision" id="rangeBulkDecision" value="" disabled>
    <!-- GRIDSHIELD_RANGE_DECISION_CARDS_V1 -->
    <section style="border:1px solid #cbd5e1;border-radius:8px;padding:1rem;margin:.75rem 0;background:#f8fafc">
      <h3 style="margin-top:0">Range decision cards</h3>
      <p><small>Load the desired suffix range using the range box above first. Each card applies its decision only to currently loaded, pending events in its inclusive suffix range. If different event-ID prefixes share a suffix, all loaded matches are included.</small></p>
      <div id="rangeDecisionCards">
        <div class="range-decision-card" style="display:flex;gap:.6rem;align-items:end;flex-wrap:wrap;border:1px solid #d8dee8;border-radius:6px;padding:.75rem;margin:.5rem 0">
          <label>Start suffix<br><input type="number" min="0" class="range-start" placeholder="120" style="width:100px"></label>
          <label>End suffix<br><input type="number" min="0" class="range-end" placeholder="140" style="width:100px"></label>
          <label>Decision<br><select class="range-decision"><option value="confirmed_attack">Confirm as attack</option><option value="not_attack">Not an attack</option><option value="unresolved">Unresolved</option></select></label>
          <button type="button" class="apply-range-decision">Apply range</button>
          <button type="button" class="remove-range-card">Remove card</button>
          <span class="range-result" role="status"></span>
        </div>
      </div>
      <button type="button" id="addRangeDecisionCard">+ Add another range card</button>
    </section>
    <div style="margin:.5rem 0">
      <button type="button" onclick="document.querySelectorAll('.event-select').forEach(x => { if (!x.disabled) x.checked = true; })">Select all pending</button>
      <button type="button" onclick="document.querySelectorAll('.event-select').forEach(x => x.checked = false)">Clear selection</button>
      <button type="submit" name="decision" value="confirmed_attack">Confirm selected as attack</button>
      <button type="submit" name="decision" value="not_attack">Mark selected not attack</button>
      <button type="submit" name="decision" value="unresolved">Mark selected unresolved</button>
    </div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr><th>Select</th><th>Event ID</th><th>Attack probability</th>
        <th>Confidence route</th><th>Review</th><th>Measurements</th></tr></thead>
      <tbody>
      {% for event in events %}
        <tr>
          <td>
            {% if event.status == 'awaiting_human_review' and event.human_review_status == 'pending' %}
              <input class="event-select" type="checkbox" name="event_ids" value="{{ event.event_id }}" aria-label="Select event {{ event.event_id }}">
            {% else %}
              <input class="event-select" type="checkbox" disabled aria-label="Event is not awaiting review">
            {% endif %}
          </td>
          <td>{{ event.event_id }}</td>
          <td>{{ "%.1f"|format(event.attack_probability * 100) }}%</td>
          <td>{{ event.confidence_route }}</td>
          <td>{{ event.human_review_status }}</td>
          <td><details><summary>View values</summary>
            <pre>{{ event.measurements|tojson(indent=2) }}</pre>
          </details></td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    </div>
  </form>
  {% else %}
  <p>No matching events found.</p>
  {% endif %}
</section>

<section class="panel">
  <h2>Attack confidence by event ID</h2>
  <div class="chart"><canvas id="confidenceChart"></canvas></div>
  <p><small>The existing 30% and 70% review boundaries are preserved.</small></p>
</section>

<!-- GRIDSHIELD_FEATURE_EXPLORER_V1 -->
<section class="panel">
  <h2>Feature explorer — all available measurements</h2>
  {% if events %}
  <label for="featureEventSelect"><strong>Event to inspect:</strong></label>
  <select id="featureEventSelect">
    {% for event in events %}<option value="{{ loop.index0 }}">{{ event.event_id }}</option>{% endfor %}
  </select>
  <p id="featureValueSummary"></p>
  <div style="overflow:auto;max-height:440px;border:1px solid #ddd;border-radius:6px">
    <table id="featureValueTable"><thead><tr><th>Feature / measurement</th><th>Value</th></tr></thead><tbody></tbody></table>
  </div>
  <hr>
  <label for="featureMultiSelect"><strong>Choose features to compare across loaded events</strong></label>
  <p><small>Use Ctrl (Windows) or Shift to select multiple features.</small></p>
  <select id="featureMultiSelect" multiple size="10" style="display:block;width:min(100%,560px);margin:.5rem 0">
    {% for key in measurement_keys %}<option value="{{ key }}">{{ key }}</option>{% endfor %}
  </select>
  <button type="button" id="plotSelectedFeatures">Plot selected features</button>
  <div id="selectedFeatureCharts" class="charts" style="margin-top:1rem"></div>
  {% else %}<p>No events loaded. Enter an event ID or range above to load data.</p>{% endif %}
</section>

<script>
const events = {{ events|tojson }};
const ids = events.map(e => e.event_id);
const confidence = events.map(e => Number(e.attack_probability) * 100);

new Chart(document.getElementById("confidenceChart"), {
  type: "line",
  data: {
    labels: ids,
    datasets: [
      {
        label: "Attack probability (%)",
        data: confidence,
        pointRadius: 3,
        tension: 0
      },
      {
        label: "30% review-band lower boundary",
        data: events.map(() => 30),
        pointRadius: 0,
        borderDash: [6, 4],
        borderWidth: 1,
        tension: 0
      },
      {
        label: "70% review-band upper boundary",
        data: events.map(() => 70),
        pointRadius: 0,
        borderDash: [6, 4],
        borderWidth: 1,
        tension: 0
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { title: { display: true, text: "Event ID" } },
      y: {
        min: 0, max: 100,
        title: { display: true, text: "Confidence (%)" }
      }
    },
    plugins: {
      annotation: { annotations: {} }
    }
  }
});

const measurementKeys = {{ measurement_keys|tojson }};
const eventSelect = document.getElementById("featureEventSelect");
const tableBody = document.querySelector("#featureValueTable tbody");
const summary = document.getElementById("featureValueSummary");
const featureSelect = document.getElementById("featureMultiSelect");
const chartsHost = document.getElementById("selectedFeatureCharts");
const featureCharts = [];

function renderEventMeasurements() {
  if (!eventSelect || !tableBody) return;
  const event = events[Number(eventSelect.value)];
  tableBody.replaceChildren();
  if (!event) return;
  const measurements = event.measurements || {};
  const keys = Object.keys(measurements).sort();
  summary.textContent = event.event_id + " — " + keys.length + " stored measurement keys";
  for (const key of keys) {
    const tr = document.createElement("tr");
    const keyCell = document.createElement("td");
    const valueCell = document.createElement("td");
    keyCell.textContent = key;
    const value = measurements[key];
    valueCell.textContent = value === null ? "null" :
      (typeof value === "object" ? JSON.stringify(value) : String(value));
    tr.append(keyCell, valueCell);
    tableBody.appendChild(tr);
  }
}

function renderFeatureCharts() {
  if (!featureSelect || !chartsHost) return;
  while (featureCharts.length) featureCharts.pop().destroy();
  chartsHost.replaceChildren();
  const chosen = Array.from(featureSelect.selectedOptions).map(option => option.value);
  if (!chosen.length) {
    chartsHost.textContent = "Select one or more features to plot.";
    return;
  }
  for (const key of chosen) {
    const panel = document.createElement("div");
    panel.className = "panel";
    const title = document.createElement("h3");
    title.textContent = key;
    const wrap = document.createElement("div");
    wrap.className = "chart";
    const canvas = document.createElement("canvas");
    wrap.appendChild(canvas);
    panel.append(title, wrap);
    chartsHost.appendChild(panel);
    const values = events.map(event => {
      const value = event.measurements ? event.measurements[key] : null;
      return typeof value === "number" && Number.isFinite(value) ? value : null;
    });
    featureCharts.push(new Chart(canvas, {
      type: "line",
      data: { labels: ids, datasets: [{ label: key, data: values,
        pointRadius: 2, spanGaps: false, tension: 0 }] },
      options: { responsive: true, maintainAspectRatio: false,
        scales: { x: { title: { display: true, text: "Event ID" } },
          y: { title: { display: true, text: key } } } }
    }));
  }
}

if (eventSelect) eventSelect.addEventListener("change", renderEventMeasurements);
if (featureSelect) {
  document.getElementById("plotSelectedFeatures").addEventListener("click", renderFeatureCharts);
  renderFeatureCharts();
}
renderEventMeasurements();

// Range decision cards: operate only on loaded, pending rows. Backend CSRF,
// workflow-interrupt validation and audit logging remain the same.
const rangeCardsHost = document.getElementById("rangeDecisionCards");
const bulkForm = rangeCardsHost ? rangeCardsHost.closest("form") : null;
const rangeDecisionInput = document.getElementById("rangeBulkDecision");

function applyRangeDecisionCard(card) {
  const startText = card.querySelector(".range-start").value.trim();
  const endText = card.querySelector(".range-end").value.trim();
  const decision = card.querySelector(".range-decision").value;
  const result = card.querySelector(".range-result");
  const start = Number(startText), end = Number(endText);
  if (!startText || !endText || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start) {
    result.textContent = "Enter a valid inclusive suffix range.";
    return;
  }
  const matching = Array.from(document.querySelectorAll(".event-select")).filter(box => {
    if (box.disabled) return false;
    const suffixMatch = box.value.match(/(\d+)$/);
    if (!suffixMatch) return false;
    const suffix = Number(suffixMatch[1]);
    return Number.isSafeInteger(suffix) && suffix >= start && suffix <= end;
  });
  if (!matching.length) {
    result.textContent = "No pending events in this range are loaded. Load this range at the top first.";
    return;
  }
  const names = matching.map(box => box.value);
  const preview = names.slice(0, 10).join("\n") + (names.length > 10 ? "\n… and " + (names.length - 10) + " more" : "");
  if (!confirm("Apply '" + decision.replaceAll("_", " ") + "' to " + names.length + " pending event(s) in suffix range " + start + "-" + end + "?\n\n" + preview)) return;
  document.querySelectorAll(".event-select").forEach(box => { box.checked = false; });
  matching.forEach(box => { box.checked = true; });
  rangeDecisionInput.value = decision;
  rangeDecisionInput.disabled = false;
  result.textContent = "Submitting " + names.length + " event(s)…";
  bulkForm.requestSubmit();
}

if (rangeCardsHost && bulkForm) {
  rangeCardsHost.addEventListener("click", event => {
    const apply = event.target.closest(".apply-range-decision");
    if (apply) { applyRangeDecisionCard(apply.closest(".range-decision-card")); return; }
    const remove = event.target.closest(".remove-range-card");
    if (remove) {
      const cards = rangeCardsHost.querySelectorAll(".range-decision-card");
      if (cards.length > 1) remove.closest(".range-decision-card").remove();
      else remove.closest(".range-decision-card").querySelector(".range-result").textContent = "At least one card must remain.";
    }
  });
  document.getElementById("addRangeDecisionCard").addEventListener("click", () => {
    const card = rangeCardsHost.querySelector(".range-decision-card").cloneNode(true);
    card.querySelector(".range-start").value = "";
    card.querySelector(".range-end").value = "";
    card.querySelector(".range-decision").value = "confirmed_attack";
    card.querySelector(".range-result").textContent = "";
    rangeCardsHost.appendChild(card);
  });
  // Ordinary manual checkbox submissions use the clicked button's decision.
  bulkForm.addEventListener("submit", event => {
    if (event.submitter && event.submitter.name === "decision") {
      rangeDecisionInput.disabled = true;
    }
  });
}
</script>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("dashboard" if session.get("officer_authenticated") else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("officer_authenticated"):
        return redirect(url_for("dashboard"))
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    error = None
    if request.method == "POST":
        if not valid_csrf_token():
            abort(400, description="Invalid CSRF token.")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        username_ok = hmac.compare_digest(username, officer_username)
        password_ok = check_password_hash(officer_password_hash, password)
        if username_ok and password_ok:
            session.clear()
            session["officer_authenticated"] = True
            session["officer_username"] = officer_username
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
        session["csrf_token"] = secrets.token_urlsafe(32)
    return render_template_string(LOGIN_PAGE, error=error, csrf_token=session["csrf_token"])


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    error = request.args.get("error")
    message = request.args.get("message")
    try:
        _, repository = _services()
        reviews = repository.list_pending_reviews()
        admissions = repository.list_pending_admissions()
        graph, _ = _services()
        deployments = _pending_deployment_candidates(graph)
    except Exception:
        app.logger.exception("Unable to load GridShield officer queues")
        abort(503, description="Approval queues are temporarily unavailable. Check server logs.")
    return render_template_string(DASHBOARD_PAGE, username=session.get("officer_username", ""), csrf_token=session["csrf_token"], reviews=reviews, admissions=admissions, deployments=deployments, error=error, message=message)



@app.route("/reviews", methods=["GET"])
@login_required
def attack_reviews_page():
    _, repository = _services()
    return render_template_string(
        ATTACK_REVIEWS_PAGE,
        username=session.get("officer_username", ""),
        csrf_token=session["csrf_token"],
        reviews=repository.list_pending_reviews(),
    )


@app.route("/admissions", methods=["GET"])
@login_required
def admissions_page():
    _, repository = _services()
    return render_template_string(
        DATA_ADMISSIONS_PAGE,
        username=session.get("officer_username", ""),
        csrf_token=session["csrf_token"],
        admissions=repository.list_pending_admissions(),
    )


@app.route("/deployments", methods=["GET"])
@login_required
def deployments_page():
    graph, _ = _services()
    return render_template_string(
        DEPLOYMENTS_PAGE,
        username=session.get("officer_username", ""),
        csrf_token=session["csrf_token"],
        deployments=_pending_deployment_candidates(graph),
    )



@app.route("/investigate", methods=["GET"])
@login_required
def investigate():
    _, repository = _services()
    single_id = request.args.get("event_id", "").strip()
    ranges_text = request.args.get("ranges", "").strip()
    selected_events = []
    error = None

    try:
        if single_id:
            event = repository.get(_event_id(single_id))
            selected_events = [event] if event else []
        elif ranges_text:
            ranges = []
            for part in ranges_text.split(","):
                match = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", part)
                if not match:
                    raise ValueError("Use ranges like 100-120,130-135.")
                start_id, end_id = map(int, match.groups())
                if end_id < start_id:
                    raise ValueError("End ID must be greater than or equal to start ID.")
                if end_id - start_id > 100000:
                    raise ValueError("Each requested range must span no more than 100001 suffix values.")
                ranges.append((start_id, end_id))
            if len(ranges) > 20:
                raise ValueError("Select at most 20 ranges at a time.")
            seen = set()
            for start_id, end_id in ranges:
                for event in repository.list_events_by_id_range(start_id, end_id):
                    event_id = event["event_id"]
                    if event_id not in seen:
                        selected_events.append(event)
                        seen.add(event_id)
        else:
            # Hide incomplete legacy/smoke-test records in the default view only.
            # Explicit event-ID and range lookups remain available; no DB rows are deleted.
            selected_events = [
                event for event in repository.list_suspicious_events()
                if isinstance(event.get("measurements"), dict)
                and len(event["measurements"]) >= 61
            ]
    except ValueError as exc:
        error = str(exc)

    return render_template_string(
        INVESTIGATE_PAGE,
        measurement_keys=_numeric_measurement_keys(selected_events),
        username=session.get("officer_username", ""),
        csrf_token=session["csrf_token"],
        events=selected_events,
        error=error,
        message=request.args.get("message"),
        single_id=single_id,
        ranges_text=ranges_text,
    )


@app.route("/investigate/review", methods=["POST"])
@login_required
def bulk_review_events():
    if not valid_csrf_token():
        abort(400, description="Invalid CSRF token.")
    decision = request.form.get("decision", "")
    allowed = {"confirmed_attack", "not_attack", "unresolved"}
    if decision not in allowed:
        abort(400, description="Invalid bulk attack-review decision.")

    event_ids = request.form.getlist("event_ids")
    if not event_ids:
        return redirect(url_for("investigate", message="Select at least one pending event first."))
    if len(event_ids) > 500:
        abort(400, description="Select no more than 500 events per bulk decision.")
    event_ids = list(dict.fromkeys(_event_id(value) for value in event_ids))

    graph, repository = _services()
    # Validate every event's workflow interrupt before changing any event.
    configs = {}
    for event_id in event_ids:
        configs[event_id] = _pending_interrupt(graph, event_id, "human_attack_review")

    from langgraph.types import Command
    succeeded = []
    failed = []
    for event_id in event_ids:
        try:
            graph.invoke(
                Command(resume={"decision": decision, "officer_username": session["officer_username"]}),
                config=configs[event_id],
            )
            repository.record_officer_decision(
                event_id,
                stage="attack_review",
                decision=decision,
                officer_username=session["officer_username"],
                thread_id=event_id,
            )
            succeeded.append(event_id)
        except Exception:
            app.logger.exception("Bulk review failed for event %s", event_id)
            failed.append(event_id)

    message = f"Recorded {len(succeeded)} of {len(event_ids)} requested decisions."
    if failed:
        message += f" Failed events: {', '.join(failed[:10])}. Check server logs; review each event before retrying."
    return redirect(url_for("investigate", message=message))

@app.route("/review/<event_id>", methods=["POST"])
@login_required
def review_event(event_id):
    if not valid_csrf_token():
        abort(400, description="Invalid CSRF token.")
    event_id = _event_id(event_id)
    decision = request.form.get("decision", "")
    allowed = {"confirmed_attack", "not_attack", "unresolved", "pending_review"}
    if decision not in allowed:
        abort(400, description="Invalid attack-review decision.")
    graph, repository = _services()
    config = _pending_interrupt(graph, event_id, "human_attack_review")
    from langgraph.types import Command
    # Resume the validated interrupt first. This stage does not perform dataset
    # persistence; write the durable decision/audit immediately afterward.
    graph.invoke(Command(resume={"decision": decision, "officer_username": session["officer_username"]}), config=config)
    repository.record_officer_decision(event_id, stage="attack_review", decision=decision, officer_username=session["officer_username"], thread_id=event_id)
    return redirect(url_for("dashboard", message="Attack review decision recorded."))


@app.route("/admission/<event_id>", methods=["POST"])
@login_required
def admission_event(event_id):
    if not valid_csrf_token():
        abort(400, description="Invalid CSRF token.")
    event_id = _event_id(event_id)
    decision = request.form.get("decision", "")
    if decision not in {"approved", "rejected"}:
        abort(400, description="Invalid data-admission decision.")
    graph, repository = _services()
    config = _pending_interrupt(graph, event_id, "data_admission")
    repository.record_officer_decision(event_id, stage="data_admission", decision=decision, officer_username=session["officer_username"], thread_id=event_id)
    from langgraph.types import Command
    graph.invoke(Command(resume={"decision": decision, "officer_username": session["officer_username"]}), config=config)
    return redirect(url_for("dashboard", message="Data-admission decision recorded."))


@app.route("/deployment/<candidate_version>", methods=["POST"])
@login_required
def deployment_decision(candidate_version):
    if not valid_csrf_token():
        abort(400, description="Invalid CSRF token.")
    decision = request.form.get("decision", "")
    if decision not in {"approved", "rejected"}:
        abort(400, description="Invalid deployment decision.")

    graph, repository = _services()
    report, event_id, config = _validated_candidate_report(candidate_version, graph)

    # Persist the officer decision before resuming the workflow. If the resume
    # fails, the audit record still captures the attempted decision.
    repository.record_model_deployment_decision(
        candidate_version=candidate_version,
        event_id=event_id,
        decision=decision,
        officer_username=session["officer_username"],
        thread_id=event_id,
        evaluation_report_path=report.get("report_path") or str(report.get("evaluation_report_path", "")),
    )
    from langgraph.types import Command
    graph.invoke(
        Command(resume={"decision": decision, "officer_username": session["officer_username"]}),
        config=config,
    )
    message = (
        "Candidate approval recorded. The active model was NOT changed; deployment and rollback remain unimplemented."
        if decision == "approved" else "Candidate rejected. The active model was not changed."
    )
    return redirect(url_for("dashboard", message=message))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not valid_csrf_token():
        abort(400, description="Invalid CSRF token.")
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
