import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path

import requests
from flask import Flask, request, jsonify

from validator import (
    check_http_redirect, check_https_root, check_https_api, check_cert,
    check_ssh_connect, check_user_exists, check_user_sudo,
    check_sshd_root_login, check_sshd_password_auth, check_ufw,
    check_nginx_active, normalize_key_path, POINTS,
)

app = Flask(__name__)

DEFAULT_KEY = Path(__file__).parent / "HNGStage0"

# Ensure the SSH private key has correct permissions at startup
if DEFAULT_KEY.exists():
    try:
        import stat
        DEFAULT_KEY.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except Exception:
        pass
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")

# ---------------------------------------------------------------------------
# Track registry
# Each entry maps a slash command to a human label and a grader function.
# To add a new track/stage: register a new slash command in Slack pointing to
# /submit, add an entry here, and implement the grader function below.
# ---------------------------------------------------------------------------
TRACK_REGISTRY = {
    "devops-stage0": {"label": "DevOps — Stage 0", "grader": "devops_stage0"},
    # "backend-stage0": {"label": "Backend — Stage 0", "grader": "backend_stage0"},
}


# ---------------------------------------------------------------------------
# Graders
# ---------------------------------------------------------------------------

def devops_stage0(username, domain):
    """Full DevOps Stage 0 check suite."""
    return _run_ssh_checks(username, domain)


def _run_ssh_checks(username, domain):
    results = []
    results.append(check_http_redirect(domain))
    results.append(check_https_root(domain, username))
    results.append(check_https_api(domain, username))
    results.append(check_cert(domain))

    raw_key = str(DEFAULT_KEY) if DEFAULT_KEY.exists() else None
    ssh_key_path = normalize_key_path(raw_key) if raw_key else None
    results.append(check_ssh_connect(domain, "hngdevops", ssh_key_path))
    results.append(check_user_exists(domain, "hngdevops", ssh_key_path))
    results.append(check_user_sudo(domain, "hngdevops", ssh_key_path))
    results.append(check_sshd_root_login(domain, "hngdevops", ssh_key_path))
    results.append(check_sshd_password_auth(domain, "hngdevops", ssh_key_path))
    results.append(check_ufw(domain, "hngdevops", ssh_key_path))
    results.append(check_nginx_active(domain, "hngdevops", ssh_key_path))

    for r in results:
        r.points = POINTS.get(r.name, 0) if r.ok else 0

    earned = sum(r.points for r in results)
    total = sum(POINTS.get(r.name, 0) for r in results)
    return results, earned, total


# ---------------------------------------------------------------------------
# Slack helpers
# ---------------------------------------------------------------------------

def _verify_slack_signature(req):
    if not SLACK_SIGNING_SECRET:
        return True
    ts = req.headers.get("X-Slack-Request-Timestamp", "")
    if not ts or abs(time.time() - int(ts)) > 300:
        return False
    sig_base = f"v0:{ts}:{req.get_data(as_text=True)}"
    expected = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), sig_base.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, req.headers.get("X-Slack-Signature", ""))


def _slack_api(method, payload):
    return requests.post(
        f"https://slack.com/api/{method}",
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        json=payload,
        timeout=10,
    )


def _submission_modal(track_key, channel_id):
    track = TRACK_REGISTRY[track_key]
    return {
        "type": "modal",
        "callback_id": "grade_submission",
        "private_metadata": json.dumps({"track_key": track_key, "channel_id": channel_id}),
        "title": {"type": "plain_text", "text": "Submit for Grading"},
        "submit": {"type": "plain_text", "text": "Grade"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f":pencil: *Track:* {track['label']}"},
            },
            {"type": "divider"},
            {
                "type": "input",
                "block_id": "username",
                "label": {"type": "plain_text", "text": "HNG Username"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "value",
                    "placeholder": {"type": "plain_text", "text": "e.g. johndoe"},
                },
            },
            {
                "type": "input",
                "block_id": "domain",
                "label": {"type": "plain_text", "text": "Domain / IP"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "value",
                    "placeholder": {"type": "plain_text", "text": "e.g. johndoe.example.com"},
                },
            },
        ],
    }


def _results_blocks(track_label, username, domain, results, earned, total):
    pct = int(earned / total * 100) if total else 0
    lines = []
    for r in results:
        icon = ":white_check_mark:" if r.ok else ":x:"
        pts = f"+{r.points}" if r.ok else f"0/{POINTS.get(r.name, 0)}"
        lines.append(f"{icon}  *{r.name}* ({pts} pts) — {r.detail}")

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"HNGI14 {track_label} — {username}"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Domain:* `{domain}`\n*Score:* `{earned}/{total}` ({pct}%)",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(lines)},
        },
    ]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return jsonify({"service": "HNGI14 Grader", "status": "running",
                    "tracks": list(TRACK_REGISTRY.keys())})


@app.route("/validate", methods=["GET", "POST"])
def validate():
    data = request.get_json(silent=True) or request.args
    username = data.get("username")
    domain = data.get("domain")
    if not username or not domain:
        return jsonify({"error": "username and domain are required"}), 400

    ssh_host = data.get("ssh_host") or domain
    ssh_user = data.get("ssh_user", "hngdevops")
    skip_ssh = str(data.get("skip_ssh", "false")).lower() in ("true", "1", "yes")

    raw_key = str(DEFAULT_KEY) if DEFAULT_KEY.exists() else None
    ssh_key_path = normalize_key_path(raw_key) if raw_key else None

    results = []
    results.append(check_http_redirect(domain))
    results.append(check_https_root(domain, username))
    results.append(check_https_api(domain, username))
    results.append(check_cert(domain))
    if not skip_ssh:
        results.append(check_ssh_connect(ssh_host, ssh_user, ssh_key_path))
        results.append(check_user_exists(ssh_host, ssh_user, ssh_key_path))
        results.append(check_user_sudo(ssh_host, ssh_user, ssh_key_path))
        results.append(check_sshd_root_login(ssh_host, ssh_user, ssh_key_path))
        results.append(check_sshd_password_auth(ssh_host, ssh_user, ssh_key_path))
        results.append(check_ufw(ssh_host, ssh_user, ssh_key_path))
        results.append(check_nginx_active(ssh_host, ssh_user, ssh_key_path))

    for r in results:
        r.points = POINTS.get(r.name, 0) if r.ok else 0
    earned = sum(r.points for r in results)
    total = sum(POINTS.get(r.name, 0) for r in results)

    return jsonify({
        "submission": {"username": username, "domain": domain},
        "score": f"{earned}/{total}",
        "results": [{"name": r.name, "ok": r.ok, "points": r.points, "detail": r.detail}
                    for r in results],
    })


@app.route("/submit", methods=["POST"])
def slack_submit():
    """
    Single Slack slash command endpoint.
    Each command registered in Slack (e.g. /submit-devops, /submit-backend)
    all point here. The command name tells us the track.
    e.g. /submit-devops  → track_key = "devops-stage0"
         /submit-backend → track_key = "backend-stage0"
    """
    if not _verify_slack_signature(request):
        return jsonify({"error": "invalid signature"}), 401

    command = request.form.get("command", "").lstrip("/")   # e.g. "submitDevOpsStage0"
    trigger_id = request.form.get("trigger_id")
    channel_id = request.form.get("channel_id", "")

    # Map command name → registry key
    command_map = {
        "submitdevopsstage0": "devops-stage0",
        # "submitbackendstage0": "backend-stage0",
    }
    track_key = command_map.get(command.lower())

    if not track_key or track_key not in TRACK_REGISTRY:
        return jsonify({
            "response_type": "ephemeral",
            "text": f":warning: Unknown command `/{command}`.",
        })

    _slack_api("views.open", {
        "trigger_id": trigger_id,
        "view": _submission_modal(track_key, channel_id),
    })
    return "", 200


@app.route("/interact", methods=["POST"])
def slack_interact():
    """Handles modal form submissions."""
    if not _verify_slack_signature(request):
        return jsonify({"error": "invalid signature"}), 401

    payload = json.loads(request.form.get("payload", "{}"))
    if payload.get("type") != "view_submission":
        return "", 200
    if payload.get("view", {}).get("callback_id") != "grade_submission":
        return "", 200

    meta = json.loads(payload["view"].get("private_metadata", "{}"))
    track_key = meta.get("track_key", "devops-stage0")
    channel_id = meta.get("channel_id", "")
    user_id = payload["user"]["id"]

    values = payload["view"]["state"]["values"]
    username = values["username"]["value"]["value"].strip()
    domain = values["domain"]["value"]["value"].strip()

    track = TRACK_REGISTRY[track_key]
    grader_fn = globals()[track["grader"]]

    def _grade():
        try:
            results, earned, total = grader_fn(username, domain)
            blocks = _results_blocks(track["label"], username, domain, results, earned, total)
            _slack_api("chat.postEphemeral", {
                "channel": channel_id,
                "user": user_id,
                "blocks": blocks,
            })
        except Exception as exc:
            _slack_api("chat.postEphemeral", {
                "channel": channel_id,
                "user": user_id,
                "text": f":warning: Grading failed for *{username}*: {exc}",
            })

    threading.Thread(target=_grade, daemon=True).start()

    return jsonify({
        "response_action": "update",
        "view": {
            "type": "modal",
            "title": {"type": "plain_text", "text": "Grading..."},
            "blocks": [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":hourglass_flowing_sand: Grading *{username}* on `{domain}`...\nYour results will appear shortly.",
                },
            }],
        },
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
