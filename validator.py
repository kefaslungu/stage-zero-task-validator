import argparse
import json
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from typing import Optional, Tuple


@dataclass
class ValidationResult:
    name: str
    ok: bool
    detail: str
    points: int = 0


REQUIRED_USER = "hngdevops"
REQUIRED_PORTS = {22, 80, 443}

POINTS = {
    "http_redirect": 1,
    "https_root": 1.5,
    "https_api": 1.5,
    "ssl_cert": 1,
    "ssh_connect": 1,
    "ssh_user_exists": 0.5,
    "ssh_user_sudo": 0.5,
    "ssh_root_login_disabled": 1,
    "ssh_password_auth_disabled": 1,
    "ufw_ports": 0.5,
    "nginx_active": 0.5,
}


def extract_visible_text(html: str) -> str:
    import re
    html = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    return " ".join(text.split())


def http_request(host: str, path: str, use_https: bool) -> Tuple[int, dict, bytes]:
    if use_https:
        connection = HTTPSConnection(host, timeout=10, context=ssl.create_default_context())
    else:
        connection = HTTPConnection(host, timeout=10)
    connection.request("GET", path, headers={"User-Agent": "hng-validator/1.0"})
    response = connection.getresponse()
    status = response.status
    headers = {k.lower(): v for k, v in response.getheaders()}
    body = response.read()
    connection.close()
    return status, headers, body


def check_http_redirect(domain: str) -> ValidationResult:
    try:
        status, headers, _ = http_request(domain, "/", use_https=False)
        location = headers.get("location", "")
        ok = status == 301 and location.lower().startswith("https://")
        detail = f"status={status}, location={location or 'missing'}"
        return ValidationResult("http_redirect", ok, detail)
    except Exception as exc:
        return ValidationResult("http_redirect", False, f"request failed: {exc}")


def check_https_root(domain: str, username: str) -> ValidationResult:
    try:
        status, _, body = http_request(domain, "/", use_https=True)
        html = body.decode("utf-8", errors="replace")
        text = extract_visible_text(html)
        ok = status == 200 and f" {username} " in f" {text} "
        detail = f"status={status}, username_present={ok}"
        return ValidationResult("https_root", ok, detail)
    except Exception as exc:
        return ValidationResult("https_root", False, f"request failed: {exc}")


def check_https_api(domain: str, username: str) -> ValidationResult:
    try:
        status, headers, body = http_request(domain, "/api", use_https=True)
        content_type = headers.get("content-type", "")
        ok_status = status == 200
        ok_type = "application/json" in content_type.lower()
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as exc:
            return ValidationResult("https_api", False, f"invalid json: {exc}")
        ok_payload = payload == {
            "message": "HNGI14 Stage 0",
            "track": "DevOps",
            "username": username,
        }
        ok = ok_status and ok_type and ok_payload
        detail = f"status={status}, content_type={content_type}, payload_match={ok_payload}"
        return ValidationResult("https_api", ok, detail)
    except Exception as exc:
        return ValidationResult("https_api", False, f"request failed: {exc}")


def check_cert(domain: str) -> ValidationResult:
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(10)
            sock.connect((domain, 443))
            cert = sock.getpeercert()
        issuer_parts = []
        for part in cert.get("issuer", []):
            for item in part:
                if len(item) == 2:
                    issuer_parts.append("=".join(item))
        issuer = " ".join(issuer_parts)
        ok = "Let's Encrypt" in issuer
        detail = f"issuer={issuer or 'unknown'}"
        return ValidationResult("ssl_cert", ok, detail)
    except Exception as exc:
        return ValidationResult("ssl_cert", False, f"cert check failed: {exc}")


def normalize_key_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    key_path = Path(path).expanduser()
    if not key_path.exists():
        raise FileNotFoundError(f"ssh private key not found: {key_path}")
    return str(key_path)


def run_ssh_command(host: str, user: str, key_path: Optional[str], command: str) -> Tuple[int, str, str]:
    base = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=10",
    ]
    if key_path:
        base.extend(["-i", key_path])
    base.append(f"{user}@{host}")
    base.append(command)
    result = subprocess.run(base, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def check_ssh_connect(host: str, user: str, key_path: Optional[str]) -> ValidationResult:
    rc, stdout, stderr = run_ssh_command(host, user, key_path, "echo ok")
    ok = rc == 0
    detail = stderr or stdout or f"rc={rc}"
    return ValidationResult("ssh_connect", ok, detail)


def check_user_exists(host: str, user: str, key_path: Optional[str]) -> ValidationResult:
    rc, stdout, stderr = run_ssh_command(host, user, key_path, f"id -u {REQUIRED_USER}")
    ok = rc == 0 and stdout.isdigit()
    detail = stderr or stdout or f"rc={rc}"
    return ValidationResult("ssh_user_exists", ok, detail)


def check_user_sudo(host: str, user: str, key_path: Optional[str]) -> ValidationResult:
    rc, stdout, stderr = run_ssh_command(host, user, key_path, f"id -nG {REQUIRED_USER}")
    groups = set(stdout.split())
    ok = rc == 0 and (("sudo" in groups) or ("wheel" in groups))
    detail = f"groups={sorted(groups)}" if stdout else (stderr or f"rc={rc}")
    return ValidationResult("ssh_user_sudo", ok, detail)


def fetch_sshd_effective_config(host: str, user: str, key_path: Optional[str]) -> Tuple[bool, str]:
    rc, stdout, _ = run_ssh_command(host, user, key_path, "sudo -n /usr/sbin/sshd -T 2>/dev/null")
    if rc == 0 and stdout:
        return True, stdout
    return False, ""


def check_sshd_root_login(host: str, user: str, key_path: Optional[str]) -> ValidationResult:
    ok, output = fetch_sshd_effective_config(host, user, key_path)
    if not ok:
        return ValidationResult("ssh_root_login_disabled", False, "unable to read sshd config")
    permit = ""
    for line in output.splitlines():
        tokens = line.strip().split()
        if not tokens:
            continue
        if tokens[0].lower() == "permitrootlogin" and len(tokens) > 1:
            permit = tokens[1].strip()
            break
    ok_setting = permit.lower() == "no"
    detail = f"permitrootlogin={permit or 'missing'}"
    return ValidationResult("ssh_root_login_disabled", ok_setting, detail)


def check_sshd_password_auth(host: str, user: str, key_path: Optional[str]) -> ValidationResult:
    ok, output = fetch_sshd_effective_config(host, user, key_path)
    if not ok:
        return ValidationResult("ssh_password_auth_disabled", False, "unable to read sshd config")
    setting = ""
    for line in output.splitlines():
        tokens = line.strip().split()
        if not tokens:
            continue
        if tokens[0].lower() == "passwordauthentication" and len(tokens) > 1:
            setting = tokens[1].strip()
            break
    ok_setting = setting.lower() == "no"
    detail = f"passwordauthentication={setting or 'missing'}"
    return ValidationResult("ssh_password_auth_disabled", ok_setting, detail)


def parse_ufw_allowed_ports(output: str) -> Tuple[bool, set]:
    if "Status: active" not in output:
        return False, set()
    allowed_ports = set()
    profile_map = {
        "Nginx Full": {80, 443},
        "Nginx HTTP": {80},
        "Nginx HTTPS": {443},
        "OpenSSH": {22},
    }
    for line in output.splitlines():
        if "ALLOW" not in line:
            continue
        if line.endswith("(v6)"):
            line = line.replace("(v6)", "").strip()
        rule = line.split("ALLOW", 1)[0].strip()
        if rule in profile_map:
            allowed_ports.update(profile_map[rule])
            continue
        token = rule.split()[0]
        if token.isdigit():
            allowed_ports.add(int(token))
            continue
        if "/" in token:
            port_part = token.split("/", 1)[0]
            if port_part.isdigit():
                allowed_ports.add(int(port_part))
    return True, allowed_ports


def check_ufw(host: str, user: str, key_path: Optional[str]) -> ValidationResult:
    rc, stdout, stderr = run_ssh_command(host, user, key_path, "sudo -n /usr/sbin/ufw status")
    if rc != 0:
        return ValidationResult("ufw_ports", False, stderr or f"rc={rc}")
    active, allowed = parse_ufw_allowed_ports(stdout)
    ok = active and allowed.issuperset(REQUIRED_PORTS) and allowed.issubset(REQUIRED_PORTS)
    detail = f"active={active}, allowed_ports={sorted(allowed)}" if stdout else (stderr or f"rc={rc}")
    return ValidationResult("ufw_ports", ok, detail)


def check_nginx_active(host: str, user: str, key_path: Optional[str]) -> ValidationResult:
    rc, stdout, stderr = run_ssh_command(host, user, key_path, "systemctl is-active nginx")
    ok = rc == 0 and stdout.strip() == "active"
    detail = stdout or stderr or f"rc={rc}"
    return ValidationResult("nginx_active", ok, detail)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate HNGI14 Stage 0 DevOps submission.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--ssh-user", default="hngdevops")
    parser.add_argument("--ssh-host", required=False)
    parser.add_argument("--ssh-private-key-path", required=False)
    parser.add_argument("--skip-ssh", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = []

    results.append(check_http_redirect(args.domain))
    results.append(check_https_root(args.domain, args.username))
    results.append(check_https_api(args.domain, args.username))
    results.append(check_cert(args.domain))

    if not args.skip_ssh:
        ssh_host = args.ssh_host or args.domain
        default_key = Path(__file__).parent / "HNGStage0"
        raw_key = args.ssh_private_key_path or (str(default_key) if default_key.exists() else None)
        ssh_key_path = normalize_key_path(raw_key) if raw_key else None
        results.append(check_ssh_connect(ssh_host, args.ssh_user, ssh_key_path))
        results.append(check_user_exists(ssh_host, args.ssh_user, ssh_key_path))
        results.append(check_user_sudo(ssh_host, args.ssh_user, ssh_key_path))
        results.append(check_sshd_root_login(ssh_host, args.ssh_user, ssh_key_path))
        results.append(check_sshd_password_auth(ssh_host, args.ssh_user, ssh_key_path))
        results.append(check_ufw(ssh_host, args.ssh_user, ssh_key_path))
        results.append(check_nginx_active(ssh_host, args.ssh_user, ssh_key_path))

    for r in results:
        r.points = POINTS.get(r.name, 0) if r.ok else 0

    earned = sum(r.points for r in results)
    total = sum(POINTS.get(r.name, 0) for r in results)

    print(json.dumps(
        {
            "submission": {
                "username": args.username,
                "domain": args.domain,
            },
            "score": f"{earned}/{total}",
            "results": [
                {"name": r.name, "ok": r.ok, "points": r.points, "detail": r.detail}
                for r in results
            ],
        },
        indent=2,
        sort_keys=True,
    ))

    return 0 if earned == total else 2


if __name__ == "__main__":
    sys.exit(main())
