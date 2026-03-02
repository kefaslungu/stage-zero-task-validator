# HNGI14 Stage 0 — DevOps Task Validator

Validates a submitted Linux server against all Stage 0 requirements: HTTP→HTTPS redirect, Nginx endpoints, SSL certificate, SSH hardening, UFW firewall, and user configuration.

## Requirements

- Python 3.8+
- SSH access to the target server (key-based)

## Usage

```bash
python validator.py \
  --username <hng-username> \
  --domain <your-domain.com> \
  --ssh-private-key-path <path-to-private-key>
```

### Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--username` | Yes | — | Your registered HNG username (case-sensitive) |
| `--domain` | Yes | — | Your submitted domain (e.g. `yourdomain.com`) |
| `--ssh-user` | No | `hngdevops` | SSH user to connect as |
| `--ssh-host` | No | Same as `--domain` | SSH host if different from domain |
| `--ssh-private-key-path` | No | Default SSH key | Path to your private key |
| `--skip-ssh` | No | `false` | Skip all SSH-based checks |

### Examples

```bash
# Full validation
python validator.py \
  --username johndoe \
  --domain johndoe.example.com \
  --ssh-private-key-path ~/.ssh/id_ed25519

# HTTP/SSL checks only (no SSH)
python validator.py \
  --username johndoe \
  --domain johndoe.example.com \
  --skip-ssh
```

## Scoring

Each check awards points on pass. **Total: 10 points.** Core deliverables are worth more; simple prerequisite checks are worth less.

| Check | Points | Description |
|-------|--------|-------------|
| `https_root` | 1.5 | `GET /` returns `200` with username visible in HTML |
| `https_api` | 1.5 | `GET /api` returns `200`, `application/json`, and exact JSON payload |
| `http_redirect` | 1 | HTTP → HTTPS returns `301` with correct `Location` header |
| `ssl_cert` | 1 | Valid Let's Encrypt certificate on port 443 |
| `ssh_connect` | 1 | Key-based SSH login as `hngdevops` succeeds |
| `ssh_root_login_disabled` | 1 | `PermitRootLogin no` in sshd effective config |
| `ssh_password_auth_disabled` | 1 | `PasswordAuthentication no` in sshd effective config |
| `ssh_user_exists` | 0.5 | `hngdevops` user exists on the server |
| `ssh_user_sudo` | 0.5 | `hngdevops` is in `sudo` or `wheel` group |
| `ufw_ports` | 0.5 | UFW active with only ports 22, 80, 443 allowed |
| `nginx_active` | 0.5 | Nginx service is running |

> **Note:** The `sshd -T` and `ufw status` checks run via `sudo -n` (non-interactive), which implicitly verifies that passwordless sudo is configured for `/usr/sbin/sshd` and `/usr/sbin/ufw`.

## Output

JSON report printed to stdout with per-check points and total score. Exit code `0` for perfect score, `2` otherwise.

```json
{
  "submission": {
    "username": "johndoe",
    "domain": "johndoe.example.com"
  },
  "score": "10/10",
  "results": [
    { "name": "http_redirect", "ok": true, "points": 1, "detail": "status=301, location=https://johndoe.example.com/" },
    { "name": "https_root", "ok": true, "points": 1.5, "detail": "status=200, username_present=True" }
  ]
}
```
