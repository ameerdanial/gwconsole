"""Safe remote config pipeline shared by HAProxy and cloudflared.

validate -> backup -> write in place -> activate (reload/restart) -> health check
and automatic rollback to the backup if activate or the health check fails.
"""
from __future__ import annotations

import difflib
import hashlib
import re
import shlex

from .config import SSHTarget
from .sshpool import NodeError, SSHPool

TS_RE = r"\d{8}-\d{6}"


def sha(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def unified_diff(old: str, new: str, path: str) -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"{path} (current)", tofile=f"{path} (proposed)", n=3))


def diff_stats(diff: str) -> dict:
    add = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    rem = sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))
    return {"added": add, "removed": rem}


async def read_file(pool: SSHPool, t: SSHTarget, path: str) -> str:
    r = await pool.run(t, f"cat {shlex.quote(path)}")
    if not r.ok:
        raise NodeError(f"{t.name}: cannot read {path}: {r.err.strip() or r.out.strip()}")
    return r.out


async def validate(pool: SSHPool, t: SSHTarget, content: str, validate_cmd: str) -> dict:
    """validate_cmd must contain {file}."""
    tmp = await pool.put_temp(t, content)
    q = shlex.quote(tmp)
    r = await pool.run(t, f"{validate_cmd.format(file=q)} 2>&1; rc=$?; rm -f {q}; exit $rc", timeout=60)
    return {"ok": r.ok, "output": r.text}


async def apply(pool: SSHPool, t: SSHTarget, *, cfg_path: str, content: str, base_hash: str | None,
                backup_dir: str, prefix: str, validate_cmd: str, activate_cmd: str, check_cmd: str,
                settle: int, keep: int) -> dict:
    current = await read_file(pool, t, cfg_path)
    if base_hash and sha(current) != base_hash:
        return {"ok": False, "stage": "conflict",
                "output": "The file changed on the server since you loaded it. Reload it, re-apply your edits, then try again."}
    if current == content:
        return {"ok": True, "stage": "noop", "output": "No changes — nothing applied."}

    tmp = await pool.put_temp(t, content)
    Q = shlex.quote
    script = f"""
CFG={Q(cfg_path)}; NEW={Q(tmp)}; BK={Q(backup_dir)}
out=$({validate_cmd.format(file='"$NEW"')} 2>&1); rc=$?
echo "$out"
if [ $rc -ne 0 ]; then rm -f "$NEW"; echo "@@GWC:VALIDATE_FAILED"; exit 10; fi
mkdir -p "$BK" && chmod 700 "$BK" || {{ rm -f "$NEW"; echo "@@GWC:BACKUP_FAILED"; exit 11; }}
B="$BK/{prefix}.$(date +%Y%m%d-%H%M%S)"
cp -p "$CFG" "$B" || {{ rm -f "$NEW"; echo "@@GWC:BACKUP_FAILED"; exit 11; }}
echo "@@GWC:BACKUP=$B"
cat "$NEW" > "$CFG" || {{ rm -f "$NEW"; echo "@@GWC:WRITE_FAILED"; exit 12; }}
rm -f "$NEW"
rollback() {{ cat "$B" > "$CFG"; {activate_cmd} 2>&1; echo "@@GWC:ROLLED_BACK"; exit 13; }}
{activate_cmd} 2>&1 || rollback
sleep {int(settle)}
{check_cmd} >/dev/null 2>&1 || rollback
ls -1t "$BK"/{prefix}.* 2>/dev/null | tail -n +{int(keep) + 1} | xargs -r rm -f
echo "@@GWC:OK"
"""
    r = await pool.run(t, script, timeout=120, critical=True)
    out = r.out + r.err
    backup = None
    m = re.search(r"@@GWC:BACKUP=(\S+)", out)
    if m:
        backup = m.group(1).rsplit("/", 1)[-1]
    stage = "applied" if "@@GWC:OK" in out else (
        "validate" if "VALIDATE_FAILED" in out else
        "rolled_back" if "ROLLED_BACK" in out else
        "backup" if "BACKUP_FAILED" in out else
        "write" if "WRITE_FAILED" in out else "unknown")
    clean = "\n".join(l for l in out.splitlines() if not l.startswith("@@GWC:")).strip()
    return {"ok": stage == "applied", "stage": stage, "backup": backup, "output": clean,
            "diff_stats": diff_stats(unified_diff(current, content, cfg_path))}


async def list_backups(pool: SSHPool, t: SSHTarget, backup_dir: str, prefix: str) -> list[dict]:
    d = shlex.quote(backup_dir)
    r = await pool.run(t, f'for f in $(ls -1t {d}/{prefix}.* 2>/dev/null); do stat -c "%n|%s|%Y" "$f"; done')
    items = []
    for line in r.out.splitlines():
        try:
            path, size, mtime = line.rsplit("|", 2)
        except ValueError:
            continue
        name = path.rsplit("/", 1)[-1]
        if re.fullmatch(re.escape(prefix) + r"\." + TS_RE, name):
            items.append({"name": name, "size": int(size), "mtime": int(mtime)})
    return items


async def read_backup(pool: SSHPool, t: SSHTarget, backup_dir: str, prefix: str, name: str) -> str:
    if not re.fullmatch(re.escape(prefix) + r"\." + TS_RE, name):
        raise ValueError("invalid backup name")
    return await read_file(pool, t, f"{backup_dir.rstrip('/')}/{name}")
