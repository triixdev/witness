#!/usr/bin/env python3
"""witness: receipts for agent claims, and independent re-checks of them.

receipt  -- run a command, record what happened, bind it to the exact files on disk
verify   -- re-run a receipt on another machine/agent and say whether it still holds
redact   -- scrub secrets and personal identifiers from text before it goes to chat
Standard library only. No network calls. Nothing is sent anywhere.
"""
import argparse, hashlib, json, os, re, subprocess, sys, time, uuid

REDACTIONS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*")),
    ("secret-assign", re.compile(r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY)[A-Z0-9_]*)\s*[=:]\s*\S+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("pan", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("aadhaar", re.compile(r"\b[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?91[ -]?)?[6-9][0-9]{9}(?!\d)")),
    ("home-path", re.compile(r"(/Users|/home)/[^/\s]+")),
]

def redact(text):
    """Return (clean_text, sorted list of rule names that fired)."""
    hit = set()
    for name, rx in REDACTIONS:
        def sub(m, name=name):
            hit.add(name)
            if name == "secret-assign":
                return m.group(1) + "=[redacted]"
            if name == "home-path":
                return m.group(1) + "/[user]"
            return "[redacted:%s]" % name
        text = rx.sub(sub, text)
    return text, sorted(hit)

def _files(root):
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-co", "--exclude-standard", "-z"],
                             capture_output=True, check=True).stdout.decode()
        found = [p for p in out.split("\0") if p]
    except Exception:
        found = []
        for d, dirs, fs in os.walk(root):
            dirs[:] = [x for x in dirs if x not in (".git", "node_modules", "__pycache__", ".venv")]
            found += [os.path.relpath(os.path.join(d, f), root) for f in fs]
    # witness's own receipts and bytecode must not change the fingerprint
    return sorted(p for p in found if not p.startswith(".witness/") and not p.endswith(".pyc"))

def fingerprint(root="."):
    """Hash of every non-ignored file's path and content. Changes if any file changes."""
    h = hashlib.sha256()
    for rel in _files(root):
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        h.update(rel.encode() + b"\0")
        with open(p, "rb") as f:
            h.update(hashlib.sha256(f.read()).digest())
    return h.hexdigest()

def run(command, root, timeout):
    t = time.time()
    try:
        p = subprocess.run(command, shell=True, cwd=root, capture_output=True, timeout=timeout)
        code, out = p.returncode, (p.stdout + p.stderr).decode(errors="replace")
    except subprocess.TimeoutExpired:
        code, out = 124, "timed out after %ss" % timeout
    return code, out, round(time.time() - t, 2)

def make_receipt(command, claim, root=".", timeout=300):
    _, hit = redact(command)
    if hit:
        sys.exit("refused: the command itself contains %s. Pass secrets by environment variable, not on the command line." % ", ".join(hit))
    fp = fingerprint(root)
    code, out, secs = run(command, root, timeout)
    tail, _ = redact("\n".join(out.splitlines()[-25:]))
    return {"version": 1, "id": uuid.uuid4().hex[:10], "claim": claim, "command": command,
            "exit_code": code, "seconds": secs, "tree": fp, "output_tail": tail,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

def to_chat(r):
    return ("WITNESS RECEIPT %(id)s\nclaim: %(claim)s\ncommand: %(command)s\nexit: %(exit_code)s in %(seconds)ss\n"
            "tree: %(tree)s\n--- last output (redacted) ---\n%(output_tail)s\n--- end ---" % r)

def verify_receipt(r, root=".", timeout=300):
    """Return (verdict, reasons). Verdicts: HOLDS, STALE, FALSE."""
    now = fingerprint(root)
    if now != r["tree"]:
        return "STALE", ["files here differ from the files the receipt was taken on (tree %s vs %s)" % (now[:12], r["tree"][:12])]
    code, out, _ = run(r["command"], root, timeout)
    if code != r["exit_code"]:
        return "FALSE", ["exit code was %s on the receipt, %s on re-run" % (r["exit_code"], code)]
    if r["exit_code"] != 0:
        return "HOLDS", ["receipt records a failure and the failure reproduced"]
    return "HOLDS", ["same files, same command, same exit code (0)"]

def _parse_chat(text):
    g = lambda k: re.search(r"^%s: (.*)$" % k, text, re.M).group(1)
    ex = re.match(r"(\d+) in ([\d.]+)s", g("exit"))
    return {"id": re.search(r"RECEIPT (\w+)", text).group(1), "claim": g("claim"), "command": g("command"),
            "exit_code": int(ex.group(1)), "seconds": float(ex.group(2)), "tree": g("tree")}

def main(argv=None):
    ap = argparse.ArgumentParser(prog="witness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("receipt"); a.add_argument("--claim", required=True); a.add_argument("--root", default=".")
    a.add_argument("--timeout", type=int, default=300); a.add_argument("--out"); a.add_argument("command", nargs=argparse.REMAINDER)
    b = sub.add_parser("verify"); b.add_argument("receipt", help="receipt .json file, or - to read a chat receipt from stdin")
    b.add_argument("--root", default="."); b.add_argument("--timeout", type=int, default=300)
    sub.add_parser("redact")
    args = ap.parse_args(argv)
    if args.cmd == "receipt":
        cmd = " ".join(args.command[1:] if args.command[:1] == ["--"] else args.command)
        if not cmd: sys.exit("give a command after --")
        r = make_receipt(cmd, args.claim, args.root, args.timeout)
        out = args.out or os.path.join(args.root, ".witness", r["id"] + ".json")
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w") as f: json.dump(r, f, indent=2)
        print(to_chat(r)); return 0
    if args.cmd == "verify":
        r = _parse_chat(sys.stdin.read()) if args.receipt == "-" else json.load(open(args.receipt))
        verdict, why = verify_receipt(r, args.root, args.timeout)
        print("WITNESS VERDICT %s: %s\n%s" % (r["id"], verdict, "\n".join("  " + x for x in why)))
        return 0 if verdict == "HOLDS" else 1
    clean, hit = redact(sys.stdin.read()); sys.stdout.write(clean)
    if hit: sys.stderr.write("redacted: %s\n" % ", ".join(hit))
    return 0

if __name__ == "__main__":
    sys.exit(main())
