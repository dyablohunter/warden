"""Guardrails for anything the LLM (or an LLM-authored routine/trigger) can execute.

- check_command(): denylist that applies in every autonomy mode.
- is_read_only(): conservative classifier used for observe/contain modes, collectors and command triggers.
- read/write path policy and mandatory config validators for write_file.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
from dataclasses import dataclass


@dataclass
class Verdict:
    allowed: bool
    reason: str = ""


_SEP = r"(?:\s|$|;|&|\|)"
_SYS_DIRS = r"(?:/|/\*|/(?:bin|boot|dev|etc|lib|lib32|lib64|opt|proc|root|sbin|srv|sys|usr|var|home)/?\*?)"
_READ_VERBS = r"\b(?:cat|tac|less|more|head|tail|base64|xxd|od|hexdump|strings|cp|scp|rsync|nc|ncat|socat|curl|wget|grep|egrep|zgrep|awk|gawk|sed|python3?|perl|ruby|tee|dd|install|mail|sendmail)\b[^|;&]*"
_SECRETS = (
    r"(?:warden\.env\b|/etc/g?shadow-?(?:\s|$|;|&|\||'|\")|/etc/ssh/ssh_host_\w+_key(?!\.pub)\b|\bid_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub)\b"
    r"|/etc/letsencrypt/(?:live|archive)/\S*privkey|/etc/ssl/private/\S+|\.pem\b(?=[^|;&]*key)"
    r"|(?:^|[\s/'\"=])\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?(?=$|[\s;&|'\"]))"
)

DENY: list[tuple[str, str]] = [
    (r"\brm\s+(?:-\S+\s+)*-\S*[rR]\S*\s+(?:-\S+\s+)*" + _SYS_DIRS + _SEP, "recursive delete of a system directory"),
    (r"--no-preserve-root", "--no-preserve-root"),
    (r"\bmkfs(?:\.\w+)?\b|\bmke2fs\b|\bmkswap\s+/dev/", "formatting a filesystem"),
    (r"\b(?:wipefs|blkdiscard)\b|\bsgdisk\s+(?:-Z|--zap)|\bfdisk\b|\bparted\b[^|;&]*\b(?:rm|mklabel|mkpart)\b", "partitioning / wiping disks"),
    (r"\bdd\b[^|;&]*\bof=/dev/(?!null\b|stdout\b|stderr\b)", "raw write to a device"),
    (r">\s*/dev/(?:sd|nvme|vd|xvd|hd|mmcblk|md|dm-|mapper/)", "overwriting a block device"),
    (r"\bshred\b[^|;&]*/dev/", "shredding a device"),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
    (r"\b(?:curl|wget|fetch)\b[^;&]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:ba|z|da|k|c|tc|fi)?sh\b", "piping a download into a shell"),
    (r"\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|perl|ruby|node|php)\b", "piping a download into an interpreter"),
    (r"\b(?:ba|z|da)?sh\s+-c\s+[\"']?\$\((?:curl|wget)", "executing downloaded code"),
    (r"\bnft\s+(?:-\S+\s+)*flush\s+ruleset\b", "flushing the whole nftables ruleset"),
    (r"\bnft\s+(?:-\S+\s+)*(?:delete|flush|destroy)\s+table\s+(?:inet\s+)?warden\b", "removing Warden's firewall table"),
    (r"\b(?:ip6?tables)(?:-legacy|-nft)?\s+(?:-t\s+\w+\s+)?(?:-F|--flush)\s*(?:$|;|&|\|)", "flushing all iptables rules"),
    (r"\b(?:ip6?tables)(?:-legacy|-nft)?\s+(?:-t\s+\w+\s+)?(?:-P|--policy)\s+INPUT\s+DROP", "default-drop INPUT policy (lockout risk)"),
    (r"\bufw\s+(?:--force\s+)?(?:disable|reset)\b", "disabling/resetting the firewall"),
    (r"\bufw\s+default\s+deny\s+incoming\b(?![^;&|]*allow)", "ufw default deny without an allow (verify SSH is allowed first, in a separate step)"),
    (
        r"\bsystemctl\s+(?:-\S+\s+)*(?:stop|disable|mask|kill)\s+(?:-\S+\s+)*(?:\S+\s+)*(?:ssh|sshd|ssh\.service|sshd\.service|ssh\.socket|warden|warden\.service|systemd-journald\S*|dbus\S*)(?:\s|$|;|&|\|)",
        "stopping SSH, journald, dbus or Warden itself",
    ),
    (r"\bservice\s+(?:ssh|sshd|warden)\s+stop\b", "stopping SSH or Warden"),
    (r"\b(?:pkill|killall)\s+(?:-\S+\s+)*(?:sshd|systemd|warden|python3?|journald|dbus-daemon)\b", "killing core processes"),
    (r"\bkill\s+(?:-\S+\s+)*1\s*(?:$|;|&|\|)", "killing PID 1"),
    (
        r"\b(?:apt|apt-get|aptitude)\b[^;&|]*\b(?:remove|purge|autoremove)\b[^;&|]*\b(?:openssh-server|systemd|sudo|sudo-rs|nftables|python3|libc6|apt|dpkg|linux-image-[\w.-]+|coreutils|bash|login|passwd)(?![\w.-])",
        "removing a critical package",
    ),
    (r"\bdpkg\s+(?:-\S+\s+)*(?:-r|-P|--remove|--purge)\b[^;&|]*\b(?:openssh-server|systemd|sudo|python3|libc6|apt|dpkg|bash)(?![\w.-])", "removing a critical package"),
    (r"\b(?:userdel|deluser)\s+(?:-\S+\s+)*root\b", "deleting root"),
    (r"\bpasswd\s+(?:-\S+\s+)*(?:-d|--delete)\b", "removing a password"),
    (r"\busermod\s+(?:-\S+\s+)*(?:-L|--lock|-e\s*\S+|--expiredate)\s+(?:-\S+\s+)*root\b", "locking root"),
    (r"\b(?:chmod|chown|chgrp)\s+(?:-\S+\s+)*(?:-R|--recursive)\b[^;&|]*\s" + _SYS_DIRS + _SEP, "recursive permission change on a system directory"),
    (r"\bchmod\s+(?:-\S+\s+)*[0-7]*[0-7]{2}[2367]\s+/etc/(?:passwd|shadow|sudoers)", "making auth files world-writable"),
    (r"\bcrontab\s+(?:-u\s+\S+\s+)?-r\b", "wiping a crontab"),
    (r"\becho\s+[a-z]\s*>\s*/proc/sysrq-trigger", "sysrq trigger"),
    (r">\s*/etc/(?:passwd|shadow|group|sudoers)(?:\s|$)", "truncating an auth file"),
    (r"\bhistory\s+-c\b|>\s*/var/log/(?:auth|syslog|wtmp|btmp|lastlog)|\bjournalctl\s+(?:-\S+\s+)*--rotate[^;&|]*--vacuum-time=1s", "destroying audit logs"),
    (_READ_VERBS + _SECRETS, "reading secrets (credentials/private keys must never be sent to the LLM)"),
    (r"(?:^|[;&|]\s*)(?:source|\.)\s+\S*warden\.env", "reading Warden's secrets"),
]
REBOOT_BINS = {"shutdown", "poweroff", "halt", "reboot", "kexec"}
REBOOT_SYSTEMCTL = {"reboot", "poweroff", "halt", "kexec", "soft-reboot", "emergency", "rescue"}
_SHELLS = {"bash", "sh", "dash", "zsh", "ksh"}

_DENY_RE = [(re.compile(p), r) for p, r in DENY]
_IP_RE = re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])|(?<![\w:])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:/\d{1,3})?(?![\w:])")
_BLOCK_WORDS = re.compile(r"\b(?:deny|drop|reject|block|ban|blackhole|unreachable|prohibit)\b", re.I)


def check_command(cmd: str, allow_reboot: bool = False, protected=None) -> Verdict:
    """Denylist check. `protected` is an optional callable(ip)->bool for never-ban addresses."""
    if not cmd or not cmd.strip():
        return Verdict(False, "empty command")
    if "\x00" in cmd:
        return Verdict(False, "NUL byte in command")
    for rx, reason in _DENY_RE:
        if rx.search(cmd):
            return Verdict(False, reason)
    if not allow_reboot and _is_reboot(cmd):
        return Verdict(False, "reboot/shutdown is disabled (WARDEN_ALLOW_REBOOT=false); recommend it to the operator instead")
    if protected and _BLOCK_WORDS.search(cmd):
        for m in _IP_RE.finditer(cmd):
            try:
                ip = str(ipaddress.ip_network(m.group(0), strict=False).network_address)
            except ValueError:
                continue
            if protected(ip):
                return Verdict(False, f"{m.group(0)} is a protected address (allowlist/trusted/own) and must not be blocked")
    return Verdict(True)


# ── read-only classification ───────────────────────────────────────────────
READ_ONLY_BINS = {
    "cat", "tac", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "zgrep", "zcat", "bzcat", "xzcat", "zless",
    "sort", "uniq", "wc", "cut", "tr", "column", "nl", "rev", "comm", "diff", "cmp", "paste", "join", "fold", "fmt", "expand",
    "ls", "dir", "tree", "stat", "file", "readlink", "realpath", "basename", "dirname", "namei", "du", "df", "findmnt",
    "lsblk", "blkid", "free", "uptime", "w", "who", "whoami", "users", "last", "lastb", "lastlog", "id", "groups", "getent",
    "ps", "pgrep", "pstree", "top", "ss", "netstat", "lsof", "uname", "arch", "nproc", "lscpu", "lspci", "lsusb", "lsmod",
    "modinfo", "dmidecode", "vmstat", "iostat", "mpstat", "pidstat", "sar", "date", "cal", "md5sum", "sha1sum", "sha256sum",
    "sha512sum", "b2sum", "cksum", "strings", "od", "xxd", "hexdump", "jq", "base64", "seq", "which", "whereis", "type",
    "command", "printenv", "locale", "getfacl", "lsattr", "getcap", "aa-status", "apparmor_status", "debsums", "chkrootkit",
    "ausearch", "aureport", "utmpdump", "systemd-analyze", "systemd-detect-virt", "systemd-cgls", "lsns", "ldd", "test", "[",
    "echo", "printf", "true", "false", "sleep", "dig", "host", "nslookup", "tracepath", "traceroute", "awk", "gawk", "mawk",
    "sed", "find", "journalctl", "dmesg", "ip", "nft", "iptables", "ip6tables", "iptables-save", "ip6tables-save", "ufw",
    "sysctl", "systemctl", "apt", "apt-cache", "apt-get", "dpkg", "dpkg-query", "docker", "hostnamectl", "timedatectl",
    "loginctl", "resolvectl", "networkctl", "smartctl", "lynis", "crontab", "faillock", "passwd", "chage", "openssl", "curl",
    "sshd", "nginx", "apache2ctl", "visudo", "fail2ban-client", "certbot", "snap", "conntrack", "ethtool", "ping", "tcpdump",
    "needrestart", "rkhunter", "hostname", "env", "timeout", "nice", "ionice", "sudo", "update-alternatives", "mokutil",
    "unattended-upgrade", "pro", "ubuntu-security-status", "landscape-sysinfo", "lsb_release", "cloud-init", "zpool", "zfs",
    "mdadm", "pvs", "vgs", "lvs", "swapon", "numfmt", "xargs",
}

_FIRST_ARG_ONLY = {
    "systemctl": {"status", "show", "list-units", "list-unit-files", "list-timers", "list-sockets", "list-dependencies",
                  "is-active", "is-enabled", "is-failed", "is-system-running", "cat", "get-default", "list-jobs", "list-machines"},
    "apt": {"list", "show", "policy", "search", "changelog", "depends", "rdepends"},
    "dpkg": {"-l", "-L", "-s", "-S", "-p", "-V", "--verify", "--get-selections", "--list", "--status", "--listfiles",
             "--search", "--audit", "-C", "--print-architecture", "--compare-versions"},
    "nft": {"list"},
    "ufw": {"status", "show", "app", "version"},
    "docker": {"ps", "inspect", "logs", "images", "stats", "info", "version", "top", "port", "diff", "compose", "container", "network", "volume", "system"},
    "hostnamectl": {"status", "show", "hostname"},
    "timedatectl": {"status", "show", "show-timesync", "timesync-status", "list-timezones"},
    "loginctl": {"list-sessions", "list-users", "show-session", "show-user", "session-status", "user-status", "list-seats"},
    "resolvectl": {"status", "query", "statistics", "dns", "domain"},
    "networkctl": {"status", "list", "lldp"},
    "fail2ban-client": {"status", "get", "ping", "version", "banned"},
    "certbot": {"certificates"},
    "snap": {"list", "info", "changes", "services", "version", "warnings"},
    "crontab": {"-l"},
    "passwd": {"-S"},
    "chage": {"-l"},
    "openssl": {"x509", "s_client", "version", "verify", "crl", "ciphers", "list"},
    "conntrack": {"-L", "-C", "-S", "--dump", "--count", "--stats"},
    "update-alternatives": {"--display", "--query", "--list", "--get-selections"},
    "visudo": {"-c"},
    "pro": {"status", "security-status", "version"},
    "cloud-init": {"status", "query", "analyze"},
    "zpool": {"status", "list", "iostat"},
    "zfs": {"list", "get"},
    "mdadm": {"--detail", "-D", "--examine", "-E", "--query", "-Q"},
}
_ANY_ARG_DENY = {
    "journalctl": ("--vacuum", "--rotate", "--flush", "--sync", "--relinquish-var", "--setup-keys", "--update-catalog"),
    "sed": ("-i", "--in-place"),
    "find": ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"),
    "sysctl": ("-w", "--write", "-p", "--load", "--system"),
    "dmesg": ("-C", "-c", "--clear", "--read-clear", "-n", "--console-level", "-D", "-E", "--console-off", "--console-on"),
    "ip": ("add", "del", "delete", "set", "flush", "change", "replace", "append", "prepend", "exec", "save", "restore"),
    "iptables": ("-A", "-I", "-D", "-F", "-X", "-P", "-N", "-R", "-Z", "-E", "--append", "--insert", "--delete", "--flush",
                 "--policy", "--new-chain", "--replace", "--zero", "--delete-chain", "--rename-chain"),
    "smartctl": ("-s", "-t", "--test", "--set", "-o", "-S", "-X", "--abort"),
    "curl": ("-o", "-O", "--output", "--remote-name", "-T", "--upload-file", "-d", "--data", "--data-raw", "--data-binary",
             "--data-urlencode", "-F", "--form", "-X", "--request", "-K", "--config", "-c", "--cookie-jar"),
    "tcpdump": ("-w", "-W", "-z"),
    "ethtool": ("-s", "-K", "-G", "-A", "-C", "-L", "-E", "-f", "--change", "--set", "--flash", "-r", "--reset"),
    "rkhunter": ("--update", "--propupd", "--versioncheck"),
    "openssl": ("-out", "genrsa", "genpkey", "req"),
    "hostname": ("-F", "--file", "-b"),
    "docker": ("rm", "rmi", "kill", "stop", "restart", "exec", "run", "up", "down", "prune", "pull", "push", "create", "start", "pause", "update", "cp"),
    "lynis": ("update", "upload", "--upload", "configure"),
    "apt-get": ("clean", "autoclean", "update", "source", "download"),  # others need -s (see _REQUIRES_ANY)
    "xargs": (),
    "sshd": (),
    "nginx": ("-s",),
    "apache2ctl": ("start", "stop", "restart", "graceful", "graceful-stop"),
    "needrestart": ("-r", "a", "-ra"),
    "zpool": (), "zfs": (), "mdadm": (),
}
for _b in ("ip6tables",):
    _ANY_ARG_DENY[_b] = _ANY_ARG_DENY["iptables"]
_REQUIRES_ANY = {
    "apt-get": ("-s", "--simulate", "--just-print", "--dry-run", "--recon", "--no-act"),
    "sshd": ("-T", "-t", "-V"),
    "nginx": ("-t", "-T", "-v", "-V"),
    "apache2ctl": ("-t", "-S", "-M", "configtest", "-V", "-v"),
    "iptables": ("-L", "-S", "--list", "--list-rules", "-C", "--check"),
    "ip6tables": ("-L", "-S", "--list", "--list-rules", "-C", "--check"),
    "needrestart": ("-b",),
    "tcpdump": ("-c",),
}
_WRAPPERS = {"sudo", "nice", "ionice", "env", "timeout", "command"}
_SEP_TOKENS = {"|", "||", "&&", ";", "&", "(", ")", ";;", "|&"}
_SAFE_XARGS_TARGETS = {"ls", "stat", "sha256sum", "md5sum", "file", "grep", "cat", "head", "tail", "wc", "dpkg", "readlink", "getcap", "lsattr", "du", "basename", "echo"}


def _unquote(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        return tok[1:-1]
    return tok


def _tokens(cmd: str) -> list[str] | None:
    try:
        lex = shlex.shlex(cmd, posix=False, punctuation_chars=";&|<>()")
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return None


def _segments(cmd: str) -> list[list[str]] | None:
    """Split into simple commands on unquoted ; & | && || ( ) and newlines (redirections left in place)."""
    toks = _tokens(cmd.replace("\n", " ; "))
    if toks is None:
        return None
    segs: list[list[str]] = [[]]
    for t in toks:
        if t in _SEP_TOKENS:
            segs.append([])
        else:
            segs[-1].append(t)
    return [s for s in segs if s]


def _is_reboot(cmd: str, depth: int = 0) -> bool:
    segs = _segments(cmd)
    if segs is None:  # unparsable: be conservative
        return re.search(r"(?<![\w.-])(?:shutdown|poweroff|halt|reboot)(?![\w.-])", cmd) is not None
    for seg in segs:
        toks = _strip_wrappers(seg)
        if not toks:
            continue
        binary = os.path.basename(_unquote(toks[0]))
        args = [_unquote(t) for t in toks[1:]]
        if binary in REBOOT_BINS:
            return True
        if binary == "systemctl" and any(a in REBOOT_SYSTEMCTL for a in args):
            return True
        if binary in ("init", "telinit") and any(a in ("0", "6") for a in args):
            return True
        if binary in _SHELLS and "-c" in args and depth < 3:
            inner = args[args.index("-c") + 1] if args.index("-c") + 1 < len(args) else ""
            if _is_reboot(inner, depth + 1):
                return True
    return False


def _strip_wrappers(seg: list[str]) -> list[str]:
    toks = [t for t in seg if t]
    # strip env assignments and wrappers
    while toks:
        head = _unquote(toks[0])
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", head):
            toks = toks[1:]
            continue
        base = os.path.basename(head)
        if base in _WRAPPERS and len(toks) > 1:
            toks = toks[1:]
            if base == "timeout":
                while toks and (_unquote(toks[0]).startswith("-") or re.match(r"^\d+[smhd]?$", _unquote(toks[0]))):
                    toks = toks[1:]
            elif base in ("nice", "ionice", "sudo", "env"):
                while toks and _unquote(toks[0]).startswith("-"):
                    toks = toks[1:]
                    if base in ("nice", "ionice") and toks and re.match(r"^-?\d+$", _unquote(toks[0])):
                        toks = toks[1:]
            continue
        break
    return toks


def _segment_ok(seg: list[str]) -> tuple[bool, str]:
    toks = _strip_wrappers(seg)
    if not toks:
        return True, ""
    binary = os.path.basename(_unquote(toks[0]))
    args = [_unquote(t) for t in toks[1:]]
    if binary not in READ_ONLY_BINS:
        return False, f"'{binary}' is not on the read-only list"
    if binary in _FIRST_ARG_ONLY:
        positional = [a for a in args if not a.startswith("-")] if binary not in ("dpkg", "crontab", "passwd", "chage", "conntrack", "update-alternatives", "visudo", "mdadm") else args[:1]
        if binary == "systemctl" and not positional:
            pass  # bare `systemctl --failed` etc.
        elif binary in ("dpkg", "crontab", "passwd", "chage", "conntrack", "update-alternatives", "visudo", "mdadm"):
            if not args or args[0] not in _FIRST_ARG_ONLY[binary]:
                return False, f"'{binary} {args[0] if args else ''}' is not read-only"
        elif not positional or positional[0] not in _FIRST_ARG_ONLY[binary]:
            if not (binary == "ufw" and not positional):
                return False, f"'{binary} {positional[0] if positional else ''}' is not read-only"
    deny = _ANY_ARG_DENY.get(binary)
    if deny:
        for a in args:
            for d in deny:
                if a == d or (d.startswith("--") and a.startswith(d + "=")) or (d.startswith("--") and a.startswith(d) and d in ("--vacuum",)):
                    return False, f"'{binary} {a}' modifies state"
                if binary == "sed" and d == "-i" and re.match(r"^-[a-zA-Z]*i", a):
                    return False, "sed -i modifies files"
    if binary in _REQUIRES_ANY and not any(a in _REQUIRES_ANY[binary] for a in args):
        return False, f"'{binary}' only allowed with {'/'.join(_REQUIRES_ANY[binary])}"
    if binary in ("awk", "gawk", "mawk"):
        prog = " ".join(args)
        if re.search(r"system\s*\(|>\s*\"|>>|\|\s*\"|\|&|getline\s*<|fflush\s*\(\s*\"", prog):
            return False, "awk program performs I/O or runs commands"
    if binary == "sed":
        scripts = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-e", "--expression")]
        if not scripts:
            scripts = [a for a in args if not a.startswith("-")][:1]
        for sc in scripts:
            if re.search(r"(?:^|[;{}\s\d$/])[wWe](?:\s|$)", sc) or re.search(r"s(.).*?\1.*?\1[gpiImM0-9]*[we]", sc):
                return False, "sed script writes files or executes"
        if any(a in ("-f", "--file") or a.startswith("--file=") for a in args):
            return False, "sed -f scripts are not allowed in read-only mode"
    if binary == "hostname" and any(not a.startswith("-") for a in args):
        return False, "hostname <name> changes the hostname"
    if binary == "sysctl" and any("=" in a for a in args):
        return False, "sysctl key=value modifies the kernel"
    if binary == "xargs":
        rest = [a for a in args if not a.startswith("-")]
        if not rest or os.path.basename(rest[0]) not in _SAFE_XARGS_TARGETS:
            return False, "xargs only allowed with simple read-only targets"
    if binary == "top" and "-b" not in args and not any(a.startswith("-b") for a in args):
        return False, "top requires -b (batch mode)"
    if binary == "ping" and not any(a.startswith("-c") for a in args):
        return False, "ping requires -c"
    if binary == "find":
        # find with -newer etc is fine; output files are already denied
        pass
    return True, ""


def is_read_only(cmd: str) -> Verdict:
    if not cmd or not cmd.strip():
        return Verdict(False, "empty command")
    if "`" in cmd or "$(" in cmd or "<(" in cmd or ">(" in cmd:
        return Verdict(False, "command substitution is not allowed in read-only mode")
    if "\n" in cmd.strip():
        return Verdict(False, "multi-line commands are not allowed in read-only mode")
    toks = _tokens(cmd)
    if toks is None:
        return Verdict(False, "could not parse command (unbalanced quotes?)")
    segments: list[list[str]] = [[]]
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in _SEP_TOKENS:
            segments.append([])
        elif set(t) <= set("<>&|") and ">" in t:
            nxt = toks[i + 1] if i + 1 < len(toks) else ""
            if nxt in ("/dev/null", "1", "2", "&1", "&2") or t in (">&", "&>") and nxt in ("1", "2"):
                # strip a trailing fd digit that belongs to the redirect (e.g. `2>`)
                if segments[-1] and segments[-1][-1] in ("1", "2"):
                    segments[-1].pop()
                i += 2
                continue
            return Verdict(False, "output redirection to a file is not read-only")
        elif t == "<" or t == "<<<":
            i += 2  # input redirect: skip the source
            continue
        elif t.startswith("<<"):
            return Verdict(False, "heredocs are not allowed in read-only mode")
        else:
            segments[-1].append(t)
        i += 1
    for seg in segments:
        ok, why = _segment_ok(seg)
        if not ok:
            return Verdict(False, why)
    return Verdict(True)


# ── file policy ────────────────────────────────────────────────────────────
_SECRET_PATHS = [
    r"warden\.env$", r"^/etc/g?shadow-?$", r"^/etc/ssh/ssh_host_\w+_key$", r"/id_(?:rsa|ed25519|ecdsa|dsa)$",
    r"^/etc/letsencrypt/(?:live|archive)/.*privkey\d*\.pem$", r"^/etc/ssl/private/", r"\.key$", r"^/root/\.gnupg/",
    r"/\.aws/credentials$", r"/\.docker/config\.json$", r"^/var/lib/warden/",
    r"(?:^|/)\.env(?:\.(?!example$|sample$|template$|dist$)[\w-]+)?$", r"/\.pgpass$", r"/\.my\.cnf$", r"/\.netrc$",
]
_NO_WRITE = [
    r"^/proc/", r"^/sys/", r"^/dev/", r"^/boot/", r"^/etc/g?shadow-?$", r"^/etc/passwd-?$", r"^/etc/group-?$",
    r"warden\.env$", r"^/opt/warden/", r"^/var/lib/warden/(?!notes/)", r"^/etc/systemd/system/warden\.service",
    r"^/usr/(?:bin|sbin|lib)/", r"^/(?:bin|sbin|lib|lib64)/",
]
VALIDATORS: list[tuple[str, str]] = [
    (r"^/etc/ssh/sshd_config(?:\.d/.+)?$", "sshd -t"),
    (r"^/etc/sudoers(?:\.d/.+)?$", "visudo -c -f {path}"),
    (r"^/etc/nginx/", "nginx -t"),
    (r"^/etc/apache2/", "apache2ctl configtest"),
    (r"^/etc/nftables\.conf$", "nft -c -f {path}"),
    (r"^/etc/fstab$", "findmnt --verify --tab-file {path}"),
    (r"^/etc/postfix/", "postfix check"),
    (r"^/etc/haproxy/haproxy\.cfg$", "haproxy -c -f {path}"),
    (r"^/etc/bind/", "named-checkconf"),
    (r"^/etc/caddy/Caddyfile$", "caddy validate --config {path}"),
]


def is_secret_path(path: str) -> bool:
    p = os.path.normpath(path)
    return any(re.search(rx, p) for rx in _SECRET_PATHS)


def write_denied(path: str) -> str | None:
    p = os.path.normpath(path)
    if not os.path.isabs(p):
        return "path must be absolute"
    for rx in _NO_WRITE:
        if re.search(rx, p):
            return f"writing {p} is not permitted (use the proper tool, e.g. usermod/chpasswd, or ask the operator)"
    return None


def validator_for(path: str) -> str | None:
    p = os.path.normpath(path)
    for rx, cmd in VALIDATORS:
        if re.search(rx, p):
            return cmd
    return None
