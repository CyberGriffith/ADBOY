#!/usr/bin/env python3
"""
ADBOY By Anuk Duljaya 🇱🇰
Professional Active Directory Exposure & Attack-Path Analyzer

Features
- LDAP exposure scan
- BloodHound JSON parsing
- Dangerous edge detection
- Privileged path identification
- Severity-colored terminal theme
- Top risks summary
- JSON export
- Cleaner finding filters
- Built-in manual

This tool is for authorized security testing and lab use.
It analyzes risk and relationships. It does not perform exploitation.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple

try:
    import ldap3
except ImportError:
    ldap3 = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    Console = None
    Panel = None
    Table = None
    Text = None
    box = None
    RICH_AVAILABLE = False


UAC_DONT_REQ_PREAUTH = 0x00400000
UAC_DONT_EXPIRE_PASSWORD = 0x00010000
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_ACCOUNTDISABLE = 0x00000002

PRIVILEGED_NAME_PATTERNS = {
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "ACCOUNT OPERATORS",
    "SERVER OPERATORS",
    "BACKUP OPERATORS",
    "PRINT OPERATORS",
    "KEY ADMINS",
    "ENTERPRISE KEY ADMINS",
    "DOMAIN CONTROLLERS",
    "SCHEMA ADMINS",
    "READ-ONLY DOMAIN CONTROLLERS",
    "KRBTGT",
    "ADMINISTRATOR",
}

NOISY_ACCOUNT_PATTERNS = {
    "GUEST",
    "KRBTGT",
}

DANGEROUS_EDGE_MAP: Dict[str, Tuple[str, str, str]] = {
    "GENERICALL": ("CRITICAL", "Full control over target object.", "ACL abuse"),
    "GENERICWRITE": ("HIGH", "Write access to target object.", "ACL abuse"),
    "WRITEDACL": ("CRITICAL", "Can modify the target ACL.", "ACL abuse"),
    "WRITEOWNER": ("HIGH", "Can take ownership of target object.", "ACL abuse"),
    "ADDMEMBER": ("HIGH", "Can modify group membership.", "Group abuse"),
    "FORCECHANGEPASSWORD": ("HIGH", "Can reset target password.", "Credential abuse"),
    "ALL_EXTENDED_RIGHTS": ("HIGH", "Has broad extended rights on object.", "ACL abuse"),
    "ALLEXTENDEDRIGHTS": ("HIGH", "Has broad extended rights on object.", "ACL abuse"),
    "ADDKEYCREDENTIALLINK": ("CRITICAL", "Can modify msDS-KeyCredentialLink.", "Shadow credentials"),
    "GETCHANGES": ("HIGH", "Directory replication right component detected.", "Replication abuse"),
    "GETCHANGESALL": ("CRITICAL", "Directory replication right component detected.", "Replication abuse"),
    "GETCHANGESINFILTEREDSET": ("HIGH", "Filtered-set replication right detected.", "Replication abuse"),
    "ALLOWEDTOACT": ("CRITICAL", "Potential RBCD-style control over computer object.", "Delegation abuse"),
    "ADMINTO": ("HIGH", "Administrative control over target computer.", "Local admin path"),
    "CANRDP": ("MEDIUM", "RDP capability to target.", "Access path"),
    "EXECUTESDCOM": ("MEDIUM", "DCOM execution capability to target.", "Access path"),
    "MEMBEROF": ("INFO", "Group membership relationship.", "Membership"),
    "CONTAINS": ("INFO", "Directory containment relationship.", "Containment"),
}

BIG_ICON = r"""
      █████╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗
     ██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗ ██╔╝
     ███████║██║  ██║██████╔╝██║   ██║ ╚████╔╝
     ██╔══██║██║  ██║██╔══██╗██║   ██║  ╚██╔╝
     ██║  ██║██████╔╝██████╔╝╚██████╔╝   ██║
     ╚═╝  ╚═╝╚═════╝ ╚═════╝  ╚═════╝    ╚═╝
"""

USER_MANUAL = """
ADBOY By Anuk Duljaya 🇱🇰
========================================

What ADBOY does
- Connects to LDAP and performs an Active Directory exposure scan
- Parses BloodHound JSON exports and looks for risky edges
- Identifies likely privilege paths to high-value targets
- Exports JSON reports for notes and writeups
- Shows top risks and severity-colored findings

Install
1. Create a virtual environment
   python3 -m venv venv
   source venv/bin/activate

2. Install dependencies
   python3 -m pip install ldap3 rich

LDAP mode
   python3 adboy.py ldap -d garfield.htb -u j.arbuckle -p 'PASSWORD' -s 10.129.27.235

LDAP mode with JSON report
   python3 adboy.py ldap -d garfield.htb -u j.arbuckle -p 'PASSWORD' -s 10.129.27.235 --json-out ldap_report.json

BloodHound mode
   python3 adboy.py bh --bh-dir ./bloodhound --start 'J.ARBUCKLE@GARFIELD.HTB'

BloodHound mode with JSON report
   python3 adboy.py bh --bh-dir ./bloodhound --start 'J.ARBUCKLE@GARFIELD.HTB' --report bh_report.json

Show this manual
   python3 adboy.py --manual

Recommended Garfield workflow
1. Run LDAP mode for fast exposure findings
2. Collect BloodHound data
3. Extract JSON files into ./bloodhound
4. Run BloodHound mode using your starting user
5. Review top risks and privileged path results

Notes
- BloodHound export formats vary by version, so some JSONs may need small parser tweaks.
- This tool analyzes risk and paths only.
""".strip()


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    reason: str
    evidence: List[str] = field(default_factory=list)
    source: str = ""
    technique: str = ""


@dataclass
class ADEntry:
    name: str
    dn: str
    object_type: str
    samaccountname: Optional[str] = None
    useraccountcontrol: Optional[int] = None
    serviceprincipalnames: List[str] = field(default_factory=list)
    memberof: List[str] = field(default_factory=list)
    admincount: Optional[int] = None
    allowed_to_delegate_to: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class PathResult:
    source: str
    target: str
    severity: str
    edges: List[str]
    summary: str
    techniques: List[str] = field(default_factory=list)


def severity_rank(severity: str) -> int:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return order.get(severity.upper(), 0)


class UI:
    def __init__(self) -> None:
        self.rich = RICH_AVAILABLE
        self.console = Console() if self.rich else None

    def banner(self) -> None:
        title = "ADBOY By Anuk Duljaya 🇱🇰"
        subtitle = "Professional AD Exposure & Attack-Path Analyzer"
        if self.rich:
            art = Text(BIG_ICON, style="bold bright_cyan")
            header = Text()
            header.append("ADBOY", style="bold bright_yellow")
            header.append("  By Anuk Duljaya 🇱🇰", style="bold bright_green")
            self.console.print(
                Panel.fit(
                    Text.assemble(art, header),
                    title=subtitle,
                    border_style="bright_magenta",
                    box=box.DOUBLE,
                )
            )
        else:
            print("=" * 72)
            print(BIG_ICON)
            print(title)
            print(subtitle)
            print("=" * 72)

    def info(self, message: str) -> None:
        self._print(message, "cyan")

    def success(self, message: str) -> None:
        self._print(message, "green")

    def warn(self, message: str) -> None:
        self._print(message, "yellow")

    def error(self, message: str) -> None:
        self._print(message, "red")

    def summary_panel(self, title: str, lines: List[str]) -> None:
        body = "\n".join(lines)
        if self.rich:
            self.console.print(Panel(body, title=title, border_style="green"))
        else:
            print(f"\n[{title}]\n{body}")

    def top_risks_panel(self, findings: List[Finding]) -> None:
        if not findings:
            return
        counter = Counter(f.severity.upper() for f in findings)
        top = sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)[:5]
        lines = [
            f"CRITICAL : {counter.get('CRITICAL', 0)}",
            f"HIGH     : {counter.get('HIGH', 0)}",
            f"MEDIUM   : {counter.get('MEDIUM', 0)}",
            f"LOW      : {counter.get('LOW', 0)}",
            f"INFO     : {counter.get('INFO', 0)}",
            "",
            "Top Findings:",
        ]
        for item in top:
            lines.append(f"- {item.severity}: {item.title}")
        self.summary_panel("Top Risks Summary", lines)

    def findings_table(self, title: str, findings: List[Finding]) -> None:
        if self.rich:
            table = Table(title=title, border_style="bright_blue", box=box.ROUNDED)
            table.add_column("Severity", style="bold")
            table.add_column("Technique", style="magenta")
            table.add_column("Title", style="white")
            table.add_column("Reason", style="cyan")
            table.add_column("Evidence", style="yellow")
            for finding in findings:
                evidence = " | ".join(finding.evidence[:3])
                if len(finding.evidence) > 3:
                    evidence += f" | +{len(finding.evidence) - 3} more"
                table.add_row(
                    self._style_severity(finding.severity),
                    finding.technique or "-",
                    finding.title,
                    finding.reason,
                    evidence,
                )
            self.console.print(table)
        else:
            print(f"\n{title}")
            for finding in findings:
                print(f"[{finding.severity}] {finding.title}")
                print(f"  Technique: {finding.technique}")
                print(f"  Reason   : {finding.reason}")
                for ev in finding.evidence[:3]:
                    print(f"  Evidence : {ev}")

    def paths_table(self, title: str, paths: List[PathResult]) -> None:
        if self.rich:
            table = Table(title=title, border_style="bright_magenta", box=box.HEAVY_HEAD)
            table.add_column("Severity", style="bold")
            table.add_column("Source", style="cyan")
            table.add_column("Target", style="red")
            table.add_column("Techniques", style="magenta")
            table.add_column("Path", style="white")
            table.add_column("Summary", style="yellow")
            for item in paths:
                table.add_row(
                    self._style_severity(item.severity),
                    item.source,
                    item.target,
                    ", ".join(item.techniques[:3]),
                    " -> ".join(item.edges),
                    item.summary,
                )
            self.console.print(table)
        else:
            print(f"\n{title}")
            for item in paths:
                print(f"[{item.severity}] {item.source} -> {item.target}")
                print(f"  Techniques: {', '.join(item.techniques)}")
                print(f"  Path      : {' -> '.join(item.edges)}")
                print(f"  Summary   : {item.summary}")

    def _style_severity(self, severity: str) -> str:
        sev = severity.upper()
        if sev == "CRITICAL":
            return "[bold red]CRITICAL[/bold red]"
        if sev == "HIGH":
            return "[bold yellow]HIGH[/bold yellow]"
        if sev == "MEDIUM":
            return "[bold cyan]MEDIUM[/bold cyan]"
        if sev == "LOW":
            return "[bold green]LOW[/bold green]"
        return "[white]INFO[/white]"

    def _print(self, message: str, style: str) -> None:
        if self.rich:
            self.console.print(f"[{style}]{message}[/{style}]")
        else:
            print(message)


class LDAPScanner:
    def __init__(
        self,
        domain: str,
        username: str,
        password: str,
        server: Optional[str],
        ui: UI,
        suppress_noisy: bool,
    ) -> None:
        self.domain = domain
        self.username = username
        self.password = password
        self.server_name = server or domain
        self.ui = ui
        self.suppress_noisy = suppress_noisy
        self.conn: Optional[Any] = None
        self.entries: List[ADEntry] = []
        self.findings: List[Finding] = []

    def run(self) -> Tuple[List[ADEntry], List[Finding]]:
        if ldap3 is None:
            raise RuntimeError("ldap3 is not installed. Run: python3 -m pip install ldap3")
        self.connect()
        self.search()
        self.analyze()
        return self.entries, self.findings

    def connect(self) -> None:
        self.ui.info(f"[*] Connecting to LDAP on {self.server_name} ...")
        server = ldap3.Server(self.server_name, get_info=ldap3.ALL, connect_timeout=10)
        attempts = [f"{self.domain}\\{self.username}", f"{self.username}@{self.domain}"]
        last_error = None
        for user_value in attempts:
            try:
                conn = ldap3.Connection(
                    server,
                    user=user_value,
                    password=self.password,
                    authentication=ldap3.NTLM,
                    auto_bind=True,
                )
                self.conn = conn
                self.ui.success(f"[+] Connected to LDAP as {user_value}")
                return
            except Exception as exc:  # noqa: BLE001
                last_error = exc
        raise RuntimeError(f"LDAP bind failed: {last_error}")

    def search(self) -> None:
        if not self.conn:
            raise RuntimeError("Not connected")
        search_base = ",".join(f"DC={part}" for part in self.domain.split("."))
        search_filter = "(|(objectClass=user)(objectClass=computer)(objectClass=group))"
        attributes = [
            "name",
            "distinguishedName",
            "sAMAccountName",
            "objectClass",
            "userAccountControl",
            "servicePrincipalName",
            "memberOf",
            "adminCount",
            "msDS-AllowedToDelegateTo",
            "description",
        ]
        ok = self.conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            paged_size=500,
        )
        if not ok:
            raise RuntimeError("LDAP search failed")
        for entry in self.conn.entries:
            parsed = self._parse_entry(entry)
            if parsed:
                self.entries.append(parsed)
        self.ui.success(f"[+] Enumerated {len(self.entries)} LDAP objects")

    def _parse_entry(self, entry: Any) -> Optional[ADEntry]:
        object_classes = [str(x).lower() for x in getattr(entry, "objectClass", [])]
        if "computer" in object_classes:
            object_type = "computer"
        elif "group" in object_classes:
            object_type = "group"
        elif "user" in object_classes:
            object_type = "user"
        else:
            return None

        def get_value(attr: str, default: Any = None) -> Any:
            if not hasattr(entry, attr):
                return default
            value = getattr(entry, attr)
            return value.value if hasattr(value, "value") else value

        def get_list(attr: str) -> List[str]:
            if not hasattr(entry, attr):
                return []
            value = getattr(entry, attr)
            raw = value.values if hasattr(value, "values") else value
            if raw is None:
                return []
            if isinstance(raw, (list, tuple, set)):
                return [str(x) for x in raw]
            return [str(raw)]

        def safe_int(value: Any) -> Optional[int]:
            try:
                return int(value) if value is not None else None
            except (TypeError, ValueError):
                return None

        return ADEntry(
            name=str(get_value("name", "<unknown>")),
            dn=str(get_value("distinguishedName", "")),
            object_type=object_type,
            samaccountname=get_value("sAMAccountName"),
            useraccountcontrol=safe_int(get_value("userAccountControl")),
            serviceprincipalnames=get_list("servicePrincipalName"),
            memberof=get_list("memberOf"),
            admincount=safe_int(get_value("adminCount")),
            allowed_to_delegate_to=get_list("msDS-AllowedToDelegateTo"),
            description=get_value("description"),
        )

    def analyze(self) -> None:
        for entry in self.entries:
            if entry.object_type == "user":
                self._check_kerberoast(entry)
                self._check_asreproast(entry)
                self._check_password_never_expires(entry)
                self._check_constrained_delegation(entry)
                self._check_admincount(entry)
            elif entry.object_type == "computer":
                self._check_unconstrained_delegation(entry)
                self._check_constrained_delegation(entry)
                self._check_admincount(entry)
            elif entry.object_type == "group":
                self._check_admincount(entry)

    def _is_disabled(self, entry: ADEntry) -> bool:
        if entry.useraccountcontrol is None:
            return False
        return bool(entry.useraccountcontrol & UAC_ACCOUNTDISABLE)

    def _is_noisy_account(self, entry: ADEntry) -> bool:
        upper = entry.name.upper()
        return any(pattern in upper for pattern in NOISY_ACCOUNT_PATTERNS)

    def _add_finding(self, finding: Finding, entry: Optional[ADEntry] = None) -> None:
        if self.suppress_noisy and entry and finding.technique == "Password Policy":
            if self._is_noisy_account(entry):
                return
        self.findings.append(finding)

    def _check_kerberoast(self, entry: ADEntry) -> None:
        if not self._is_disabled(entry) and entry.serviceprincipalnames:
            self._add_finding(
                Finding(
                    category="LDAP Exposure",
                    severity="HIGH",
                    title=f"Kerberoastable user: {entry.name}",
                    reason="User has one or more SPNs and appears enabled.",
                    evidence=entry.serviceprincipalnames,
                    source="LDAP",
                    technique="Kerberoasting",
                ),
                entry,
            )

    def _check_asreproast(self, entry: ADEntry) -> None:
        if entry.useraccountcontrol is not None and not self._is_disabled(entry):
            if entry.useraccountcontrol & UAC_DONT_REQ_PREAUTH:
                self._add_finding(
                    Finding(
                        category="LDAP Exposure",
                        severity="HIGH",
                        title=f"AS-REP roastable user: {entry.name}",
                        reason="DONT_REQ_PREAUTH flag is set.",
                        evidence=[f"userAccountControl={entry.useraccountcontrol}"],
                        source="LDAP",
                        technique="AS-REP Roasting",
                    ),
                    entry,
                )

    def _check_password_never_expires(self, entry: ADEntry) -> None:
        if entry.useraccountcontrol is not None and (
            entry.useraccountcontrol & UAC_DONT_EXPIRE_PASSWORD
        ):
            self._add_finding(
                Finding(
                    category="LDAP Exposure",
                    severity="MEDIUM",
                    title=f"Password never expires: {entry.name}",
                    reason="Account has DONT_EXPIRE_PASSWORD set.",
                    evidence=[f"userAccountControl={entry.useraccountcontrol}"],
                    source="LDAP",
                    technique="Password Policy",
                ),
                entry,
            )

    def _check_unconstrained_delegation(self, entry: ADEntry) -> None:
        if entry.useraccountcontrol is not None and (
            entry.useraccountcontrol & UAC_TRUSTED_FOR_DELEGATION
        ):
            self._add_finding(
                Finding(
                    category="LDAP Exposure",
                    severity="CRITICAL",
                    title=f"Unconstrained delegation: {entry.name}",
                    reason="Computer/account is trusted for unconstrained delegation.",
                    evidence=[f"userAccountControl={entry.useraccountcontrol}"],
                    source="LDAP",
                    technique="Delegation Abuse",
                ),
                entry,
            )

    def _check_constrained_delegation(self, entry: ADEntry) -> None:
        if entry.allowed_to_delegate_to:
            self._add_finding(
                Finding(
                    category="LDAP Exposure",
                    severity="HIGH",
                    title=f"Constrained delegation configured: {entry.name}",
                    reason="msDS-AllowedToDelegateTo is populated.",
                    evidence=entry.allowed_to_delegate_to,
                    source="LDAP",
                    technique="Delegation Abuse",
                ),
                entry,
            )

    def _check_admincount(self, entry: ADEntry) -> None:
        if entry.admincount == 1:
            self._add_finding(
                Finding(
                    category="LDAP Exposure",
                    severity="MEDIUM",
                    title=f"Protected/adminCount object: {entry.name}",
                    reason="adminCount=1 indicates protected or high-privilege handling.",
                    evidence=["adminCount=1"],
                    source="LDAP",
                    technique="Protected Object",
                ),
                entry,
            )


class BloodHoundAnalyzer:
    def __init__(self, bh_dir: str, start_principal: Optional[str], ui: UI) -> None:
        self.bh_dir = Path(bh_dir)
        self.start_principal = start_principal.upper() if start_principal else None
        self.ui = ui
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.adj: DefaultDict[str, List[Tuple[str, str]]] = defaultdict(list)
        self.findings: List[Finding] = []
        self.paths: List[PathResult] = []

    def run(self) -> Tuple[List[Finding], List[PathResult]]:
        self.load_json_files()
        self.flag_dangerous_edges()
        if self.start_principal:
            self.find_paths_to_privileged_targets()
        return self.findings, self.paths

    def load_json_files(self) -> None:
        if not self.bh_dir.exists() or not self.bh_dir.is_dir():
            raise RuntimeError(f"BloodHound directory not found: {self.bh_dir}")
        files = sorted(self.bh_dir.glob("*.json"))
        if not files:
            raise RuntimeError("No JSON files found in BloodHound directory")

        loaded_nodes = 0
        loaded_edges = 0
        for file_path in files:
            try:
                data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception as exc:  # noqa: BLE001
                self.ui.warn(f"[!] Skipping unreadable JSON file {file_path.name}: {exc}")
                continue

            items = self._extract_items(data)
            for item in items:
                source_id = self._node_id(item)
                source_name = self._node_name(item)
                source_type = self._node_type(item)
                if source_id:
                    self.nodes[source_id] = {"name": source_name, "type": source_type, "raw": item}
                    loaded_nodes += 1
                for relation, target_id in self._extract_edges(item):
                    if source_id and target_id:
                        self.adj[source_id].append((relation, target_id))
                        loaded_edges += 1
        self.ui.success(f"[+] Loaded BloodHound data: {loaded_nodes} nodes, {loaded_edges} edges")

    def _extract_items(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            if isinstance(data.get("data"), list):
                return [x for x in data["data"] if isinstance(x, dict)]
            if isinstance(data.get("nodes"), list):
                return [x for x in data["nodes"] if isinstance(x, dict)]
            if all(isinstance(v, dict) for v in data.values()):
                return list(data.values())
            return [data]
        return []

    def _node_id(self, item: Dict[str, Any]) -> Optional[str]:
        for key in ("ObjectIdentifier", "objectIdentifier", "ObjectID", "objectid", "id"):
            value = item.get(key)
            if value:
                return str(value).upper()
        props = item.get("Properties") or item.get("properties") or {}
        for key in ("name", "samaccountname"):
            value = props.get(key)
            if value:
                return str(value).upper()
        return None

    def _node_name(self, item: Dict[str, Any]) -> str:
        props = item.get("Properties") or item.get("properties") or {}
        value = (
            props.get("name")
            or props.get("samaccountname")
            or item.get("Name")
            or item.get("name")
            or item.get("ObjectIdentifier")
            or item.get("objectid")
            or "UNKNOWN"
        )
        return str(value).upper()

    def _node_type(self, item: Dict[str, Any]) -> str:
        return str(
            item.get("Label")
            or item.get("label")
            or item.get("Type")
            or item.get("type")
            or "UNKNOWN"
        ).upper()

    def _extract_edges(self, item: Dict[str, Any]) -> List[Tuple[str, str]]:
        edges: List[Tuple[str, str]] = []
        for rel_block_name in ("Aces", "aces", "Relationships", "relationships", "Edges", "edges"):
            rels = item.get(rel_block_name)
            if not isinstance(rels, list):
                continue
            for rel in rels:
                if not isinstance(rel, dict):
                    continue
                relation = str(
                    rel.get("RightName")
                    or rel.get("rightname")
                    or rel.get("Relationship")
                    or rel.get("relationship")
                    or rel.get("Label")
                    or rel.get("label")
                    or "UNKNOWN"
                ).upper()
                target_id = (
                    rel.get("PrincipalSID")
                    or rel.get("principalid")
                    or rel.get("TargetSID")
                    or rel.get("targetid")
                    or rel.get("ObjectIdentifier")
                    or rel.get("objectid")
                )
                if relation and target_id:
                    target_upper = str(target_id).upper()
                    self.nodes.setdefault(target_upper, {"name": target_upper, "type": "UNKNOWN", "raw": {}})
                    edges.append((relation, target_upper))

        members = item.get("Members") or item.get("members")
        group_id = self._node_id(item)
        if isinstance(members, list) and group_id:
            for member in members:
                if not isinstance(member, dict):
                    continue
                member_id = (
                    member.get("ObjectIdentifier")
                    or member.get("objectid")
                    or member.get("MemberId")
                    or member.get("memberid")
                )
                if member_id:
                    member_upper = str(member_id).upper()
                    self.nodes.setdefault(member_upper, {"name": member_upper, "type": "UNKNOWN", "raw": {}})
                    self.adj[member_upper].append(("MEMBEROF", group_id))
        return edges

    def flag_dangerous_edges(self) -> None:
        for source, rels in self.adj.items():
            for relation, target in rels:
                key = relation.upper().replace(" ", "")
                if key not in DANGEROUS_EDGE_MAP:
                    continue
                severity, meaning, technique = DANGEROUS_EDGE_MAP[key]
                source_name = self.nodes.get(source, {}).get("name", source)
                target_name = self.nodes.get(target, {}).get("name", target)
                if self._is_privileged_name(target_name):
                    severity = self._bump_severity(severity)
                self.findings.append(
                    Finding(
                        category="BloodHound Edge",
                        severity=severity,
                        title=f"{source_name} --[{relation}]--> {target_name}",
                        reason=meaning,
                        evidence=[f"relation={relation}", f"source={source_name}", f"target={target_name}"],
                        source="BloodHound",
                        technique=technique,
                    )
                )

    def find_paths_to_privileged_targets(self) -> None:
        start_id = self._resolve_start_node(self.start_principal)
        if not start_id:
            self.ui.warn(f"[!] Start principal not found in BloodHound data: {self.start_principal}")
            return

        targets = [node_id for node_id, meta in self.nodes.items() if self._is_privileged_name(meta.get("name", ""))]
        if not targets:
            self.ui.warn("[!] No privileged targets matched current patterns")
            return

        for target_id in targets:
            path = self._shortest_path(start_id, target_id)
            if not path:
                continue

            edges_display: List[str] = []
            severities: List[str] = []
            techniques: List[str] = []
            relations_seen: List[str] = []

            for src, rel, dst in path:
                src_name = self.nodes.get(src, {}).get("name", src)
                dst_name = self.nodes.get(dst, {}).get("name", dst)
                edges_display.append(f"{src_name} [{rel}] {dst_name}")
                relations_seen.append(rel)
                key = rel.upper().replace(" ", "")
                sev, _, tech = DANGEROUS_EDGE_MAP.get(key, ("INFO", "", "Path"))
                severities.append(sev)
                if tech not in techniques:
                    techniques.append(tech)

            final_severity = max(severities, key=severity_rank) if severities else "INFO"
            source_name = self.nodes.get(start_id, {}).get("name", start_id)
            target_name = self.nodes.get(target_id, {}).get("name", target_id)
            summary = self._summarize_path(relations_seen, target_name)
            self.paths.append(
                PathResult(
                    source=source_name,
                    target=target_name,
                    severity=final_severity,
                    edges=edges_display,
                    summary=summary,
                    techniques=techniques,
                )
            )
        self.paths.sort(key=lambda item: severity_rank(item.severity), reverse=True)

    def _resolve_start_node(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        candidate = value.upper()
        if candidate in self.nodes:
            return candidate
        for node_id, meta in self.nodes.items():
            name = meta.get("name", "").upper()
            if name == candidate or candidate in name:
                return node_id
        return None

    def _shortest_path(self, start: str, goal: str) -> Optional[List[Tuple[str, str, str]]]:
        queue: deque[str] = deque([start])
        visited: Set[str] = {start}
        parents: Dict[str, Tuple[str, str]] = {}

        while queue:
            current = queue.popleft()
            if current == goal:
                break
            for relation, neighbor in self.adj.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    parents[neighbor] = (current, relation)
                    queue.append(neighbor)

        if goal not in visited:
            return None

        ordered_nodes = [goal]
        while ordered_nodes[-1] != start:
            parent, _ = parents[ordered_nodes[-1]]
            ordered_nodes.append(parent)
        ordered_nodes.reverse()

        built_path: List[Tuple[str, str, str]] = []
        for i in range(len(ordered_nodes) - 1):
            dst = ordered_nodes[i + 1]
            parent, relation = parents[dst]
            built_path.append((parent, relation, dst))
        return built_path

    def _is_privileged_name(self, value: str) -> bool:
        upper = value.upper()
        return any(pattern in upper for pattern in PRIVILEGED_NAME_PATTERNS)

    def _bump_severity(self, severity: str) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev = severity.upper()
        if sev not in order:
            return sev
        idx = order.index(sev)
        return order[min(idx + 1, len(order) - 1)]

    def _summarize_path(self, relations: List[str], target_name: str) -> str:
        normalized = [r.upper().replace(" ", "") for r in relations]
        if any(r in {"GENERICALL", "WRITEDACL", "GENERICWRITE", "ADDMEMBER"} for r in normalized):
            return f"Dangerous control path reaches privileged target {target_name}."
        if "ADDKEYCREDENTIALLINK" in normalized:
            return f"Path includes shadow-credential style control toward {target_name}."
        if "ALLOWEDTOACT" in normalized:
            return f"Path includes delegation-style control toward {target_name}."
        if "GETCHANGES" in normalized or "GETCHANGESALL" in normalized:
            return f"Path includes replication-related control toward {target_name}."
        return f"Shortest privileged path reaches {target_name}."


def export_json(path: str, payload: Dict[str, Any], ui: UI) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    ui.success(f"[+] JSON report written to: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ADBOY By Anuk Duljaya 🇱🇰")
    parser.add_argument("--manual", action="store_true", help="Show built-in user manual")
    subparsers = parser.add_subparsers(dest="mode")

    ldap_parser = subparsers.add_parser("ldap", help="Run LDAP-based exposure scan")
    ldap_parser.add_argument("-d", "--domain", required=True, help="Domain name")
    ldap_parser.add_argument("-u", "--username", required=True, help="Username")
    ldap_parser.add_argument("-p", "--password", required=True, help="Password")
    ldap_parser.add_argument("-s", "--server", help="LDAP server / DC IP / hostname")
    ldap_parser.add_argument("--json-out", help="Optional JSON output path")
    ldap_parser.add_argument(
        "--show-noisy",
        action="store_true",
        help="Show noisy password-never-expires findings for built-in accounts",
    )

    bh_parser = subparsers.add_parser("bh", help="Parse BloodHound JSON and find dangerous paths")
    bh_parser.add_argument("--bh-dir", required=True, help="Directory containing extracted BloodHound JSON files")
    bh_parser.add_argument("--start", help="Start principal, e.g. J.ARBUCKLE@GARFIELD.HTB")
    bh_parser.add_argument("--report", help="Optional JSON output path")

    return parser


def run_ldap_mode(args: argparse.Namespace, ui: UI) -> int:
    scanner = LDAPScanner(
        args.domain,
        args.username,
        args.password,
        args.server,
        ui,
        suppress_noisy=not args.show_noisy,
    )
    entries, findings = scanner.run()
    users = sum(1 for e in entries if e.object_type == "user")
    groups = sum(1 for e in entries if e.object_type == "group")
    computers = sum(1 for e in entries if e.object_type == "computer")

    ui.summary_panel(
        "LDAP Scan Summary",
        [
            f"Domain      : {args.domain}",
            f"Server      : {args.server or args.domain}",
            f"Users       : {users}",
            f"Groups      : {groups}",
            f"Computers   : {computers}",
            f"Findings    : {len(findings)}",
            f"Noisy Filter: {'Enabled' if not args.show_noisy else 'Disabled'}",
        ],
    )

    if findings:
        ordered = sorted(findings, key=lambda item: severity_rank(item.severity), reverse=True)
        ui.top_risks_panel(ordered)
        ui.findings_table("LDAP Exposure & Vulnerability Findings", ordered)
    else:
        ui.success("[+] No LDAP findings matched the current rule set")

    if args.json_out:
        payload = {
            "mode": "ldap",
            "domain": args.domain,
            "server": args.server or args.domain,
            "entry_count": len(entries),
            "finding_count": len(findings),
            "entries": [asdict(e) for e in entries],
            "findings": [asdict(f) for f in findings],
        }
        export_json(args.json_out, payload, ui)
    return 0


def run_bh_mode(args: argparse.Namespace, ui: UI) -> int:
    analyzer = BloodHoundAnalyzer(args.bh_dir, args.start, ui)
    findings, paths = analyzer.run()

    ui.summary_panel(
        "BloodHound Analysis Summary",
        [
            f"BloodHound Dir : {args.bh_dir}",
            f"Start Principal: {args.start or 'Not provided'}",
            f"Edge Findings  : {len(findings)}",
            f"Priv Paths     : {len(paths)}",
        ],
    )

    if findings:
        ordered_findings = sorted(findings, key=lambda item: severity_rank(item.severity), reverse=True)
        ui.top_risks_panel(ordered_findings)
        ui.findings_table("Dangerous BloodHound Edges", ordered_findings[:50])
    else:
        ui.warn("[!] No dangerous edges matched the current rule map")

    if paths:
        ui.paths_table("Privileged Path Results", paths[:25])
    else:
        ui.warn("[!] No privileged paths found from the selected starting principal")

    if args.report:
        payload = {
            "mode": "bloodhound",
            "start_principal": args.start,
            "node_count": len(analyzer.nodes),
            "edge_finding_count": len(findings),
            "path_count": len(paths),
            "findings": [asdict(f) for f in findings],
            "paths": [asdict(p) for p in paths],
        }
        export_json(args.report, payload, ui)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    ui = UI()
    ui.banner()

    if args.manual:
        print(USER_MANUAL)
        return 0
    if not args.mode:
        parser.print_help()
        return 1

    try:
        if args.mode == "ldap":
            return run_ldap_mode(args, ui)
        if args.mode == "bh":
            return run_bh_mode(args, ui)
        ui.error("[!] Unknown mode selected")
        return 1
    except KeyboardInterrupt:
        ui.warn("[!] Interrupted by user")
        return 130
    except Exception as exc:  # noqa: BLE001
        ui.error(f"[!] Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
