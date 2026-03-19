#!/usr/bin/env python3
"""
UE Signaling Analyzer — LTE/NR Signaling Message Analysis Tool

Provides detailed signaling message views for RRC/NAS/OTA troubleshooting:
  - Protocol timelines
  - Ladder diagrams
  - Failure analysis
  - Mobility tracking
  - State machine views

Imports the parsing engine from qcom_log_analyzer.py and adds signaling-focused
analysis layers on top.

No external dependencies beyond the standard library (+ optional colorama for colors).
"""

import argparse
import csv
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path setup — locate qcom_log_analyzer.py (check parent, grandparent, cwd)
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
for _candidate in [_SCRIPT_DIR.parent, _SCRIPT_DIR.parent.parent, Path.cwd()]:
    if (_candidate / "qcom_log_analyzer.py").exists():
        sys.path.insert(0, str(_candidate))
        break

from qcom_log_analyzer import (
    DLFParser,
    DiagPacket,
    LTEAnalyzer,
    NR5GAnalyzer,
    InsightEngine,
    AnalysisResult,
    RRCEvent,
    NASEvent,
    SignalSample,
    Anomaly,
    LOG_LTE_RRC_OTA,
    LOG_LTE_RRC_STATE,
    LOG_LTE_NAS_EMM_OTA,
    LOG_LTE_NAS_EMM_STATE,
    LOG_LTE_NAS_EMM_SEC_OTA,
    LOG_LTE_NAS_ESM_OTA,
    LOG_LTE_MAC_DL_TB,
    LOG_LTE_MAC_UL_TB,
    LOG_LTE_MAC_RACH,
    LOG_LTE_ML1_SERV_CELL_MEAS,
    LOG_LTE_RRC_SERV_CELL_INFO,
    LOG_LTE_PDCP_DL_STATS,
    LOG_LTE_PDCP_UL_STATS,
    LOG_NR_RRC_OTA,
    LOG_NR_RRC_STATE,
    LOG_NR_NAS_MM5G_STATE,
    LOG_NR_NAS_MM5G_STATE_ALT,
    LOG_NR_NAS_SM5G_OTA,
    LOG_NR_NAS_MM5G_OTA_PLAIN,
    LOG_NR_ML1_MEAS_DB,
    LOG_NR_MAC_PDSCH_STATS,
    LOG_NR_MAC_PUSCH_STATS,
    LOG_NR_ML1_SEARCHER,
    LOG_NR_PDCP_DL_STATS,
    LOG_CODE_NAMES,
    LTE_RRC_MSG_TYPES,
    NR_RRC_MSG_TYPES,
    NAS_EMM_MSG_TYPES,
    EMM_CAUSE_CODES,
    MM5G_CAUSE_CODES,
    LTE_RRC_STATES,
    NR_RRC_STATES,
)

# ---------------------------------------------------------------------------
# Color support — optional colorama, falls back to no-op
# ---------------------------------------------------------------------------

class _NoColor:
    """No-op color class when colorama is not available or --no-color is set."""
    RESET = ""
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    CYAN = ""
    MAGENTA = ""
    WHITE = ""
    BOLD = ""
    DIM = ""

class _AnsiColor:
    """ANSI escape color codes."""
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

# Global color instance — set by main()
C = _AnsiColor()

# ---------------------------------------------------------------------------
# EARFCN / NR-ARFCN → Band Lookup Tables
# ---------------------------------------------------------------------------

# LTE EARFCN ranges: (earfcn_start, earfcn_end) → band_name
LTE_EARFCN_BANDS = [
    (600, 1199, "B2"),
    (1950, 2399, "B4"),
    (2400, 2649, "B5"),
    (2750, 3449, "B7"),
    (5010, 5179, "B12"),
    (5180, 5279, "B13"),
    (5280, 5379, "B14"),
    (8040, 8689, "B25"),
    (8690, 9039, "B26"),
    (9210, 9659, "B30"),
    (39650, 41589, "B41"),
    (46590, 54339, "B46"),
    (55240, 56739, "B48"),
    (66436, 67335, "B66"),
    (68586, 68935, "B71"),
    (0, 599, "B1"),
    (1200, 1949, "B3"),
    (6150, 6449, "B17"),
    (9660, 9769, "B31"),
    (9770, 9869, "B32"),
    (36000, 36199, "B33"),
    (36200, 36349, "B34"),
    (36350, 36949, "B35"),
    (36950, 37549, "B36"),
    (37550, 37749, "B37"),
    (37750, 38249, "B38"),
    (38250, 38649, "B39"),
    (38650, 39649, "B40"),
    (41590, 43589, "B42"),
    (43590, 45589, "B43"),
    (45590, 46589, "B44"),
    (65536, 66435, "B65"),
    (67336, 67535, "B67"),
    (67536, 67835, "B68"),
    (67836, 68335, "B69"),
    (68336, 68585, "B70"),
]

# NR NR-ARFCN ranges: (arfcn_start, arfcn_end) → band_name
NR_ARFCN_BANDS = [
    (386000, 398000, "n2"),
    (173800, 178800, "n5"),
    (524000, 538000, "n7"),
    (145800, 149200, "n12"),
    (386000, 399000, "n25"),
    (151600, 160600, "n28"),
    (499200, 537999, "n41"),
    (636667, 646666, "n48"),
    (422000, 440000, "n66"),
    (123400, 130400, "n71"),
    (620000, 680000, "n77"),
    (620000, 653333, "n78"),
    (2054166, 2104165, "n260"),
    (2016667, 2070832, "n261"),
    (285400, 286400, "n8"),
    (496700, 499000, "n38"),
    (743334, 795000, "n79"),
    (422000, 434000, "n70"),
    (399000, 404000, "n34"),
    (460000, 480000, "n39"),
    (286400, 303400, "n20"),
    (158200, 164200, "n14"),
    (171800, 178800, "n29"),
    (402000, 405000, "n75"),
    (405000, 420000, "n76"),
]


def earfcn_to_band(earfcn: Optional[int], tech: str) -> str:
    """Convert EARFCN or NR-ARFCN to band name string."""
    if earfcn is None:
        return ""
    table = NR_ARFCN_BANDS if tech == "NR" else LTE_EARFCN_BANDS
    for start, end, band in table:
        if start <= earfcn <= end:
            return band
    return ""


# ---------------------------------------------------------------------------
# CQI quality mapping
# ---------------------------------------------------------------------------

def cqi_quality(cqi: int) -> str:
    """Map CQI index (0-15) to quality category."""
    if cqi == 0:
        return "out-of-range"
    if cqi <= 6:
        return "poor"
    if cqi <= 9:
        return "fair"
    if cqi <= 12:
        return "good"
    return "excellent"


# ---------------------------------------------------------------------------
# SignalingEvent — unified dataclass for RRC + NAS events
# ---------------------------------------------------------------------------

@dataclass
class SignalingEvent:
    """Unified signaling event merging RRC and NAS information."""
    timestamp: datetime
    tech: str               # "LTE" or "NR"
    layer: str              # "RRC", "NAS-EMM", "NAS-ESM", "NAS-5GMM", "NAS-5GSM"
    direction: str          # "UL", "DL", ""
    channel: str            # e.g. "BCCH-BCH", "DCCH-DL", ""
    message_type: str       # e.g. "RRCConnectionSetup", "Attach Accept"
    pci: Optional[int] = None
    earfcn: Optional[int] = None
    sfn: Optional[int] = None
    band: str = ""
    call_mode: str = ""     # "SA", "NSA", "LTE-only", ""
    cause_code: Optional[int] = None
    cause_text: str = ""
    severity: str = ""      # "normal", "warning", "critical"
    procedure_group: str = ""  # grouping for ladder diagrams


# ---------------------------------------------------------------------------
# Procedure grouping helpers
# ---------------------------------------------------------------------------

_LTE_PROCEDURE_KEYWORDS = {
    "RRCConnection": "RRC Setup",
    "Reestablishment": "RRC Reestablishment",
    "Reconfiguration": "RRC Reconfiguration",
    "Release": "RRC Release",
    "SecurityMode": "Security",
    "UECapability": "UE Capability",
    "MeasurementReport": "Measurement",
    "MasterInformationBlock": "MIB/SIB",
    "SystemInformation": "MIB/SIB",
    "Paging": "Paging",
    "DLInformationTransfer": "Information Transfer",
    "ULInformationTransfer": "Information Transfer",
    "Attach": "Attach",
    "Detach": "Detach",
    "Tracking Area Update": "TAU",
    "Service": "Service Request",
    "Authentication": "Authentication",
    "Identity": "Identity",
    "GUTI": "GUTI Reallocation",
    "EMM State": "EMM State",
    "EMM Information": "EMM Information",
    "EMM Status": "EMM Status",
    "EPS Bearer": "EPS Bearer",
    "PDN": "PDN Connectivity",
    "ESM": "ESM",
    "RACH": "RACH",
}

_NR_PROCEDURE_KEYWORDS = {
    "RRCSetup": "RRC Setup",
    "RRCReestablishment": "RRC Reestablishment",
    "RRCReconfiguration": "RRC Reconfiguration",
    "RRCRelease": "RRC Release",
    "RRCReject": "RRC Reject",
    "RRCResume": "RRC Resume",
    "SecurityMode": "Security",
    "MIB": "MIB/SIB",
    "SIB": "MIB/SIB",
    "MeasurementReport": "Measurement",
    "DLInformationTransfer": "Information Transfer",
    "ULInformationTransfer": "Information Transfer",
    "Registration": "Registration",
    "Deregistration": "Deregistration",
    "Service": "Service Request",
    "Authentication": "Authentication",
    "Configuration Update": "Configuration Update",
    "5GMM State": "5GMM State",
    "5GMM Status": "5GMM Status",
    "PDU Session": "PDU Session",
    "RACH": "RACH",
}


def _classify_procedure(msg_type: str, tech: str) -> str:
    """Determine procedure group from message type string."""
    keywords = _NR_PROCEDURE_KEYWORDS if tech == "NR" else _LTE_PROCEDURE_KEYWORDS
    for keyword, group in keywords.items():
        if keyword in msg_type:
            return group
    return "Other"


def _classify_severity(msg_type: str, cause_code: Optional[int]) -> str:
    """Classify event severity based on message type and cause code."""
    lower = msg_type.lower()
    if any(w in lower for w in ("reject", "failure", "fail")):
        return "critical"
    if any(w in lower for w in ("reestablishment", "release", "detach", "deregistration")):
        return "warning"
    if cause_code is not None and cause_code > 0:
        return "warning"
    return "normal"


def _extract_channel(details: str) -> str:
    """Extract channel name from RRCEvent.details string."""
    if details.startswith("chan="):
        return details.split("chan=")[1].split()[0]
    return ""


def _classify_nas_layer(msg_type: str, tech: str) -> str:
    """Determine NAS sub-layer from message type."""
    if tech == "NR":
        if "5GSM" in msg_type or "PDU Session" in msg_type:
            return "NAS-5GSM"
        return "NAS-5GMM"
    else:
        if "ESM" in msg_type or "EPS Bearer" in msg_type or "PDN" in msg_type:
            return "NAS-ESM"
        return "NAS-EMM"


# ---------------------------------------------------------------------------
# LogProcessor — parse file, build unified SignalingEvent list
# ---------------------------------------------------------------------------

class LogProcessor:
    """Parse log file and build unified SignalingEvent list with mode/band info."""

    def __init__(self, filepath: str, verbose: bool = False):
        self.filepath = filepath
        self.verbose = verbose
        self.events: List[SignalingEvent] = []
        self.result: Optional[AnalysisResult] = None
        self.cqi_samples: List[Tuple[datetime, int]] = []   # (timestamp, cqi_index)
        self.fiveqi_values: List[Tuple[datetime, int]] = []  # (timestamp, 5qi_value)

        # RRC state timeline for SA/NSA/LTE-only detection
        self._lte_rrc_states: List[Tuple[datetime, str]] = []  # (ts, "Idle"/"Connected")
        self._nr_rrc_states: List[Tuple[datetime, str]] = []

    def process(self) -> List[SignalingEvent]:
        """Full processing pipeline."""
        # 1. Parse binary log
        parser = DLFParser(self.filepath, verbose=self.verbose)
        packets = parser.parse()
        if not packets:
            print(f"[WARN] No packets parsed from {self.filepath}")
            return []

        # 2. Decode with LTE/NR analyzers
        result = AnalysisResult()
        lte = LTEAnalyzer(verbose=self.verbose)
        nr = NR5GAnalyzer(verbose=self.verbose)

        for pkt in packets:
            result.packet_counts[pkt.log_code] += 1
            result.total_packets += 1
            if pkt.tech == "LTE":
                lte.decode_packet(pkt, result)
            elif pkt.tech == "NR":
                nr.decode_packet(pkt, result)

            # Extract CQI from LTE MAC DL TB (0xB063)
            if pkt.log_code == LOG_LTE_MAC_DL_TB:
                self._extract_cqi(pkt)

            # Extract 5QI from NR NAS 5GSM (0xB80A)
            if pkt.log_code == LOG_NR_NAS_SM5G_OTA:
                self._extract_5qi(pkt)

        # 3. Insight engine
        engine = InsightEngine()
        engine.analyze(result)
        self.result = result

        # 4. Build RRC state timeline
        self._build_rrc_state_timeline(result)

        # 5. Convert to unified SignalingEvent list
        self._build_events(result)

        # 6. Sort by timestamp
        self.events.sort(key=lambda e: e.timestamp)

        return self.events

    def _extract_cqi(self, pkt: DiagPacket) -> None:
        """Best-effort extraction of CQI from LTE MAC DL TB payload."""
        payload = pkt.payload
        if len(payload) < 10:
            return
        try:
            # CQI is often in the per-record data; scan for a plausible CQI byte (0-15)
            # In many DL TB versions, a CQI byte is present at offset 6 or 8
            for off in (6, 8, 7, 9):
                if off < len(payload):
                    val = payload[off]
                    if 0 <= val <= 15:
                        self.cqi_samples.append((pkt.timestamp, val))
                        return
        except (IndexError, TypeError):
            pass

    def _extract_5qi(self, pkt: DiagPacket) -> None:
        """Best-effort extraction of 5QI from NR NAS 5GSM OTA payload."""
        payload = pkt.payload
        if len(payload) < 10:
            return
        try:
            # 5QI is in QoS flow descriptor of PDU Session Establishment Accept
            # Scan for plausible 5QI values (1-86 per 3GPP TS 23.501)
            nas_pdu = payload[4:]
            for off in range(min(len(nas_pdu), 64)):
                val = nas_pdu[off]
                if 1 <= val <= 86:
                    # Heuristic: 5QI typically follows a QoS rule/flow descriptor IE
                    if off > 0 and nas_pdu[off - 1] in (0x09, 0x79, 0x65):
                        self.fiveqi_values.append((pkt.timestamp, val))
                        return
        except (IndexError, TypeError):
            pass

    def _build_rrc_state_timeline(self, result: AnalysisResult) -> None:
        """Build RRC state timelines for SA/NSA detection."""
        for evt in result.rrc_events:
            if "RRC State:" in evt.event:
                state = evt.event.split("RRC State: ")[1] if "RRC State: " in evt.event else ""
                if evt.tech == "LTE":
                    self._lte_rrc_states.append((evt.timestamp, state))
                elif evt.tech == "NR":
                    self._nr_rrc_states.append((evt.timestamp, state))
        self._lte_rrc_states.sort(key=lambda x: x[0])
        self._nr_rrc_states.sort(key=lambda x: x[0])

    def _get_call_mode(self, ts: datetime) -> str:
        """Determine SA/NSA/LTE-only mode at a given timestamp."""
        lte_state = self._state_at(self._lte_rrc_states, ts)
        nr_state = self._state_at(self._nr_rrc_states, ts)

        lte_connected = lte_state == "Connected"
        nr_connected = nr_state == "Connected"

        if lte_connected and nr_connected:
            return "NSA"
        if nr_connected and not lte_connected:
            return "SA"
        if lte_connected and not nr_connected:
            return "LTE-only"
        return ""

    @staticmethod
    def _state_at(timeline: List[Tuple[datetime, str]], ts: datetime) -> str:
        """Get the last known state at or before timestamp ts."""
        last = ""
        for t, state in timeline:
            if t <= ts:
                last = state
            else:
                break
        return last

    def _build_events(self, result: AnalysisResult) -> None:
        """Convert RRCEvents and NASEvents into unified SignalingEvents."""
        # RRC events
        for rrc in result.rrc_events:
            band = earfcn_to_band(rrc.earfcn, rrc.tech)
            mode = self._get_call_mode(rrc.timestamp)
            channel = _extract_channel(rrc.details)
            severity = _classify_severity(rrc.event, None)
            procedure = _classify_procedure(rrc.event, rrc.tech)

            evt = SignalingEvent(
                timestamp=rrc.timestamp,
                tech=rrc.tech,
                layer="RRC",
                direction=rrc.direction,
                channel=channel,
                message_type=rrc.event,
                pci=rrc.pci,
                earfcn=rrc.earfcn,
                sfn=rrc.sfn,
                band=band,
                call_mode=mode,
                severity=severity,
                procedure_group=procedure,
            )
            self.events.append(evt)

        # NAS events
        for nas in result.nas_events:
            layer = _classify_nas_layer(nas.msg_type, nas.tech)
            mode = self._get_call_mode(nas.timestamp)
            severity = _classify_severity(nas.msg_type, nas.cause_code)
            procedure = _classify_procedure(nas.msg_type, nas.tech)

            evt = SignalingEvent(
                timestamp=nas.timestamp,
                tech=nas.tech,
                layer=layer,
                direction=nas.direction,
                channel="",
                message_type=nas.msg_type,
                band="",
                call_mode=mode,
                cause_code=nas.cause_code,
                cause_text=nas.cause_text,
                severity=severity,
                procedure_group=procedure,
            )
            self.events.append(evt)

    def filter_events(
        self,
        tech: Optional[str] = None,
        msg_filter: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
    ) -> List[SignalingEvent]:
        """Return filtered copy of events."""
        filtered = self.events
        if tech:
            t = tech.upper()
            filtered = [e for e in filtered if e.tech == t]
        if msg_filter:
            mf = msg_filter.lower()
            filtered = [e for e in filtered if mf in e.message_type.lower()]
        if time_start:
            filtered = [e for e in filtered if e.timestamp >= time_start]
        if time_end:
            filtered = [e for e in filtered if e.timestamp <= time_end]
        return filtered


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _ts(dt: datetime) -> str:
    """Format timestamp as HH:MM:SS.mmm."""
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _ts_full(dt: datetime) -> str:
    """Format timestamp as YYYY-MM-DD HH:MM:SS.mmm."""
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _colorize_severity(text: str, severity: str) -> str:
    """Color-code text based on severity."""
    if severity == "critical":
        return f"{C.RED}{text}{C.RESET}"
    if severity == "warning":
        return f"{C.YELLOW}{text}{C.RESET}"
    return f"{C.GREEN}{text}{C.RESET}"


def _section_header(title: str) -> str:
    """Format a section header."""
    line = "=" * 80
    return f"\n{C.BOLD}{C.CYAN}{line}\n  {title}\n{line}{C.RESET}"


# ---- SummaryDashboard ----

class SummaryDashboard:
    """Quick overview dashboard."""

    def render(self, proc: LogProcessor, events: List[SignalingEvent]) -> None:
        result = proc.result
        if not result:
            print("[WARN] No analysis result available.")
            return

        print(_section_header("SIGNALING SUMMARY DASHBOARD"))

        # Time range
        if result.first_timestamp and result.last_timestamp:
            print(f"\n  Log Period : {_ts_full(result.first_timestamp)} → {_ts_full(result.last_timestamp)}")
            if result.file_duration:
                total_sec = result.file_duration.total_seconds()
                mins, secs = divmod(int(total_sec), 60)
                hrs, mins = divmod(mins, 60)
                print(f"  Duration   : {hrs}h {mins}m {secs}s")
        print(f"  Total Pkts : {result.total_packets}  (parse errors: {result.parse_errors})")

        # Message distribution
        print(f"\n{C.BOLD}  Message Distribution:{C.RESET}")
        lte_msgs = [e for e in events if e.tech == "LTE"]
        nr_msgs = [e for e in events if e.tech == "NR"]
        print(f"    {'Layer':<15} {'LTE':>8} {'NR':>8} {'Total':>8}")
        print(f"    {'─' * 15} {'─' * 8} {'─' * 8} {'─' * 8}")
        for layer in ["RRC", "NAS-EMM", "NAS-ESM", "NAS-5GMM", "NAS-5GSM"]:
            lc = sum(1 for e in lte_msgs if e.layer == layer)
            nc = sum(1 for e in nr_msgs if e.layer == layer)
            total = lc + nc
            if total > 0:
                print(f"    {layer:<15} {lc:>8} {nc:>8} {total:>8}")
        total_lte = len(lte_msgs)
        total_nr = len(nr_msgs)
        print(f"    {'─' * 15} {'─' * 8} {'─' * 8} {'─' * 8}")
        print(f"    {'TOTAL':<15} {total_lte:>8} {total_nr:>8} {total_lte + total_nr:>8}")

        # Call mode summary
        print(f"\n{C.BOLD}  Call Mode:{C.RESET}")
        mode_counts = defaultdict(int)
        for e in events:
            if e.call_mode:
                mode_counts[e.call_mode] += 1
        if mode_counts:
            for mode in ["SA", "NSA", "LTE-only"]:
                if mode in mode_counts:
                    print(f"    {mode:<12}: {mode_counts[mode]} events")
            # Estimate time in each mode from RRC state timeline
            self._print_mode_durations(proc)
        else:
            print("    (mode detection unavailable — no RRC state events)")

        # Bands used
        print(f"\n{C.BOLD}  Bands Used:{C.RESET}")
        bands = defaultdict(int)
        for e in events:
            if e.band:
                bands[e.band] += 1
        if bands:
            for b in sorted(bands.keys()):
                print(f"    {b:<8}: {bands[b]} events")
        else:
            print("    (no band information available)")

        # CQI distribution
        if proc.cqi_samples:
            print(f"\n{C.BOLD}  CQI Distribution (LTE):{C.RESET}")
            cats = {"out-of-range": 0, "poor": 0, "fair": 0, "good": 0, "excellent": 0}
            for _, cqi in proc.cqi_samples:
                cats[cqi_quality(cqi)] += 1
            total_cqi = len(proc.cqi_samples)
            for cat in ["excellent", "good", "fair", "poor", "out-of-range"]:
                cnt = cats[cat]
                pct = cnt / total_cqi * 100 if total_cqi else 0
                bar = "█" * int(pct / 2)
                print(f"    {cat:<14}: {cnt:>6} ({pct:5.1f}%) {bar}")

        # 5QI values
        if proc.fiveqi_values:
            print(f"\n{C.BOLD}  5QI Values (NR):{C.RESET}")
            qi_counts = defaultdict(int)
            for _, qi in proc.fiveqi_values:
                qi_counts[qi] += 1
            for qi in sorted(qi_counts.keys()):
                print(f"    5QI={qi:<4}: {qi_counts[qi]} occurrences")

        # Failure summary
        failures = [e for e in events if e.severity == "critical"]
        warnings = [e for e in events if e.severity == "warning"]
        print(f"\n{C.BOLD}  Failure Stats:{C.RESET}")
        print(f"    {C.RED}Critical : {len(failures)}{C.RESET}")
        print(f"    {C.YELLOW}Warnings : {len(warnings)}{C.RESET}")
        if failures:
            fail_types = defaultdict(int)
            for f in failures:
                fail_types[f.message_type] += 1
            print(f"    Top failures:")
            for mt, cnt in sorted(fail_types.items(), key=lambda x: -x[1])[:5]:
                print(f"      {mt}: {cnt}")

        # Signal quality snapshot
        if result.signal_samples:
            print(f"\n{C.BOLD}  Signal Quality Snapshot:{C.RESET}")
            for tech in ["LTE", "NR"]:
                samples = [s for s in result.signal_samples if s.tech == tech]
                if samples:
                    rsrp_vals = [s.rsrp for s in samples if s.rsrp is not None]
                    sinr_vals = [s.sinr for s in samples if s.sinr is not None]
                    if rsrp_vals:
                        print(f"    {tech} RSRP: avg={mean(rsrp_vals):.1f} min={min(rsrp_vals):.1f} max={max(rsrp_vals):.1f} dBm")
                    if sinr_vals:
                        print(f"    {tech} SINR: avg={mean(sinr_vals):.1f} min={min(sinr_vals):.1f} max={max(sinr_vals):.1f} dB")

        # Cell summary
        pcis = defaultdict(set)
        for e in events:
            if e.pci is not None:
                pcis[e.tech].add(e.pci)
        if pcis:
            print(f"\n{C.BOLD}  Cells Seen:{C.RESET}")
            for tech in sorted(pcis.keys()):
                print(f"    {tech}: {len(pcis[tech])} cells — PCI {sorted(pcis[tech])}")

        # Anomaly counts
        if result.anomalies:
            print(f"\n{C.BOLD}  Anomaly Summary:{C.RESET}")
            anom_cats = defaultdict(int)
            for a in result.anomalies:
                anom_cats[a.category] += 1
            for cat, cnt in sorted(anom_cats.items(), key=lambda x: -x[1]):
                print(f"    {cat:<24}: {cnt}")

        print()

    def _print_mode_durations(self, proc: LogProcessor) -> None:
        """Estimate time spent in each call mode from RRC state timeline."""
        # Merge LTE and NR state transitions in order
        all_ts = set()
        for t, _ in proc._lte_rrc_states:
            all_ts.add(t)
        for t, _ in proc._nr_rrc_states:
            all_ts.add(t)
        if len(all_ts) < 2:
            return
        timestamps = sorted(all_ts)
        mode_time: Dict[str, float] = defaultdict(float)
        for i in range(len(timestamps) - 1):
            ts = timestamps[i]
            next_ts = timestamps[i + 1]
            delta = (next_ts - ts).total_seconds()
            mode = proc._get_call_mode(ts)
            if mode:
                mode_time[mode] += delta
        total = sum(mode_time.values())
        if total > 0:
            print("    Time in mode:")
            for mode in ["SA", "NSA", "LTE-only"]:
                if mode in mode_time:
                    secs = mode_time[mode]
                    pct = secs / total * 100
                    print(f"      {mode:<10}: {secs:>8.1f}s ({pct:5.1f}%)")


# ---- TimelineRenderer ----

class TimelineRenderer:
    """Chronological table of all signaling events."""

    def render(self, events: List[SignalingEvent]) -> None:
        if not events:
            print("[INFO] No signaling events to display.")
            return

        print(_section_header("SIGNALING TIMELINE"))

        hdr = (
            f"  {'TIME':<15} {'TECH':<5} {'MODE':<5} {'DIR':<4} "
            f"{'LAYER':<10} {'CHANNEL':<12} {'MESSAGE TYPE':<38} "
            f"{'PCI':<6} {'BAND':<6} {'CAUSE'}"
        )
        print(f"\n{C.BOLD}{hdr}{C.RESET}")
        print(f"  {'─' * 120}")

        for evt in events:
            pci_str = str(evt.pci) if evt.pci is not None else ""
            cause_str = ""
            if evt.cause_text:
                cause_str = f"{evt.cause_text}"
            elif evt.severity == "critical":
                cause_str = "[!!]"
            elif evt.severity == "warning":
                cause_str = "[!]"

            line = (
                f"  {_ts(evt.timestamp):<15} {evt.tech:<5} {evt.call_mode:<5} "
                f"{evt.direction:<4} {evt.layer:<10} {evt.channel:<12} "
                f"{evt.message_type:<38} {pci_str:<6} {evt.band:<6} {cause_str}"
            )
            print(_colorize_severity(line, evt.severity))

        print()


# ---- LadderRenderer ----

class LadderRenderer:
    """ASCII UE ↔ Network protocol ladder diagram."""

    def render(self, events: List[SignalingEvent]) -> None:
        if not events:
            print("[INFO] No signaling events for ladder diagram.")
            return

        print(_section_header("PROTOCOL LADDER DIAGRAM"))

        # Group by procedure
        groups: List[Tuple[str, List[SignalingEvent]]] = []
        current_group = ""
        current_events: List[SignalingEvent] = []

        for evt in events:
            if evt.layer != "RRC" and "State" in evt.message_type:
                continue  # Skip state-only events in ladder
            group = evt.procedure_group
            if group != current_group and current_events:
                groups.append((current_group, current_events))
                current_events = []
            current_group = group
            current_events.append(evt)
        if current_events:
            groups.append((current_group, current_events))

        ue_col = 4
        net_col = 50

        for group_name, group_events in groups:
            first = group_events[0]
            pci_str = f", PCI={first.pci}" if first.pci is not None else ""
            band_str = f", {first.band}" if first.band else ""
            mode_str = f", {first.call_mode}" if first.call_mode else ""
            header = f"--- [{_ts(first.timestamp)}] {group_name} ({first.tech}{pci_str}{band_str}{mode_str}) ---"
            print(f"\n{C.BOLD}{C.CYAN}{header}{C.RESET}")
            print(f"    {'UE':<{net_col - ue_col - 2}}{'Network'}")
            print(f"    {'|':<{net_col - ue_col - 2}}{'|'}")

            for evt in group_events:
                msg = evt.message_type
                if len(msg) > 35:
                    msg = msg[:32] + "..."
                if evt.direction == "UL":
                    arrow = f"  ---[{msg}]---->"
                    line = f"    |{arrow:<{net_col - ue_col - 2}}|"
                elif evt.direction == "DL":
                    arrow = f"<----[{msg}]---  "
                    padding = net_col - ue_col - 2 - len(arrow)
                    line = f"    |{' ' * max(padding, 0)}{arrow}|"
                else:
                    line = f"    |  ({msg}){' ' * max(net_col - ue_col - 8 - len(msg), 0)}|"

                print(_colorize_severity(line, evt.severity))

            print(f"    {'|':<{net_col - ue_col - 2}}{'|'}")

        print()


# ---- FailureAnalyzer ----

class FailureAnalyzer:
    """Failure/reject analysis view."""

    def render(self, proc: LogProcessor, events: List[SignalingEvent]) -> None:
        result = proc.result
        if not result:
            return

        print(_section_header("FAILURE & REJECT ANALYSIS"))

        failures = [e for e in events if e.severity == "critical"]
        warnings = [e for e in events if e.severity == "warning"]

        if not failures and not warnings:
            print(f"\n  {C.GREEN}No failures or rejects detected.{C.RESET}\n")
            return

        # Summary counts by category
        print(f"\n{C.BOLD}  Failure Summary:{C.RESET}")
        categories = defaultdict(int)
        for f in failures:
            cat = f.procedure_group or "Other"
            categories[cat] += 1
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
            print(f"    {C.RED}{cat:<30}: {cnt}{C.RESET}")

        # Failure rate
        total_events = len(events)
        if total_events > 0:
            fail_rate = len(failures) / total_events * 100
            print(f"\n  Failure rate: {fail_rate:.2f}% ({len(failures)}/{total_events})")

        # Reestablishment counts
        reest = [e for e in events if "Reestablishment" in e.message_type or "reestablishment" in e.message_type.lower()]
        if reest:
            reest_req = [e for e in reest if "Request" in e.message_type]
            reest_rej = [e for e in reest if "Reject" in e.message_type]
            print(f"\n{C.BOLD}  RRC Reestablishments:{C.RESET}")
            print(f"    Requests: {len(reest_req)}")
            print(f"    Rejects : {C.RED}{len(reest_rej)}{C.RESET}")

        # Detailed failure list
        print(f"\n{C.BOLD}  Detailed Failures:{C.RESET}")
        print(f"  {'TIME':<15} {'TECH':<5} {'LAYER':<10} {'MESSAGE':<35} {'CAUSE':<30} {'CONTEXT'}")
        print(f"  {'─' * 110}")

        for i, f in enumerate(failures):
            cause = f.cause_text if f.cause_text else ""
            if f.cause_code is not None:
                cause = f"#{f.cause_code}: {cause}"

            # Find preceding event for context
            context = ""
            all_sorted = sorted(events, key=lambda e: e.timestamp)
            idx = None
            for j, e in enumerate(all_sorted):
                if e is f:
                    idx = j
                    break
            if idx is not None and idx > 0:
                prev = all_sorted[idx - 1]
                context = f"after {prev.message_type}"

            # Signal quality at time of failure
            sig_ctx = self._signal_at_time(result, f.timestamp, f.tech)
            if sig_ctx:
                context += f" | {sig_ctx}"

            line = (
                f"  {_ts(f.timestamp):<15} {f.tech:<5} {f.layer:<10} "
                f"{f.message_type:<35} {cause:<30} {context}"
            )
            print(f"{C.RED}{line}{C.RESET}")

        # Warning events
        if warnings:
            print(f"\n{C.BOLD}  Warnings ({len(warnings)}):{C.RESET}")
            for w in warnings[:20]:  # cap at 20
                print(f"  {C.YELLOW}{_ts(w.timestamp)} {w.tech} {w.message_type}{C.RESET}")
            if len(warnings) > 20:
                print(f"  ... and {len(warnings) - 20} more warnings")

        print()

    @staticmethod
    def _signal_at_time(result: AnalysisResult, ts: datetime, tech: str) -> str:
        """Find nearest signal sample to given timestamp."""
        best = None
        best_delta = timedelta(hours=1)
        for s in result.signal_samples:
            if s.tech == tech:
                delta = abs(s.timestamp - ts)
                if delta < best_delta:
                    best_delta = delta
                    best = s
        if best and best.rsrp is not None:
            parts = [f"RSRP={best.rsrp:.1f}"]
            if best.sinr is not None:
                parts.append(f"SINR={best.sinr:.1f}")
            return " ".join(parts)
        return ""


# ---- MobilityAnalyzer ----

class MobilityAnalyzer:
    """Cell and handover tracking analysis."""

    def render(self, proc: LogProcessor, events: List[SignalingEvent]) -> None:
        result = proc.result
        if not result:
            return

        print(_section_header("MOBILITY & CELL ANALYSIS"))

        # Serving cell timeline
        print(f"\n{C.BOLD}  Serving Cell Timeline:{C.RESET}")
        cell_events = []
        for e in events:
            if e.pci is not None and e.layer == "RRC":
                cell_events.append(e)

        if not cell_events:
            print("    (no cell information available)")
        else:
            print(f"  {'TIME':<15} {'TECH':<5} {'PCI':<6} {'EARFCN':<8} {'BAND':<6} {'MODE':<6} {'EVENT'}")
            print(f"  {'─' * 80}")
            seen: List[Tuple[int, str]] = []
            for e in cell_events:
                key = (e.pci, e.tech)
                marker = ""
                if key not in seen:
                    marker = " [NEW CELL]"
                    seen.append(key)
                earfcn_str = str(e.earfcn) if e.earfcn is not None else ""
                print(
                    f"  {_ts(e.timestamp):<15} {e.tech:<5} {e.pci or '':<6} "
                    f"{earfcn_str:<8} {e.band:<6} {e.call_mode:<6} "
                    f"{e.message_type}{marker}"
                )

        # Dwell time per cell
        self._print_cell_stats(proc, events, result)

        # Handover events
        self._print_handover_events(events)

        # Band usage summary
        self._print_band_usage(events)

        # SA/NSA mode transitions
        self._print_mode_transitions(proc)

        print()

    def _print_cell_stats(
        self, proc: LogProcessor, events: List[SignalingEvent], result: AnalysisResult
    ) -> None:
        """Print per-cell statistics."""
        cell_visits: Dict[Tuple[str, int], List[SignalingEvent]] = defaultdict(list)
        for e in events:
            if e.pci is not None:
                cell_visits[(e.tech, e.pci)].append(e)

        if not cell_visits:
            return

        print(f"\n{C.BOLD}  Cell Statistics:{C.RESET}")
        print(f"    {'TECH':<5} {'PCI':<6} {'BAND':<6} {'EVENTS':>8} {'AVG RSRP':>10} {'AVG CQI':>10}")
        print(f"    {'─' * 55}")

        for (tech, pci), evts in sorted(cell_visits.items()):
            band = ""
            for e in evts:
                if e.band:
                    band = e.band
                    break

            # Find signal samples for this PCI
            rsrp_vals = [
                s.rsrp for s in result.signal_samples
                if s.tech == tech and s.pci == pci and s.rsrp is not None
            ]
            avg_rsrp = f"{mean(rsrp_vals):.1f}" if rsrp_vals else "N/A"

            # CQI per cell — use time overlap heuristic
            avg_cqi_str = "N/A"
            if tech == "LTE" and proc.cqi_samples:
                # Find CQI samples during time when this PCI was serving
                evt_times = [e.timestamp for e in evts]
                if evt_times:
                    t_start = min(evt_times)
                    t_end = max(evt_times)
                    cqis = [c for t, c in proc.cqi_samples if t_start <= t <= t_end]
                    if cqis:
                        avg_cqi_str = f"{mean(cqis):.1f}"

            print(f"    {tech:<5} {pci:<6} {band:<6} {len(evts):>8} {avg_rsrp:>10} {avg_cqi_str:>10}")

    def _print_handover_events(self, events: List[SignalingEvent]) -> None:
        """Identify and print handover events."""
        ho_events = []
        prev_pci: Dict[str, Optional[int]] = {}
        prev_earfcn: Dict[str, Optional[int]] = {}

        for e in events:
            if e.pci is None or e.layer != "RRC":
                continue
            tech = e.tech
            if tech in prev_pci and prev_pci[tech] is not None:
                if e.pci != prev_pci[tech]:
                    # PCI changed — handover
                    ho_type = "intra-freq"
                    if prev_earfcn.get(tech) and e.earfcn and prev_earfcn[tech] != e.earfcn:
                        ho_type = "inter-freq"
                    ho_events.append((e.timestamp, tech, prev_pci[tech], e.pci, ho_type, e.band))
            prev_pci[tech] = e.pci
            prev_earfcn[tech] = e.earfcn

        if ho_events:
            print(f"\n{C.BOLD}  Handover Events:{C.RESET}")
            print(f"    {'TIME':<15} {'TECH':<5} {'FROM PCI':<10} {'TO PCI':<10} {'TYPE':<12} {'BAND'}")
            print(f"    {'─' * 65}")
            for ts, tech, from_pci, to_pci, ho_type, band in ho_events:
                print(f"    {_ts(ts):<15} {tech:<5} {from_pci:<10} {to_pci:<10} {ho_type:<12} {band}")
            print(f"    Total handovers: {len(ho_events)}")

    def _print_band_usage(self, events: List[SignalingEvent]) -> None:
        """Print band usage summary with time per band."""
        band_events: Dict[str, List[datetime]] = defaultdict(list)
        for e in events:
            if e.band:
                band_events[e.band].append(e.timestamp)

        if not band_events:
            return

        print(f"\n{C.BOLD}  Band Usage Summary:{C.RESET}")
        print(f"    {'BAND':<8} {'EVENTS':>8} {'FIRST SEEN':<15} {'LAST SEEN':<15}")
        print(f"    {'─' * 55}")
        for band in sorted(band_events.keys()):
            timestamps = sorted(band_events[band])
            print(
                f"    {band:<8} {len(timestamps):>8} "
                f"{_ts(timestamps[0]):<15} {_ts(timestamps[-1]):<15}"
            )

    def _print_mode_transitions(self, proc: LogProcessor) -> None:
        """Print SA/NSA/LTE-only mode transitions."""
        all_ts = set()
        for t, _ in proc._lte_rrc_states:
            all_ts.add(t)
        for t, _ in proc._nr_rrc_states:
            all_ts.add(t)
        if not all_ts:
            return

        timestamps = sorted(all_ts)
        transitions = []
        prev_mode = ""
        for ts in timestamps:
            mode = proc._get_call_mode(ts)
            if mode and mode != prev_mode:
                transitions.append((ts, prev_mode, mode))
                prev_mode = mode

        if transitions:
            print(f"\n{C.BOLD}  Mode Transitions:{C.RESET}")
            print(f"    {'TIME':<15} {'FROM':<10} {'TO':<10}")
            print(f"    {'─' * 40}")
            for ts, from_m, to_m in transitions:
                from_str = from_m if from_m else "(none)"
                print(f"    {_ts(ts):<15} {from_str:<10} {to_m:<10}")


# ---- StateMachineRenderer ----

class StateMachineRenderer:
    """RRC and NAS state machine transition view."""

    def render(self, proc: LogProcessor, events: List[SignalingEvent]) -> None:
        result = proc.result
        if not result:
            return

        print(_section_header("STATE MACHINE VIEW"))

        # RRC state transitions
        for tech in ["LTE", "NR"]:
            timeline = proc._lte_rrc_states if tech == "LTE" else proc._nr_rrc_states
            if not timeline:
                continue

            print(f"\n{C.BOLD}  {tech} RRC State Transitions:{C.RESET}")
            print(f"    {'TIME':<15} {'FROM':<15} {'TO':<15} {'DURATION IN PREV'}")
            print(f"    {'─' * 65}")

            prev_state = ""
            prev_ts = None
            for ts, state in timeline:
                if prev_state and state != prev_state:
                    dur = ""
                    if prev_ts:
                        delta = (ts - prev_ts).total_seconds()
                        dur = self._fmt_duration(delta)
                    print(f"    {_ts(ts):<15} {prev_state:<15} {state:<15} {dur}")
                prev_state = state
                prev_ts = ts

            # Duration summary
            self._print_state_durations(tech, timeline)

            # ASCII state bar
            self._print_state_bar(tech, timeline)

        # NAS state events
        nas_states = [e for e in events if "State:" in e.message_type or "State:" in e.message_type]
        if nas_states:
            print(f"\n{C.BOLD}  NAS State Changes:{C.RESET}")
            print(f"    {'TIME':<15} {'TECH':<5} {'STATE'}")
            print(f"    {'─' * 50}")
            for e in nas_states:
                print(f"    {_ts(e.timestamp):<15} {e.tech:<5} {e.message_type}")

        print()

    def _print_state_durations(self, tech: str, timeline: List[Tuple[datetime, str]]) -> None:
        """Print how long UE spent in each state."""
        if len(timeline) < 2:
            return

        durations: Dict[str, float] = defaultdict(float)
        for i in range(len(timeline) - 1):
            ts, state = timeline[i]
            next_ts = timeline[i + 1][0]
            delta = (next_ts - ts).total_seconds()
            durations[state] += delta

        total = sum(durations.values())
        if total <= 0:
            return

        print(f"\n    {tech} RRC State Duration Summary:")
        for state in sorted(durations.keys()):
            dur = durations[state]
            pct = dur / total * 100
            print(f"      {state:<15}: {self._fmt_duration(dur):<15} ({pct:.1f}%)")

    def _print_state_bar(self, tech: str, timeline: List[Tuple[datetime, str]]) -> None:
        """Print ASCII state timeline bar."""
        if len(timeline) < 2:
            return

        total_time = (timeline[-1][0] - timeline[0][0]).total_seconds()
        if total_time <= 0:
            return

        bar_width = 60
        bar = []
        for i in range(len(timeline) - 1):
            ts, state = timeline[i]
            next_ts = timeline[i + 1][0]
            delta = (next_ts - ts).total_seconds()
            chars = max(1, int(delta / total_time * bar_width))
            if state == "Connected":
                bar.append(f"{C.GREEN}" + "█" * chars + f"{C.RESET}")
            elif state == "Idle":
                bar.append(f"{C.DIM}" + "░" * chars + f"{C.RESET}")
            else:
                bar.append(f"{C.YELLOW}" + "▒" * chars + f"{C.RESET}")

        print(f"\n    {tech} RRC State Timeline:")
        print(f"    [{''.join(bar)}]")
        print(f"    {C.GREEN}█=Connected{C.RESET}  {C.DIM}░=Idle{C.RESET}  {C.YELLOW}▒=Other{C.RESET}")

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        """Format seconds as human-readable duration."""
        if seconds < 1:
            return f"{seconds * 1000:.0f}ms"
        if seconds < 60:
            return f"{seconds:.1f}s"
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.0f}s"


# ---------------------------------------------------------------------------
# CSVExporter
# ---------------------------------------------------------------------------

class CSVExporter:
    """Export signaling events to CSV."""

    def export(self, events: List[SignalingEvent], outfile: str) -> None:
        fieldnames = [
            "timestamp", "tech", "layer", "direction", "channel",
            "message_type", "pci", "earfcn", "sfn", "band",
            "call_mode", "cause_code", "cause_text", "severity",
            "procedure_group",
        ]
        with open(outfile, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for evt in events:
                writer.writerow({
                    "timestamp": _ts_full(evt.timestamp),
                    "tech": evt.tech,
                    "layer": evt.layer,
                    "direction": evt.direction,
                    "channel": evt.channel,
                    "message_type": evt.message_type,
                    "pci": evt.pci if evt.pci is not None else "",
                    "earfcn": evt.earfcn if evt.earfcn is not None else "",
                    "sfn": evt.sfn if evt.sfn is not None else "",
                    "band": evt.band,
                    "call_mode": evt.call_mode,
                    "cause_code": evt.cause_code if evt.cause_code is not None else "",
                    "cause_text": evt.cause_text,
                    "severity": evt.severity,
                    "procedure_group": evt.procedure_group,
                })
        print(f"[INFO] Exported {len(events)} events to {outfile}")


# ---------------------------------------------------------------------------
# CLI — main
# ---------------------------------------------------------------------------

def parse_time(s: str) -> Optional[datetime]:
    """Parse a time string in various formats."""
    for fmt in ["%Y-%m-%d %H:%M:%S", "%H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def main():
    global C

    parser = argparse.ArgumentParser(
        description="UE Signaling Analyzer — LTE/NR signaling message analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s log.hdf                        # Default summary dashboard
  %(prog)s log.hdf --timeline             # Full chronological timeline
  %(prog)s log.hdf --ladder               # Protocol ladder diagram
  %(prog)s log.hdf --failures             # Failure/reject analysis
  %(prog)s log.hdf --mobility             # Cell & handover analysis
  %(prog)s log.hdf --states               # RRC/NAS state machine view
  %(prog)s log.hdf --all                  # Show all views
  %(prog)s log.hdf --csv events.csv       # Export to CSV
  %(prog)s log.hdf --timeline --filter-tech nr   # NR-only timeline
  %(prog)s log.hdf --timeline --filter-msg Reestablishment
""",
    )
    parser.add_argument("logfile", help="Qualcomm DIAG binary log file (.dlf/.isf/.hdf)")
    parser.add_argument("--summary", action="store_true", help="Dashboard overview (default)")
    parser.add_argument("--timeline", action="store_true", help="Full chronological message timeline")
    parser.add_argument("--ladder", action="store_true", help="Protocol ladder diagram")
    parser.add_argument("--failures", action="store_true", help="Failure/reject analysis")
    parser.add_argument("--mobility", action="store_true", help="Cell & handover analysis")
    parser.add_argument("--states", action="store_true", help="RRC/NAS state machine view")
    parser.add_argument("--all", action="store_true", help="Show all views")
    parser.add_argument("--csv", nargs="?", const="signaling_events.csv", metavar="OUTFILE",
                        help="Export events to CSV (default: signaling_events.csv)")
    parser.add_argument("--filter-tech", choices=["lte", "nr"], help="Filter by technology")
    parser.add_argument("--filter-msg", metavar="TEXT", help="Filter by message type substring")
    parser.add_argument("--time-range", nargs=2, metavar=("START", "END"),
                        help="Filter by time range (HH:MM:SS or YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose packet output")

    args = parser.parse_args()

    # Color setup
    if args.no_color or not sys.stdout.isatty():
        C = _NoColor()
    else:
        C = _AnsiColor()

    # Validate input file
    if not os.path.isfile(args.logfile):
        print(f"[ERROR] File not found: {args.logfile}")
        sys.exit(1)

    # Process log
    print(f"{C.BOLD}UE Signaling Analyzer{C.RESET}")
    print(f"Processing: {args.logfile}")
    print(f"{'─' * 60}")

    proc = LogProcessor(args.logfile, verbose=args.verbose)
    events = proc.process()

    if not events:
        print("[WARN] No signaling events found in log file.")
        sys.exit(0)

    print(f"Parsed {len(events)} signaling events.")

    # Apply filters
    time_start = None
    time_end = None
    if args.time_range:
        time_start = parse_time(args.time_range[0])
        time_end = parse_time(args.time_range[1])
        if not time_start or not time_end:
            print("[WARN] Could not parse time range, ignoring filter.")
            time_start = time_end = None

    filtered = proc.filter_events(
        tech=args.filter_tech,
        msg_filter=args.filter_msg,
        time_start=time_start,
        time_end=time_end,
    )

    if len(filtered) != len(events):
        print(f"After filters: {len(filtered)} events.")

    # Determine which views to show
    show_summary = args.summary or args.all
    show_timeline = args.timeline or args.all
    show_ladder = args.ladder or args.all
    show_failures = args.failures or args.all
    show_mobility = args.mobility or args.all
    show_states = args.states or args.all

    # Default to summary if nothing else specified
    if not any([show_summary, show_timeline, show_ladder, show_failures,
                show_mobility, show_states, args.csv]):
        show_summary = True

    # Render views
    if show_summary:
        SummaryDashboard().render(proc, filtered)

    if show_timeline:
        TimelineRenderer().render(filtered)

    if show_ladder:
        LadderRenderer().render(filtered)

    if show_failures:
        FailureAnalyzer().render(proc, filtered)

    if show_mobility:
        MobilityAnalyzer().render(proc, filtered)

    if show_states:
        StateMachineRenderer().render(proc, filtered)

    # CSV export
    if args.csv:
        CSVExporter().export(filtered, args.csv)


if __name__ == "__main__":
    main()
