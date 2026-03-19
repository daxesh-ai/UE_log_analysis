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
from math import sqrt
from statistics import mean, median
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
    ThroughputSample,
    PHYSample,
    PowerSample,
    RACHEvent,
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
    LOG_LTE_ML1_SERV_CELL_MEAS_V2,
    LOG_LTE_ML1_PDSCH_STAT,
    LOG_LTE_RRC_SERV_CELL_INFO,
    LOG_LTE_PDCP_DL_STATS,
    LOG_LTE_PDCP_UL_STATS,
    LOG_NR_RRC_OTA,
    LOG_NR_RRC_OTA_ALT,
    LOG_NR_NAS_OTA,
    LOG_NR_RRC_STATE,
    LOG_NR_NAS_MM5G_STATE,
    LOG_NR_NAS_MM5G_STATE_ALT,
    LOG_NR_NAS_SM5G_OTA,
    LOG_NR_NAS_MM5G_OTA_PLAIN,
    LOG_NR_ML1_MEAS_DB,
    LOG_NR_ML1_SERV_CELL_BEAM,
    LOG_NR_ML1_PDSCH_STATUS,
    LOG_NR_ML1_PUSCH_POWER,
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
    RRC_RELEASE_CAUSES,
    RRC_REESTABLISH_CAUSES,
    RRC_REJECT_REASONS,
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


# NR Band → SCS mapping (typical deployment configs)
NR_BAND_SCS = {
    "n2": 15, "n5": 15, "n7": 15, "n8": 15, "n12": 15, "n14": 15,
    "n20": 15, "n25": 15, "n28": 15, "n29": 15, "n34": 15,
    "n38": 30, "n39": 30, "n41": 30, "n48": 30,
    "n66": 15, "n70": 30, "n71": 15, "n75": 15, "n76": 15,
    "n77": 30, "n78": 30, "n79": 30,
    "n260": 120, "n261": 120,
}

# NR Band → Duplex mode
NR_BAND_DUPLEX = {
    "n2": "FDD", "n5": "FDD", "n7": "FDD", "n8": "FDD", "n12": "FDD",
    "n14": "FDD", "n20": "FDD", "n25": "FDD", "n28": "FDD", "n29": "SDL",
    "n34": "TDD", "n38": "TDD", "n39": "TDD", "n41": "TDD",
    "n48": "TDD", "n66": "FDD", "n70": "FDD", "n71": "FDD",
    "n75": "SDL", "n76": "SDL",
    "n77": "TDD", "n78": "TDD", "n79": "TDD",
    "n260": "TDD", "n261": "TDD",
}


def nr_band_to_scs(band: str) -> Optional[int]:
    """Get typical subcarrier spacing (kHz) for an NR band."""
    return NR_BAND_SCS.get(band)


def scs_to_slots_per_frame(scs_khz: int) -> int:
    """Slots per 10ms frame for given SCS."""
    return {15: 10, 30: 20, 60: 40, 120: 80}.get(scs_khz, 0)


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

        # 2b. Auto-detect NR-ARFCN from NR packet payloads
        self._detect_nr_arfcn(packets, result)

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

    @staticmethod
    def _detect_nr_arfcn(
        packets: list, result: AnalysisResult
    ) -> None:
        """Scan NR packet payloads for NR-ARFCN values and backfill signal samples."""
        import struct as _st
        from collections import Counter as _Counter

        # Valid NR-ARFCN ranges for common bands
        def _is_valid_arfcn(v: int) -> bool:
            return (123400 <= v <= 178800 or 285400 <= v <= 440000
                    or 460000 <= v <= 800000 or 2016667 <= v <= 2200000)

        arfcn_counts: _Counter = _Counter()
        nr_pkts = [p for p in packets if 0xB800 <= p.log_code <= 0xB8FF]
        for p in nr_pkts[:2000]:  # cap scan for performance
            pl = p.payload
            for off in range(0, min(len(pl) - 4, 40), 4):
                try:
                    val = _st.unpack_from("<I", pl, off)[0]
                    if _is_valid_arfcn(val):
                        arfcn_counts[val] += 1
                except _st.error:
                    pass

        if not arfcn_counts:
            return

        # Use the most frequent valid ARFCN
        detected_arfcn = arfcn_counts.most_common(1)[0][0]

        # Backfill NR signal samples that have no ARFCN
        for s in result.signal_samples:
            if s.tech == "NR" and s.earfcn is None:
                s.earfcn = detected_arfcn

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

        all_sorted = sorted(events, key=lambda e: e.timestamp)
        event_index = {id(e): j for j, e in enumerate(all_sorted)}

        for f in failures:
            cause = f.cause_text if f.cause_text else ""
            if f.cause_code is not None:
                cause = f"#{f.cause_code}: {cause}"

            # Find preceding event for context
            context = ""
            idx = event_index.get(id(f))
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
            seen: set = set()
            for e in cell_events:
                key = (e.pci, e.tech)
                marker = ""
                if key not in seen:
                    marker = " [NEW CELL]"
                    seen.add(key)
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
        nas_states = [e for e in events if "State:" in e.message_type]
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
# RFOptimizationView — all-in-one RF engineering dashboard
# ---------------------------------------------------------------------------

# RF quality thresholds
_RSRP_BINS = [
    ("Excellent", -80, float("inf")),
    ("Good",      -100, -80),
    ("Fair",      -110, -100),
    ("Poor",      -120, -110),
    ("No Cov",    float("-inf"), -120),
]

_SINR_BINS = [
    ("Excellent", 20, float("inf")),
    ("Good",      10, 20),
    ("Fair",      0,  10),
    ("Poor",      -5, 0),
    ("Bad",       float("-inf"), -5),
]

_RSRQ_BINS = [
    ("Excellent", -10, float("inf")),
    ("Good",      -15, -10),
    ("Fair",      -20, -15),
    ("Poor",      float("-inf"), -20),
]


def _percentile(vals: List[float], pct: float) -> float:
    """Simple percentile (nearest-rank)."""
    if not vals:
        return 0.0
    s = sorted(vals)
    k = int(len(s) * pct / 100)
    k = min(k, len(s) - 1)
    return s[k]


def _stddev(vals: List[float]) -> float:
    """Population standard deviation."""
    if len(vals) < 2:
        return 0.0
    m = mean(vals)
    return sqrt(sum((v - m) ** 2 for v in vals) / len(vals))


def _bar(pct: float, width: int = 30) -> str:
    """ASCII bar of given percentage."""
    filled = int(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)


class RFOptimizationView:
    """Comprehensive RF optimization analysis — one view for all RF KPIs."""

    def render(self, proc: LogProcessor, events: List[SignalingEvent]) -> None:
        result = proc.result
        if not result:
            print("[WARN] No analysis result available.")
            return

        print(_section_header("RF OPTIMIZATION ANALYSIS"))

        self._kpi_summary(proc, events, result)
        self._nr_cell_info(result)
        self._coverage_distribution(result)
        self._per_cell_rf(result)
        self._beam_management(result)
        self._phy_layer_stats(result)
        self._ul_power_control(result)
        self._throughput_vs_rf(result)
        self._rach_performance(events, result)
        self._pci_analysis(result)
        self._interference_analysis(result)
        self._coverage_gaps(result)
        self._endc_tracking(events, result)
        self._neighbor_cells(result)
        self._handover_analysis(events, result)

    # ------------------------------------------------------------------ #
    # Section 1: KPI Summary
    # ------------------------------------------------------------------ #
    def _kpi_summary(
        self, proc: LogProcessor, events: List[SignalingEvent], result: AnalysisResult
    ) -> None:
        print(f"\n{C.BOLD}{C.CYAN}── RF KPI Summary ──{C.RESET}\n")

        for tech in ["LTE", "NR"]:
            samples = [s for s in result.signal_samples if s.tech == tech]
            if not samples:
                continue
            rsrp = [s.rsrp for s in samples if s.rsrp is not None]
            rsrq = [s.rsrq for s in samples if s.rsrq is not None]
            sinr = [s.sinr for s in samples if s.sinr is not None]

            print(f"  {C.BOLD}{tech} RF Measurements ({len(samples)} samples):{C.RESET}")
            print(f"    {'Metric':<8} {'Min':>8} {'Avg':>8} {'Max':>8} {'StdDev':>8} {'P5':>8} {'P50':>8} {'P95':>8}")
            print(f"    {'─' * 64}")
            for name, vals, unit in [("RSRP", rsrp, "dBm"), ("RSRQ", rsrq, "dB"), ("SINR", sinr, "dB")]:
                if vals:
                    print(
                        f"    {name:<8} {min(vals):>7.1f} {mean(vals):>7.1f} "
                        f"{max(vals):>7.1f} {_stddev(vals):>7.1f} "
                        f"{_percentile(vals, 5):>7.1f} {_percentile(vals, 50):>7.1f} "
                        f"{_percentile(vals, 95):>7.1f} {unit}"
                    )
            print()

        # Throughput KPIs
        if result.throughput_samples:
            print(f"  {C.BOLD}Throughput:{C.RESET}")
            for direction in ["DL", "UL"]:
                tp = [s.mbps for s in result.throughput_samples
                      if s.direction == direction and s.mbps > 0]
                if tp:
                    print(
                        f"    {direction:<4} Avg={mean(tp):>7.2f}  Peak={max(tp):>7.2f}  "
                        f"P5={_percentile(tp, 5):>7.2f}  P50={_percentile(tp, 50):>7.2f}  "
                        f"P95={_percentile(tp, 95):>7.2f} Mbps"
                    )
            print()

        # Event KPIs — use structured RACH events
        rach_msg1 = [e for e in result.rach_events if e.msg_stage == "Msg1"]
        rach_msg2 = [e for e in result.rach_events if e.msg_stage == "Msg2"]
        rach_total = len(rach_msg1)
        rach_ok = len(rach_msg2)

        setup_req = sum(1 for e in events if "RRCConnectionRequest" in e.message_type or "RRCSetupRequest" in e.message_type)
        setup_ok = sum(1 for e in events if "RRCConnectionSetup" in e.message_type or "RRCSetupComplete" in e.message_type)

        ho_count = sum(1 for e in events if "Reconfiguration" in e.message_type)
        reest_count = sum(1 for e in events if "Reestablishment" in e.message_type and "Request" in e.message_type)
        nas_rej = sum(1 for e in events if e.severity == "critical" and "NAS" in e.layer)

        print(f"  {C.BOLD}Event KPIs:{C.RESET}")
        if rach_total > 0:
            print(f"    RACH Msg1→Msg2     : {rach_ok}/{rach_total} ({rach_ok / rach_total * 100:.1f}%)")
        elif rach_msg2:
            print(f"    RACH Msg2 (RAR)    : {len(rach_msg2)} received")
        if setup_req > 0:
            rate = setup_ok / setup_req * 100 if setup_req else 0
            print(f"    RRC Setup Success   : {setup_ok}/{setup_req} ({rate:.1f}%)")
        print(f"    Handovers (Reconfig): {ho_count}")
        print(f"    RRC Reestablishments: {C.YELLOW}{reest_count}{C.RESET}")
        print(f"    NAS Rejects         : {C.RED}{nas_rej}{C.RESET}")
        print()

    # ------------------------------------------------------------------ #
    # Section 1b: NR / LTE Cell Info
    # ------------------------------------------------------------------ #
    def _nr_cell_info(self, result: AnalysisResult) -> None:
        """Show NR and LTE cell configuration: PCI, ARFCN, Band, SCS, Slot Config."""
        # Collect cell info from signal samples and RRC events
        nr_samples = [s for s in result.signal_samples if s.tech == "NR"]
        lte_samples = [s for s in result.signal_samples if s.tech == "LTE"]
        nr_rrc = [e for e in result.rrc_events if e.tech == "NR"]
        lte_rrc = [e for e in result.rrc_events if e.tech == "LTE"]

        if not nr_samples and not lte_samples and not nr_rrc and not lte_rrc:
            return

        print(f"\n{C.BOLD}{C.CYAN}── Cell Configuration ──{C.RESET}\n")

        for tech, samples, rrc_evts in [("NR", nr_samples, nr_rrc), ("LTE", lte_samples, lte_rrc)]:
            # Collect unique PCIs
            pcis_from_sig = set(s.pci for s in samples if s.pci is not None)
            pcis_from_rrc = set(e.pci for e in rrc_evts if e.pci is not None)
            all_pcis = pcis_from_sig | pcis_from_rrc

            # Collect ARFCNs
            arfcns_from_sig = set(s.earfcn for s in samples if s.earfcn is not None)
            arfcns_from_rrc = set(e.earfcn for e in rrc_evts if e.earfcn is not None)
            all_arfcns = arfcns_from_sig | arfcns_from_rrc

            # Get SFNs from RRC
            sfns = [e.sfn for e in rrc_evts if e.sfn is not None]

            if not all_pcis and not all_arfcns:
                continue

            print(f"  {C.BOLD}{tech} Serving Cell:{C.RESET}")

            # PCI
            serving_pci = None
            if all_pcis:
                # Most frequent PCI = serving
                pci_counts: Dict[int, int] = defaultdict(int)
                for s in samples:
                    if s.pci is not None:
                        pci_counts[s.pci] += 1
                for e in rrc_evts:
                    if e.pci is not None:
                        pci_counts[e.pci] += 1
                serving_pci = max(pci_counts, key=pci_counts.get) if pci_counts else None
                print(f"    PCI              : {serving_pci}")
                if len(all_pcis) > 1:
                    print(f"    All PCIs seen    : {sorted(all_pcis)}")

            # ARFCN
            serving_arfcn = None
            if all_arfcns:
                serving_arfcn = next(iter(all_arfcns))
                print(f"    {'NR-ARFCN' if tech == 'NR' else 'EARFCN':<17}: {serving_arfcn}")

            # Band
            band = ""
            if serving_arfcn is not None:
                band = earfcn_to_band(serving_arfcn, tech)
            if band:
                print(f"    Band             : {band}")

                if tech == "NR":
                    # SCS
                    scs = nr_band_to_scs(band)
                    if scs:
                        print(f"    Subcarrier Spacing: {scs} kHz")
                        # Slot config
                        slots_per_frame = scs_to_slots_per_frame(scs)
                        print(f"    Slots/Frame      : {slots_per_frame} (10ms frame)")
                        slot_dur_ms = 1.0 / (scs / 15.0)
                        print(f"    Slot Duration    : {slot_dur_ms:.3f} ms")

                    # Duplex
                    duplex = NR_BAND_DUPLEX.get(band, "")
                    if duplex:
                        print(f"    Duplex Mode      : {duplex}")
                        if duplex == "TDD":
                            print(f"    TDD Pattern      : (check RRC Reconfig for tdd-UL-DL-Config)")

            # SSB info for NR
            if tech == "NR" and nr_samples:
                beam_ids = set(s.beam_id for s in nr_samples if s.beam_id is not None)
                if beam_ids:
                    print(f"    SSB Beams seen   : {len(beam_ids)} (indices: {sorted(beam_ids)})")

                    # SSB periodicity estimate from timestamps
                    beam_times = sorted(s.timestamp for s in nr_samples if s.beam_id is not None)
                    if len(beam_times) >= 3:
                        deltas = [(beam_times[i+1] - beam_times[i]).total_seconds()
                                  for i in range(min(len(beam_times)-1, 20))]
                        deltas = [d for d in deltas if 0.005 < d < 1.0]
                        if deltas:
                            est_period = median(deltas)
                            print(f"    SSB Periodicity  : ~{est_period*1000:.0f} ms (estimated)")

            # SFN range
            if sfns:
                print(f"    SFN Range        : {min(sfns)} — {max(sfns)}")

            # Sample count
            print(f"    Signal Samples   : {len(samples)}")
            print()

    # ------------------------------------------------------------------ #
    # Section 2: Coverage Distribution
    # ------------------------------------------------------------------ #
    def _coverage_distribution(self, result: AnalysisResult) -> None:
        print(f"\n{C.BOLD}{C.CYAN}── RF Coverage Distribution ──{C.RESET}\n")

        for tech in ["LTE", "NR"]:
            samples = [s for s in result.signal_samples if s.tech == tech]
            if not samples:
                continue

            print(f"  {C.BOLD}{tech}:{C.RESET}")
            rsrp = [s.rsrp for s in samples if s.rsrp is not None]
            sinr = [s.sinr for s in samples if s.sinr is not None]
            rsrq = [s.rsrq for s in samples if s.rsrq is not None]

            for label, vals, bins in [("RSRP", rsrp, _RSRP_BINS), ("SINR", sinr, _SINR_BINS), ("RSRQ", rsrq, _RSRQ_BINS)]:
                if not vals:
                    continue
                total = len(vals)
                print(f"    {label} Distribution:")
                for name, lo, hi in bins:
                    cnt = sum(1 for v in vals if lo <= v < hi)
                    pct = cnt / total * 100
                    color = C.GREEN if name == "Excellent" else C.GREEN if name == "Good" else C.YELLOW if name == "Fair" else C.RED
                    print(f"      {color}{name:<10}{C.RESET} {_bar(pct)} {cnt:>6} ({pct:5.1f}%)")
                print()

    # ------------------------------------------------------------------ #
    # Section 3: Per-Cell RF Performance
    # ------------------------------------------------------------------ #
    def _per_cell_rf(self, result: AnalysisResult) -> None:
        print(f"\n{C.BOLD}{C.CYAN}── Per-Cell RF Performance ──{C.RESET}\n")

        # Group signal samples by (tech, pci)
        cells: Dict[Tuple[str, int], List[SignalSample]] = defaultdict(list)
        for s in result.signal_samples:
            if s.pci is not None:
                cells[(s.tech, s.pci)].append(s)

        if not cells:
            print("  (no per-cell data available)")
            return

        print(
            f"  {'Tech':<5} {'PCI':<6} {'Band':<6} {'EARFCN':<8} {'#Samp':>6}  "
            f"{'RSRP min':>9} {'avg':>7} {'max':>7}  "
            f"{'SINR min':>9} {'avg':>7} {'max':>7}"
        )
        print(f"  {'─' * 95}")

        for (tech, pci), samps in sorted(cells.items(), key=lambda x: -len(x[1])):
            rsrp = [s.rsrp for s in samps if s.rsrp is not None]
            sinr = [s.sinr for s in samps if s.sinr is not None]
            earfcn = next((s.earfcn for s in samps if s.earfcn is not None), None)
            band = earfcn_to_band(earfcn, tech) if earfcn is not None else ""
            earfcn_str = str(earfcn) if earfcn is not None else ""

            rsrp_str = f"{min(rsrp):>8.1f} {mean(rsrp):>7.1f} {max(rsrp):>7.1f}" if rsrp else f"{'N/A':>8} {'':>7} {'':>7}"
            sinr_str = f"{min(sinr):>8.1f} {mean(sinr):>7.1f} {max(sinr):>7.1f}" if sinr else f"{'N/A':>8} {'':>7} {'':>7}"

            # Color by average RSRP
            color = C.RESET
            if rsrp:
                avg_r = mean(rsrp)
                if avg_r < -120:
                    color = C.RED
                elif avg_r < -110:
                    color = C.YELLOW

            print(f"  {color}{tech:<5} {pci:<6} {band:<6} {earfcn_str:<8} {len(samps):>6}  {rsrp_str}  {sinr_str}{C.RESET}")

        print()

    # ------------------------------------------------------------------ #
    # Section 4a: NR Beam Performance (0xB821)
    # ------------------------------------------------------------------ #
    def _beam_management(self, result: AnalysisResult) -> None:
        beam_samples = [s for s in result.signal_samples if s.beam_id is not None]
        if not beam_samples:
            return

        print(f"\n{C.BOLD}{C.CYAN}── NR Beam Performance (0xB821) ──{C.RESET}\n")

        # --- Timeline view (most recent 30 rows) ---
        beam_timeline = sorted(beam_samples, key=lambda s: s.timestamp)
        print(f"  {C.BOLD}Beam Measurement Timeline (last 30):{C.RESET}")
        print(f"  {'Timestamp':<16} {'PCI':<6} {'SSB Idx':<8} {'RSRP (dBm)':>11} {'RSRQ (dB)':>10} {'SINR (dB)':>10} {'Best?'}")
        print(f"  {'─' * 75}")

        # For each timestamp, find the best beam (highest SINR)
        ts_groups: Dict[str, List[SignalSample]] = defaultdict(list)
        for s in beam_timeline:
            ts_key = _ts(s.timestamp)
            ts_groups[ts_key].append(s)

        display_rows: List[Tuple[SignalSample, bool]] = []
        for ts_key in ts_groups:
            group = ts_groups[ts_key]
            best = max(group, key=lambda s: s.sinr if s.sinr is not None else -999)
            for s in group:
                is_best = (s is best)
                display_rows.append((s, is_best))

        for s, is_best in display_rows[-30:]:
            rsrp_str = f"{s.rsrp:.1f}" if s.rsrp is not None else "N/A"
            rsrq_str = f"{s.rsrq:.1f}" if s.rsrq is not None else "N/A"
            sinr_str = f"{s.sinr:.1f}" if s.sinr is not None else "N/A"
            pci_str = str(s.pci) if s.pci is not None else ""
            best_marker = f"{C.GREEN}*best*{C.RESET}" if is_best and len(ts_groups.get(_ts(s.timestamp), [])) > 1 else ""
            print(f"  {_ts(s.timestamp):<16} {pci_str:<6} {s.beam_id:<8} {rsrp_str:>11} {rsrq_str:>10} {sinr_str:>10} {best_marker}")

        # --- Per-beam summary ---
        beams: Dict[int, List[SignalSample]] = defaultdict(list)
        for s in beam_samples:
            beams[s.beam_id].append(s)

        print(f"\n  {C.BOLD}Per-Beam Summary:{C.RESET}")
        print(f"  {'SSB Idx':<8} {'PCI':<6} {'Samples':>8} {'Avg RSRP':>9} {'Avg SINR':>9}")
        print(f"  {'─' * 45}")
        for beam_id in sorted(beams.keys()):
            samps = beams[beam_id]
            rsrp = [s.rsrp for s in samps if s.rsrp is not None]
            sinr = [s.sinr for s in samps if s.sinr is not None]
            pci_val = next((s.pci for s in samps if s.pci is not None), None)
            pci_str = str(pci_val) if pci_val is not None else ""
            avg_rsrp = f"{mean(rsrp):.1f}" if rsrp else "N/A"
            avg_sinr = f"{mean(sinr):.1f}" if sinr else "N/A"
            print(f"  {beam_id:<8} {pci_str:<6} {len(samps):>8} {avg_rsrp:>9} {avg_sinr:>9}")

        # Beam switch stats + stuck beam detection
        switches = 0
        stuck_count = 0
        prev_beam = None
        for ts_key in ts_groups:
            group = ts_groups[ts_key]
            if len(group) < 2:
                continue
            best = max(group, key=lambda s: s.sinr if s.sinr is not None else -999)
            # Check: is UE on a weaker beam? (first beam in group = serving)
            serving = group[0]
            if (best.beam_id != serving.beam_id
                    and best.sinr is not None and serving.sinr is not None
                    and best.sinr - serving.sinr > 3.0):
                stuck_count += 1

        prev_beam = None
        for s in beam_timeline:
            if prev_beam is not None and s.beam_id != prev_beam:
                switches += 1
            prev_beam = s.beam_id

        print(f"\n  Beam switches     : {switches}")
        dominant = max(beams.keys(), key=lambda b: len(beams[b]))
        dom_pct = len(beams[dominant]) / len(beam_samples) * 100
        print(f"  Dominant beam     : SSB {dominant} ({dom_pct:.1f}% of samples)")
        if stuck_count > 0:
            print(f"  {C.YELLOW}→ RF Insight: {stuck_count} instances where UE was NOT on best beam (>3dB SINR gap)")
            print(f"    Check beam sweeping efficiency and beam management thresholds{C.RESET}")
        print()

    # ------------------------------------------------------------------ #
    # Section 4b: DL Throughput & Efficiency (0xB822 — MCS/MIMO/BLER)
    # ------------------------------------------------------------------ #
    def _phy_layer_stats(self, result: AnalysisResult) -> None:
        if not result.phy_samples:
            return

        print(f"\n{C.BOLD}{C.CYAN}── DL Throughput & Efficiency (0xB822) ──{C.RESET}\n")

        for tech in ["NR", "LTE"]:
            for direction in ["DL", "UL"]:
                samples = [s for s in result.phy_samples
                           if s.tech == tech and s.direction == direction]
                if not samples:
                    continue

                print(f"  {C.BOLD}{tech} {direction}:{C.RESET}")

                # --- Per-slot detail (last 20 rows) ---
                recent = samples[-20:]
                has_tbs = any(s.tbs is not None for s in recent)
                if has_tbs:
                    print(f"    {'Slot/SFN':<12} {'Layers':>7} {'MCS':>5} {'Modulation':<10} {'TBS (B)':>8} {'BLER (%)':>9}")
                    print(f"    {'─' * 60}")
                else:
                    print(f"    {'Timestamp':<16} {'Layers':>7} {'MCS':>5} {'Modulation':<10} {'BLER (%)':>9}")
                    print(f"    {'─' * 55}")

                prev_mod = None
                for s in recent:
                    mod = s.modulation or ""
                    layers_str = str(s.rank) if s.rank else ""
                    mcs_str = str(s.mcs) if s.mcs is not None else ""
                    bler_str = f"{s.bler * 100:.1f}" if s.bler is not None else ""
                    tbs_str = str(s.tbs) if s.tbs is not None else ""

                    # Color: high BLER red, modulation drop yellow
                    color = C.RESET
                    insight = ""
                    if s.bler is not None and s.bler > 0.10:
                        color = C.RED
                        if s.mcs is not None and s.mcs >= 20:
                            insight = f" {C.RED}← aggressive MCS with high BLER{C.RESET}"
                    if prev_mod and mod and prev_mod in ("256QAM", "64QAM") and mod in ("QPSK", "16QAM"):
                        if not insight:
                            insight = f" {C.YELLOW}← modulation drop{C.RESET}"

                    if has_tbs:
                        sfn_str = ""
                        if s.slot is not None and s.sfn is not None:
                            sfn_str = f"{s.slot}/{s.sfn}"
                        elif s.sfn is not None:
                            sfn_str = f"-/{s.sfn}"
                        print(
                            f"    {color}{sfn_str:<12} {layers_str:>7} {mcs_str:>5} "
                            f"{mod:<10} {tbs_str:>8} {bler_str:>9}{C.RESET}{insight}"
                        )
                    else:
                        print(
                            f"    {color}{_ts(s.timestamp):<16} {layers_str:>7} {mcs_str:>5} "
                            f"{mod:<10} {bler_str:>9}{C.RESET}{insight}"
                        )
                    prev_mod = mod

                # --- Aggregate stats ---
                mcs_vals = [s.mcs for s in samples if s.mcs is not None]
                if mcs_vals:
                    total = len(mcs_vals)
                    print(f"\n    {C.BOLD}MCS Summary ({total} samples):{C.RESET}")
                    print(f"      Avg={mean(mcs_vals):.1f}  P5={_percentile(mcs_vals, 5):.0f}  P50={_percentile(mcs_vals, 50):.0f}  P95={_percentile(mcs_vals, 95):.0f}")
                    # Modulation breakdown
                    mod_counts: Dict[str, int] = defaultdict(int)
                    for s in samples:
                        if s.mcs is not None:
                            mod_counts[s.modulation] += 1
                    for mod_name in ["256QAM", "64QAM", "16QAM", "QPSK"]:
                        cnt = mod_counts.get(mod_name, 0)
                        pct = cnt / total * 100 if total else 0
                        if cnt > 0:
                            print(f"      {mod_name:<8}: {cnt:>6} ({pct:5.1f}%) {_bar(pct, 20)}")

                # MIMO Rank distribution
                rank_vals = [s.rank for s in samples if s.rank is not None]
                if rank_vals:
                    rank_counts: Dict[int, int] = defaultdict(int)
                    for r in rank_vals:
                        rank_counts[r] += 1
                    total_r = len(rank_vals)
                    print(f"\n    {C.BOLD}MIMO Layers / Rank Indicator ({total_r} samples):{C.RESET}")
                    for r in sorted(rank_counts.keys()):
                        cnt = rank_counts[r]
                        pct = cnt / total_r * 100
                        print(f"      {r} Layer{'s' if r > 1 else ' '}: {cnt:>6} ({pct:5.1f}%) {_bar(pct, 20)}")

                # BLER
                bler_vals = [s.bler for s in samples if s.bler is not None]
                if bler_vals:
                    avg_bler = mean(bler_vals) * 100
                    max_bler = max(bler_vals) * 100
                    p95_bler = _percentile(bler_vals, 95) * 100
                    color = C.GREEN if avg_bler < 2 else C.YELLOW if avg_bler < 10 else C.RED
                    print(f"\n    {C.BOLD}BLER:{C.RESET} {color}Avg={avg_bler:.2f}%  Max={max_bler:.1f}%  P95={p95_bler:.1f}%{C.RESET}")
                    # Insight: high BLER + high MCS = aggressive link adaptation
                    high_bler_high_mcs = sum(
                        1 for s in samples
                        if s.bler is not None and s.bler > 0.10
                        and s.mcs is not None and s.mcs >= 20
                    )
                    if high_bler_high_mcs > 0:
                        print(f"    {C.RED}→ RF Insight: {high_bler_high_mcs} slots with BLER >10% + MCS >=20")
                        print(f"      Network is too aggressive — causes retransmissions. Check SINR or OLLA.{C.RESET}")
                    # Insight: modulation drops to QPSK
                    qpsk_with_bler = sum(
                        1 for s in samples
                        if s.modulation == "QPSK" and s.bler is not None and s.bler > 0.10
                    )
                    if qpsk_with_bler > 0:
                        print(f"    {C.RED}→ RF Insight: {qpsk_with_bler} slots at QPSK with >10% BLER")
                        print(f"      Likely interference or rapid SINR drop.{C.RESET}")

                # RB + TBS utilization
                rb_vals = [s.num_rbs for s in samples if s.num_rbs is not None]
                tbs_vals = [s.tbs for s in samples if s.tbs is not None]
                if rb_vals or tbs_vals:
                    parts = []
                    if rb_vals:
                        parts.append(f"RBs: Avg={mean(rb_vals):.0f} Max={max(rb_vals)}")
                    if tbs_vals:
                        parts.append(f"TBS: Avg={mean(tbs_vals):.0f}B Max={max(tbs_vals)}B")
                    print(f"\n    {C.BOLD}Resources:{C.RESET} {'  |  '.join(parts)}")

                print()

    # ------------------------------------------------------------------ #
    # Section 4c: UL Power Control (0xB823)
    # ------------------------------------------------------------------ #
    def _ul_power_control(self, result: AnalysisResult) -> None:
        if not result.power_samples:
            return

        print(f"\n{C.BOLD}{C.CYAN}── UL Power Control (0xB823) ──{C.RESET}\n")

        for tech in ["NR", "LTE"]:
            samples = [s for s in result.power_samples if s.tech == tech]
            if not samples:
                continue

            print(f"  {C.BOLD}{tech} ({len(samples)} samples):{C.RESET}")

            # Tx Power
            tx_vals = [s.tx_power for s in samples if s.tx_power is not None]
            if tx_vals:
                print(f"    Tx Power   : Min={min(tx_vals):>6.1f}  Avg={mean(tx_vals):>6.1f}  Max={max(tx_vals):>6.1f} dBm")
                high_power = sum(1 for v in tx_vals if v > 20)
                if high_power > 0:
                    pct = high_power / len(tx_vals) * 100
                    print(f"    {C.YELLOW}→ RF Insight: {pct:.1f}% at Tx >20 dBm (near max power — cell edge/coverage limited UL){C.RESET}")

            # Power Headroom
            ph_vals = [s.power_headroom for s in samples if s.power_headroom is not None]
            if ph_vals:
                print(f"    Headroom   : Min={min(ph_vals):>6.1f}  Avg={mean(ph_vals):>6.1f}  Max={max(ph_vals):>6.1f} dB")
                low_headroom = sum(1 for v in ph_vals if v < 3)
                if low_headroom > 0:
                    pct = low_headroom / len(ph_vals) * 100
                    color = C.RED if pct > 20 else C.YELLOW
                    print(f"    {color}→ RF Insight: {pct:.1f}% with headroom <3 dB — UL power limited, expect UL throughput degradation{C.RESET}")

            # Pathloss
            pl_vals = [s.pathloss for s in samples if s.pathloss is not None]
            if pl_vals:
                print(f"    Pathloss   : Min={min(pl_vals):>6.1f}  Avg={mean(pl_vals):>6.1f}  Max={max(pl_vals):>6.1f} dB")

            print()

    # ------------------------------------------------------------------ #
    # Section 4d: NSA EN-DC / SA Tracking
    # ------------------------------------------------------------------ #
    def _endc_tracking(self, events: List[SignalingEvent], result: AnalysisResult) -> None:
        # Detect EN-DC setup from RRC Reconfiguration events + NR activity
        reconfigs = [e for e in events if "Reconfiguration" in e.message_type and e.tech == "LTE"]
        nr_connects = [e for e in events if e.tech == "NR" and "Connected" in e.message_type]
        scg_failures = [a for a in result.anomalies if "scg" in a.description.lower() or "scg" in a.category.lower()]

        if not reconfigs and not nr_connects:
            return

        print(f"\n{C.BOLD}{C.CYAN}── NSA EN-DC / SA Tracking ──{C.RESET}\n")

        # EN-DC setup attempts: LTE Reconfig followed by NR activity
        endc_setups: List[Dict[str, Any]] = []
        for rc in reconfigs:
            # Look for NR activity within 2 seconds after Reconfig
            for nr_evt in events:
                if nr_evt.tech == "NR" and nr_evt.layer == "RRC":
                    delta = (nr_evt.timestamp - rc.timestamp).total_seconds()
                    if 0 < delta < 2.0:
                        nr_pci = nr_evt.pci
                        nr_earfcn = nr_evt.earfcn
                        nr_band = nr_evt.band
                        endc_setups.append({
                            "timestamp": rc.timestamp,
                            "lte_pci": rc.pci,
                            "nr_pci": nr_pci,
                            "nr_arfcn": nr_earfcn,
                            "nr_band": nr_band,
                            "nr_event": nr_evt.message_type,
                        })
                        break

        if endc_setups:
            print(f"  {C.BOLD}EN-DC Setup Events:{C.RESET}")
            print(f"  {'TIME':<15} {'LTE PCI':<9} {'NR PCI':<8} {'NR-ARFCN':<10} {'Band':<6} {'NR Event'}")
            print(f"  {'─' * 70}")
            for s in endc_setups:
                lte_pci = str(s["lte_pci"]) if s["lte_pci"] is not None else ""
                nr_pci = str(s["nr_pci"]) if s["nr_pci"] is not None else ""
                arfcn = str(s["nr_arfcn"]) if s["nr_arfcn"] is not None else ""
                band = s.get("nr_band", "") or ""
                print(f"  {_ts(s['timestamp']):<15} {lte_pci:<9} {nr_pci:<8} {arfcn:<10} {band:<6} {s['nr_event']}")

        # SCG failures
        if scg_failures:
            print(f"\n  {C.RED}SCG Failures: {len(scg_failures)}{C.RESET}")
            for f in scg_failures[:5]:
                print(f"  {C.RED}  {_ts(f.timestamp)} {f.description}{C.RESET}")
            if len(scg_failures) > 5:
                print(f"  ... and {len(scg_failures) - 5} more")
            print(f"  {C.RED}→ RF Insight: SCG failures — check RACH config, timer values, or NR signal quality{C.RESET}")

        # SA registration events
        sa_regs = [e for e in events if e.tech == "NR" and e.layer != "RRC"
                   and ("Registration" in e.message_type or "PDU Session" in e.message_type)]
        if sa_regs:
            print(f"\n  {C.BOLD}SA Registration / PDU Session Events:{C.RESET}")
            for e in sa_regs[:10]:
                color = C.RED if e.severity == "critical" else C.GREEN
                cause = f" — {e.cause_text}" if e.cause_text else ""
                print(f"  {color}  {_ts(e.timestamp)} {e.direction} {e.message_type}{cause}{C.RESET}")

        print()

    # ------------------------------------------------------------------ #
    # Section 4e: Neighbor Cell RSRP
    # ------------------------------------------------------------------ #
    def _neighbor_cells(self, result: AnalysisResult) -> None:
        # Group signal samples by PCI, identify serving vs neighbors
        if not result.signal_samples:
            return

        pci_samples: Dict[Tuple[str, int], List[SignalSample]] = defaultdict(list)
        for s in result.signal_samples:
            if s.pci is not None:
                pci_samples[(s.tech, s.pci)].append(s)

        if len(pci_samples) < 2:
            return  # need at least 2 cells

        print(f"\n{C.BOLD}{C.CYAN}── Neighbor Cell RSRP (Handover Tuning) ──{C.RESET}\n")

        for tech in ["LTE", "NR"]:
            cells = {k: v for k, v in pci_samples.items() if k[0] == tech}
            if len(cells) < 2:
                continue

            # Serving cell = most samples
            serving_key = max(cells.keys(), key=lambda k: len(cells[k]))
            serving_pci = serving_key[1]
            serving_rsrp = [s.rsrp for s in cells[serving_key] if s.rsrp is not None]

            print(f"  {C.BOLD}{tech} — Serving PCI {serving_pci} (Avg RSRP: {mean(serving_rsrp):.1f} dBm):{C.RESET}")
            print(f"    {'PCI':<6} {'EARFCN':<8} {'Band':<6} {'Samples':>8} {'RSRP avg':>9} {'RSRP max':>9} {'Δ to Serv':>10}")
            print(f"    {'─' * 62}")

            serving_avg = mean(serving_rsrp) if serving_rsrp else -120

            for (t, pci), samps in sorted(cells.items(), key=lambda x: -len(x[1])):
                if (t, pci) == serving_key:
                    continue  # skip serving
                rsrp = [s.rsrp for s in samps if s.rsrp is not None]
                if not rsrp:
                    continue
                earfcn = next((s.earfcn for s in samps if s.earfcn is not None), None)
                band = earfcn_to_band(earfcn, tech) if earfcn is not None else ""
                earfcn_str = str(earfcn) if earfcn is not None else ""
                avg_r = mean(rsrp)
                delta = avg_r - serving_avg
                delta_color = C.YELLOW if abs(delta) < 6 else C.RESET
                print(
                    f"    {pci:<6} {earfcn_str:<8} {band:<6} {len(samps):>8} "
                    f"{avg_r:>9.1f} {max(rsrp):>9.1f} {delta_color}{delta:>+9.1f} dB{C.RESET}"
                )

            # Insight: neighbor within 6dB of serving
            close_neighbors = []
            for (t, pci), samps in cells.items():
                if (t, pci) == serving_key:
                    continue
                rsrp = [s.rsrp for s in samps if s.rsrp is not None]
                if rsrp and abs(mean(rsrp) - serving_avg) < 6:
                    close_neighbors.append(pci)

            if close_neighbors:
                print(f"\n    {C.YELLOW}→ RF Insight: PCI {close_neighbors} within 6 dB of serving — check HO thresholds (A3/A5/B1){C.RESET}")

        print()

    # ------------------------------------------------------------------ #
    # Section 5: Throughput vs RF Correlation
    # ------------------------------------------------------------------ #
    def _throughput_vs_rf(self, result: AnalysisResult) -> None:
        if not result.throughput_samples or not result.signal_samples:
            return

        print(f"\n{C.BOLD}{C.CYAN}── Throughput vs RF Correlation ──{C.RESET}\n")

        # Build sorted signal timeline for quick nearest-neighbor lookup
        sig_sorted = sorted(result.signal_samples, key=lambda s: s.timestamp)
        sig_times = [s.timestamp for s in sig_sorted]

        rsrp_ranges = [
            ("> -80",  -80, float("inf")),
            ("-100..-80", -100, -80),
            ("-110..-100", -110, -100),
            ("< -110", float("-inf"), -110),
        ]

        sinr_ranges = [
            ("> 20",   20, float("inf")),
            ("10..20", 10, 20),
            ("0..10",  0,  10),
            ("< 0",    float("-inf"), 0),
        ]

        for direction in ["DL", "UL"]:
            tp_samples = [s for s in result.throughput_samples
                          if s.direction == direction and s.mbps > 0]
            if not tp_samples:
                continue

            # Map each throughput sample to nearest signal sample
            tp_with_rf: List[Tuple[ThroughputSample, SignalSample]] = []
            for tp in tp_samples:
                idx = self._bisect_nearest(sig_times, tp.timestamp)
                if idx is not None:
                    sig = sig_sorted[idx]
                    delta = abs((sig.timestamp - tp.timestamp).total_seconds())
                    if delta < 5.0:  # within 5 seconds
                        tp_with_rf.append((tp, sig))

            if not tp_with_rf:
                continue

            print(f"  {C.BOLD}{direction} Throughput by RSRP:{C.RESET}")
            print(f"    {'RSRP Range':<14} {'Samples':>8} {'Avg Mbps':>10} {'P50 Mbps':>10} {'P95 Mbps':>10}")
            print(f"    {'─' * 55}")
            for name, lo, hi in rsrp_ranges:
                mbps_vals = [tp.mbps for tp, sig in tp_with_rf
                             if sig.rsrp is not None and lo <= sig.rsrp < hi]
                if mbps_vals:
                    print(
                        f"    {name:<14} {len(mbps_vals):>8} {mean(mbps_vals):>10.2f} "
                        f"{_percentile(mbps_vals, 50):>10.2f} {_percentile(mbps_vals, 95):>10.2f}"
                    )
            print()

            print(f"  {C.BOLD}{direction} Throughput by SINR:{C.RESET}")
            print(f"    {'SINR Range':<14} {'Samples':>8} {'Avg Mbps':>10} {'P50 Mbps':>10} {'P95 Mbps':>10}")
            print(f"    {'─' * 55}")
            for name, lo, hi in sinr_ranges:
                mbps_vals = [tp.mbps for tp, sig in tp_with_rf
                             if sig.sinr is not None and lo <= sig.sinr < hi]
                if mbps_vals:
                    print(
                        f"    {name:<14} {len(mbps_vals):>8} {mean(mbps_vals):>10.2f} "
                        f"{_percentile(mbps_vals, 50):>10.2f} {_percentile(mbps_vals, 95):>10.2f}"
                    )
            print()

    @staticmethod
    def _bisect_nearest(times: List[datetime], target: datetime) -> Optional[int]:
        """Find index of nearest timestamp using binary search."""
        if not times:
            return None
        lo, hi = 0, len(times) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if times[mid] < target:
                lo = mid + 1
            else:
                hi = mid
        # Check lo and lo-1 for closest
        best = lo
        if lo > 0:
            if abs(times[lo - 1] - target) < abs(times[lo] - target):
                best = lo - 1
        return best

    # ------------------------------------------------------------------ #
    # Section 5: RACH Performance (0xB168/0xB883-0xB885)
    # ------------------------------------------------------------------ #
    def _rach_performance(self, events: List[SignalingEvent], result: AnalysisResult) -> None:
        rach_evts: List[RACHEvent] = result.rach_events
        # Also include legacy RACH from signaling events
        legacy_rach = [e for e in events if e.procedure_group == "RACH"]

        if not rach_evts and not legacy_rach:
            return

        print(f"\n{C.BOLD}{C.CYAN}── RACH Performance (Msg1/Msg2/Msg3) ──{C.RESET}\n")

        for tech in ["LTE", "NR"]:
            tech_evts = [e for e in rach_evts if e.tech == tech]
            if not tech_evts:
                continue

            triggers = [e for e in tech_evts if e.msg_stage == "Trigger"]
            msg1 = [e for e in tech_evts if e.msg_stage == "Msg1"]
            msg2 = [e for e in tech_evts if e.msg_stage == "Msg2"]
            configs = [e for e in tech_evts if e.msg_stage == "Config"]

            print(f"  {C.BOLD}{tech} RACH Procedure:{C.RESET}")
            if triggers:
                print(f"    RACH Triggers    : {len(triggers)}")
                cause_counts: Dict[str, int] = defaultdict(int)
                for t in triggers:
                    cause_counts[t.cause or "Unknown"] += 1
                for cause, cnt in sorted(cause_counts.items(), key=lambda x: -x[1]):
                    print(f"      {cause:<25}: {cnt}")

            if msg1:
                print(f"    Msg1 (Preamble)  : {len(msg1)}")
                preambles = [e.preamble_id for e in msg1 if e.preamble_id is not None]
                powers = [e.preamble_power for e in msg1 if e.preamble_power is not None]
                target_powers = [e.target_power for e in msg1 if e.target_power is not None]
                if preambles:
                    print(f"      Preamble IDs   : {sorted(set(preambles))}")
                if powers:
                    print(f"      Preamble Power : avg={mean(powers):.1f} dBm  range=[{min(powers):.1f}, {max(powers):.1f}]")
                if target_powers:
                    print(f"      Target Power   : avg={mean(target_powers):.1f} dBm")

            if msg2:
                print(f"    {C.GREEN}Msg2 (RAR)       : {len(msg2)}{C.RESET}")
                ta_vals = [e.timing_advance for e in msg2 if e.timing_advance is not None]
                rnti_vals = [e.temp_rnti for e in msg2 if e.temp_rnti is not None]
                if ta_vals:
                    print(f"      Timing Advance : avg={mean(ta_vals):.1f}  range=[{min(ta_vals)}, {max(ta_vals)}]")
                    avg_dist = mean(ta_vals) * 78.12
                    print(f"      Est. Distance  : ~{avg_dist:.0f}m (TA×78.12m)")
                if rnti_vals:
                    print(f"      Temp-RNTI      : {len(rnti_vals)} assigned")

            # Msg1 without Msg2 = failure
            if msg1 and not msg2:
                print(f"    {C.RED}→ RF Insight: {len(msg1)} Msg1 sent, 0 Msg2 received — RACH failure!")
                print(f"      Check preamble target power in SIB2 and path loss to cell{C.RESET}")
            elif msg1 and msg2 and len(msg2) < len(msg1):
                lost = len(msg1) - len(msg2)
                print(f"    {C.YELLOW}→ RF Insight: {lost} Msg1 without Msg2 — partial RACH failure")
                print(f"      Check for preamble collisions or RAR timeout{C.RESET}")

            if configs:
                print(f"    RACH Configs     : {len(configs)}")

            # Timeline view (last 15)
            sorted_evts = sorted(tech_evts, key=lambda e: e.timestamp)
            if sorted_evts:
                print(f"\n    {C.BOLD}RACH Timeline (last 15):{C.RESET}")
                print(f"    {'Timestamp':<16} {'Stage':<10} {'Preamble':>9} {'Power':>8} {'TA':>5} {'Cause/Detail'}")
                print(f"    {'─' * 70}")
                for e in sorted_evts[-15:]:
                    pre_str = str(e.preamble_id) if e.preamble_id is not None else ""
                    pwr_str = f"{e.preamble_power:.0f}" if e.preamble_power is not None else (f"{e.target_power:.0f}" if e.target_power is not None else "")
                    ta_str = str(e.timing_advance) if e.timing_advance is not None else ""
                    info = e.cause or e.result or e.details or ""
                    color = C.GREEN if e.msg_stage == "Msg2" else C.YELLOW if e.msg_stage == "Msg1" else C.RESET
                    print(f"    {color}{_ts(e.timestamp):<16} {e.msg_stage:<10} {pre_str:>9} {pwr_str:>8} {ta_str:>5} {info}{C.RESET}")

            print()

        # ---- Msg2 → Msg3 Success Rate ----
        # Msg3 = UL RRC Setup Request (SA) or RRC Connection Request (LTE)
        # Msg4 = DL RRC Setup (SA) — gNB response confirms it got Msg3
        nr_msg2 = [e for e in rach_evts if e.tech == "NR" and e.msg_stage == "Msg2"]
        nr_msg4 = [e for e in events if e.tech == "NR" and e.layer == "RRC"
                   and "RRCSetup" in e.message_type and e.direction == "DL"]

        if nr_msg2:
            msg2_count = len(nr_msg2)
            msg4_count = len(nr_msg4)  # Msg4 = proof gNB received Msg3
            msg2to3_rate = msg4_count / msg2_count * 100 if msg2_count else 0

            print(f"  {C.BOLD}Msg2 → Msg3 Success (NR SA):{C.RESET}")
            print(f"    Msg2 (RAR) received : {msg2_count}")
            print(f"    Msg4 (RRCSetup DL)  : {msg4_count}  (confirms gNB got Msg3)")
            color = C.GREEN if msg2to3_rate >= 95 else C.YELLOW if msg2to3_rate >= 80 else C.RED
            print(f"    {color}Msg2→Msg3 Rate      : {msg2to3_rate:.1f}%{C.RESET}")

            if msg2to3_rate < 80:
                print(f"    {C.RED}→ RF Insight: Msg2→Msg3 <80% — Uplink interference on PUSCH")
                print(f"      UE cannot transmit Msg3 (RRC Setup Request) reliably")
                print(f"      Check UL SINR, inter-cell interference, PUSCH power settings{C.RESET}")
            elif msg2to3_rate < 95:
                print(f"    {C.YELLOW}→ RF Insight: Msg2→Msg3 rate below 95% target")
                print(f"      Possible intermittent UL interference on PUSCH{C.RESET}")

            # Show Msg3 / RRC Setup timeline
            if nr_msg4:
                print(f"\n    Msg3/Msg4 Timeline (last 10):")
                for e in nr_msg4[-10:]:
                    print(f"      {C.GREEN}{_ts(e.timestamp)} {e.direction} {e.message_type}{C.RESET}")
            print()

        # ---- SINR at RACH Failure Correlation ----
        failed_msg1 = []
        for tech_name in ["LTE", "NR"]:
            t_msg1 = [e for e in rach_evts if e.tech == tech_name and e.msg_stage == "Msg1"]
            t_msg2 = [e for e in rach_evts if e.tech == tech_name and e.msg_stage == "Msg2"]
            # If Msg1 > Msg2, there were failures
            if len(t_msg1) > len(t_msg2):
                failed_msg1.extend(t_msg1)

        if failed_msg1 and result.signal_samples:
            sig_sorted = sorted(result.signal_samples, key=lambda s: s.timestamp)
            sig_times = [s.timestamp for s in sig_sorted]

            sinr_at_failure = []
            rsrp_at_failure = []
            for e in failed_msg1:
                idx = self._bisect_nearest(sig_times, e.timestamp)
                if idx is not None:
                    s = sig_sorted[idx]
                    delta = abs((s.timestamp - e.timestamp).total_seconds())
                    if delta < 5.0:
                        if s.sinr is not None:
                            sinr_at_failure.append(s.sinr)
                        if s.rsrp is not None:
                            rsrp_at_failure.append(s.rsrp)

            if sinr_at_failure:
                avg_sinr = mean(sinr_at_failure)
                print(f"  {C.BOLD}RF Conditions During RACH Failures:{C.RESET}")
                print(f"    SINR at failure: avg={avg_sinr:.1f} dB  min={min(sinr_at_failure):.1f}  max={max(sinr_at_failure):.1f}")
                if rsrp_at_failure:
                    print(f"    RSRP at failure: avg={mean(rsrp_at_failure):.1f} dBm")

                if avg_sinr < -3:
                    print(f"    {C.RED}→ Root Cause: DL INTERFERENCE — SINR <-3dB at RACH time")
                    print(f"      UE likely missing RAR on PDCCH/PDSCH due to interference{C.RESET}")
                elif rsrp_at_failure and mean(rsrp_at_failure) < -110:
                    print(f"    {C.RED}→ Root Cause: UL COVERAGE — RSRP <-110dBm")
                    print(f"      gNB likely not hearing preamble — increase target power{C.RESET}")
                else:
                    print(f"    {C.YELLOW}→ Possible congestion or timing issue — check Backoff Indicator{C.RESET}")
                print()

        # ---- Preamble Collision Detection ----
        all_msg1 = [e for e in rach_evts if e.msg_stage == "Msg1" and e.preamble_id is not None]
        if all_msg1:
            preamble_counts: Dict[int, int] = defaultdict(int)
            for e in all_msg1:
                preamble_counts[e.preamble_id] += 1
            repeated = {k: v for k, v in preamble_counts.items() if v > 2}
            if repeated:
                print(f"  {C.BOLD}Preamble Collision Risk:{C.RESET}")
                for pre_id, cnt in sorted(repeated.items(), key=lambda x: -x[1]):
                    print(f"    {C.YELLOW}Preamble {pre_id}: used {cnt} times (potential collision/retransmission){C.RESET}")
                print()

        # ---- SIB2 Optimization Recommendations ----
        all_msg1_no_msg2 = False
        for tech_name in ["LTE", "NR"]:
            t_msg1 = [e for e in rach_evts if e.tech == tech_name and e.msg_stage == "Msg1"]
            t_msg2 = [e for e in rach_evts if e.tech == tech_name and e.msg_stage == "Msg2"]
            if t_msg1 and len(t_msg2) < len(t_msg1) * 0.95:
                all_msg1_no_msg2 = True

        if all_msg1_no_msg2:
            print(f"  {C.BOLD}SIB2/SIB1 Optimization Recommendations:{C.RESET}")
            print(f"    1. Increase preambleInitialReceivedTargetPower (e.g., -110→-104 dBm)")
            print(f"    2. Increase powerRampingStep (2dB→4dB) to reach gNB threshold faster")
            print(f"    3. Increase ra-ResponseWindow (10→20 slots) for processing margin")
            print(f"    4. Verify msg1-SubcarrierSpacing matches cell config")
            print()

    # ------------------------------------------------------------------ #
    # Section 6: PCI Analysis
    # ------------------------------------------------------------------ #
    def _pci_analysis(self, result: AnalysisResult) -> None:
        # Collect unique PCIs per tech
        pci_map: Dict[str, set] = defaultdict(set)
        for s in result.signal_samples:
            if s.pci is not None:
                pci_map[s.tech].add(s.pci)

        if not pci_map:
            return

        print(f"\n{C.BOLD}{C.CYAN}── PCI Analysis ──{C.RESET}\n")

        all_pcis: List[Tuple[str, int]] = []
        for tech in ["LTE", "NR"]:
            if tech not in pci_map:
                continue
            pcis = sorted(pci_map[tech])
            all_pcis.extend((tech, p) for p in pcis)

            print(f"  {C.BOLD}{tech} PCIs ({len(pcis)}):{C.RESET}")
            print(f"    {'PCI':<6} {'mod3':<6} {'mod6':<6} {'mod30':<6}")
            print(f"    {'─' * 24}")
            for p in pcis:
                print(f"    {p:<6} {p % 3:<6} {p % 6:<6} {p % 30:<6}")

        # Collision detection: PCIs with same mod-3 (PSS) or mod-6 (SSS)
        print(f"\n  {C.BOLD}PCI Collision/Confusion Risk:{C.RESET}")
        collisions_found = False

        for tech in ["LTE", "NR"]:
            if tech not in pci_map:
                continue
            pcis = sorted(pci_map[tech])
            if len(pcis) < 2:
                continue

            # mod-3 groups (PSS collision)
            mod3_groups: Dict[int, List[int]] = defaultdict(list)
            for p in pcis:
                mod3_groups[p % 3].append(p)

            for mod_val, group in sorted(mod3_groups.items()):
                if len(group) > 1:
                    collisions_found = True
                    print(f"    {C.YELLOW}{tech} mod-3={mod_val} (PSS collision risk): PCI {group}{C.RESET}")

            # mod-6 groups (SSS confusion)
            mod6_groups: Dict[int, List[int]] = defaultdict(list)
            for p in pcis:
                mod6_groups[p % 6].append(p)

            for mod_val, group in sorted(mod6_groups.items()):
                if len(group) > 1:
                    collisions_found = True
                    print(f"    {C.YELLOW}{tech} mod-6={mod_val} (SSS confusion risk): PCI {group}{C.RESET}")

        if not collisions_found:
            print(f"    {C.GREEN}No collision/confusion risks detected among observed PCIs.{C.RESET}")

        print()

    # ------------------------------------------------------------------ #
    # Section 7: Interference vs Coverage Analysis
    # ------------------------------------------------------------------ #
    def _interference_analysis(self, result: AnalysisResult) -> None:
        # Need samples with both RSRP and SINR
        paired = [
            s for s in result.signal_samples
            if s.rsrp is not None and s.sinr is not None
        ]
        if not paired:
            return

        print(f"\n{C.BOLD}{C.CYAN}── Interference vs Coverage Analysis ──{C.RESET}\n")

        for tech in ["LTE", "NR"]:
            samples = [s for s in paired if s.tech == tech]
            if not samples:
                continue

            coverage_limited = [s for s in samples if s.rsrp < -110 and s.sinr < 0]
            interference_limited = [s for s in samples if s.rsrp >= -100 and s.sinr < 5]
            good = [s for s in samples if s.rsrp >= -100 and s.sinr >= 10]
            mid_zone = len(samples) - len(coverage_limited) - len(interference_limited) - len(good)

            total = len(samples)
            print(f"  {C.BOLD}{tech} ({total} samples with RSRP+SINR):{C.RESET}")
            for label, cnt, color in [
                ("Good RF (RSRP>=-100, SINR>=10)", len(good), C.GREEN),
                ("Interference limited (RSRP>=-100, SINR<5)", len(interference_limited), C.YELLOW),
                ("Coverage limited (RSRP<-110, SINR<0)", len(coverage_limited), C.RED),
                ("Transition zone", mid_zone, C.DIM),
            ]:
                pct = cnt / total * 100 if total else 0
                print(f"    {color}{label:<45}{C.RESET} {cnt:>6} ({pct:5.1f}%) {_bar(pct, 20)}")

            if len(interference_limited) > len(coverage_limited) and interference_limited:
                print(f"    {C.YELLOW}→ Dominant issue: INTERFERENCE — consider PCI/antenna optimization{C.RESET}")
            elif len(coverage_limited) > len(interference_limited) and coverage_limited:
                print(f"    {C.RED}→ Dominant issue: COVERAGE — consider power/tilt/new site{C.RESET}")
            print()

    # ------------------------------------------------------------------ #
    # Section 8: Coverage Gap Detection
    # ------------------------------------------------------------------ #
    def _coverage_gaps(self, result: AnalysisResult) -> None:
        # Sort signal samples by time, look for periods with RSRP < threshold
        threshold = -110.0
        min_gap_sec = 1.0

        samples = sorted(
            [s for s in result.signal_samples if s.rsrp is not None],
            key=lambda s: s.timestamp,
        )
        if not samples:
            return

        gaps: List[Dict[str, Any]] = []
        gap_start = None
        gap_min_rsrp = 0.0
        gap_pci = None

        for s in samples:
            if s.rsrp < threshold:
                if gap_start is None:
                    gap_start = s.timestamp
                    gap_min_rsrp = s.rsrp
                    gap_pci = s.pci
                else:
                    if s.rsrp < gap_min_rsrp:
                        gap_min_rsrp = s.rsrp
                        gap_pci = s.pci
            else:
                if gap_start is not None:
                    duration = (s.timestamp - gap_start).total_seconds()
                    if duration >= min_gap_sec:
                        gaps.append({
                            "start": gap_start,
                            "end": s.timestamp,
                            "duration": duration,
                            "min_rsrp": gap_min_rsrp,
                            "pci": gap_pci,
                            "tech": s.tech,
                        })
                    gap_start = None

        # Close open gap at end
        if gap_start is not None and samples:
            duration = (samples[-1].timestamp - gap_start).total_seconds()
            if duration >= min_gap_sec:
                gaps.append({
                    "start": gap_start,
                    "end": samples[-1].timestamp,
                    "duration": duration,
                    "min_rsrp": gap_min_rsrp,
                    "pci": gap_pci,
                    "tech": samples[-1].tech,
                })

        print(f"\n{C.BOLD}{C.CYAN}── Coverage Gap Detection (RSRP < {threshold:.0f} dBm, > {min_gap_sec:.0f}s) ──{C.RESET}\n")

        if not gaps:
            print(f"  {C.GREEN}No coverage gaps detected.{C.RESET}")
        else:
            print(f"  {C.RED}{len(gaps)} coverage gap(s) found:{C.RESET}\n")
            print(f"  {'#':<4} {'START':<15} {'DURATION':>10} {'MIN RSRP':>10} {'TECH':<5} {'PCI'}")
            print(f"  {'─' * 55}")
            total_gap_time = 0.0
            for i, g in enumerate(gaps, 1):
                dur_str = StateMachineRenderer._fmt_duration(g["duration"])
                pci_str = str(g["pci"]) if g["pci"] is not None else ""
                total_gap_time += g["duration"]
                print(
                    f"  {i:<4} {_ts(g['start']):<15} {dur_str:>10} "
                    f"{g['min_rsrp']:>9.1f}  {g.get('tech', ''):<5} {pci_str}"
                )

            if result.file_duration:
                total_sec = result.file_duration.total_seconds()
                if total_sec > 0:
                    gap_pct = total_gap_time / total_sec * 100
                    print(f"\n  Total gap time: {StateMachineRenderer._fmt_duration(total_gap_time)} ({gap_pct:.1f}% of log)")

        print()

    # ------------------------------------------------------------------ #
    # Section 9: Mobility & Handover Analysis (A1-A5, B1-B2, RLF, T304)
    # ------------------------------------------------------------------ #
    def _handover_analysis(self, events: List[SignalingEvent], result: AnalysisResult) -> None:  # noqa: C901
        print(f"\n{C.BOLD}{C.CYAN}── Mobility & Handover Analysis ──{C.RESET}\n")

        # ---- Build handover list from PCI changes ----
        rrc_with_pci = [e for e in events if e.pci is not None and e.layer == "RRC"]
        handovers: List[Dict[str, Any]] = []
        prev_pci: Dict[str, Optional[int]] = {}
        prev_earfcn: Dict[str, Optional[int]] = {}

        for e in rrc_with_pci:
            tech = e.tech
            if tech in prev_pci and prev_pci[tech] is not None and e.pci != prev_pci[tech]:
                ho_type = "intra-freq"
                event_id = "A3"  # default: intra-freq
                if prev_earfcn.get(tech) and e.earfcn and prev_earfcn[tech] != e.earfcn:
                    ho_type = "inter-freq"
                    event_id = "A4/A5"

                # Find RSRP at HO time
                rsrp_at_ho = ""
                sig_sorted = sorted(result.signal_samples, key=lambda s: s.timestamp)
                sig_times = [s.timestamp for s in sig_sorted]
                idx = self._bisect_nearest(sig_times, e.timestamp)
                if idx is not None:
                    s = sig_sorted[idx]
                    if abs((s.timestamp - e.timestamp).total_seconds()) < 2 and s.rsrp is not None:
                        rsrp_at_ho = f"{s.rsrp:.1f}"

                handovers.append({
                    "timestamp": e.timestamp, "tech": tech,
                    "from_pci": prev_pci[tech], "to_pci": e.pci,
                    "type": ho_type, "event_id": event_id,
                    "band": e.band, "rsrp": rsrp_at_ho,
                })
            prev_pci[tech] = e.pci
            prev_earfcn[tech] = e.earfcn

        # ---- Detect inter-RAT (B1/B2) from LTE→NR transitions ----
        lte_reconfigs = [e for e in events if "Reconfiguration" in e.message_type and e.tech == "LTE"]
        for rc in lte_reconfigs:
            for nr_evt in events:
                if nr_evt.tech == "NR" and nr_evt.layer == "RRC":
                    delta = (nr_evt.timestamp - rc.timestamp).total_seconds()
                    if 0 < delta < 2.0 and nr_evt.pci is not None:
                        handovers.append({
                            "timestamp": rc.timestamp, "tech": "LTE→NR",
                            "from_pci": rc.pci or "LTE", "to_pci": nr_evt.pci,
                            "type": "inter-RAT", "event_id": "B1/B2",
                            "band": nr_evt.band or "", "rsrp": "",
                        })
                        break

        handovers.sort(key=lambda h: h["timestamp"])

        # ---- Handover Summary ----
        intra = sum(1 for h in handovers if h["type"] == "intra-freq")
        inter = sum(1 for h in handovers if h["type"] == "inter-freq")
        irat = sum(1 for h in handovers if h["type"] == "inter-RAT")
        print(f"  Total Handovers    : {len(handovers)}")
        if handovers:
            print(f"    A3 (intra-freq)  : {intra}")
            print(f"    A4/A5 (inter-freq): {inter}")
            print(f"    B1/B2 (inter-RAT): {irat}")

        # ---- Ping-pong detection ----
        pingpongs: List[Dict[str, Any]] = []
        for i in range(len(handovers) - 1):
            h1, h2 = handovers[i], handovers[i + 1]
            if (h1["from_pci"] == h2["to_pci"] and h1["to_pci"] == h2["from_pci"]
                    and h1["tech"] == h2["tech"]):
                delta = (h2["timestamp"] - h1["timestamp"]).total_seconds()
                if delta < 10.0:
                    pingpongs.append({"h1": h1, "h2": h2, "delta": delta})

        if pingpongs:
            print(f"    {C.RED}Ping-pong HOs    : {len(pingpongs)}{C.RESET}")
            for pp in pingpongs[:5]:
                print(f"      {C.RED}{_ts(pp['h1']['timestamp'])} PCI {pp['h1']['from_pci']}→{pp['h1']['to_pci']}→{pp['h2']['to_pci']} in {pp['delta']:.1f}s{C.RESET}")
            print(f"    {C.YELLOW}→ Fix: Increase Hysteresis (Hys) or Time-to-Trigger (TTT){C.RESET}")
        elif handovers:
            print(f"    {C.GREEN}Ping-pong HOs    : 0{C.RESET}")

        # ---- Handover Timeline (Optimization Dashboard format) ----
        if handovers:
            print(f"\n  {C.BOLD}Mobility Event Timeline:{C.RESET}")
            print(f"  {'Timestamp':<16} {'Event':<8} {'Details':<35} {'RSRP':>8} {'Status'}")
            print(f"  {'─' * 80}")
            for h in handovers:
                details = f"PCI {h['from_pci']}→{h['to_pci']} ({h['type']})"
                rsrp_str = h["rsrp"] if h["rsrp"] else "N/A"
                # Check if HO completed (next event on target PCI)
                status = f"{C.GREEN}Complete{C.RESET}"
                print(f"  {_ts(h['timestamp']):<16} {h['event_id']:<8} {details:<35} {rsrp_str:>8} {status}")

            ho_rsrp = [float(h["rsrp"]) for h in handovers if h["rsrp"]]
            if ho_rsrp:
                print(f"\n  RSRP at HO Trigger: Min={min(ho_rsrp):.1f}  Avg={mean(ho_rsrp):.1f}  Max={max(ho_rsrp):.1f} dBm")

        # ---- RRC Rejects ----
        rrc_rejects = [e for e in events if "Reject" in e.message_type and e.layer == "RRC"]
        if rrc_rejects:
            print(f"\n  {C.BOLD}RRC Rejects:{C.RESET} {C.RED}{len(rrc_rejects)}{C.RESET}")
            for e in rrc_rejects[:5]:
                print(f"    {C.RED}{_ts(e.timestamp)} {e.tech} {e.message_type}{C.RESET}")
            if len(rrc_rejects) > 5:
                print(f"    ... and {len(rrc_rejects) - 5} more")

        # ---- Radio Link Failures (RLF) ----
        rlf_events = [a for a in result.anomalies if a.category == "rlf"]
        reest_events = [e for e in events if "Reestablishment" in e.message_type]
        if rlf_events or reest_events:
            print(f"\n  {C.BOLD}Radio Link Failures / Reestablishments:{C.RESET}")
            if rlf_events:
                print(f"    {C.RED}NR RLF Events    : {len(rlf_events)}{C.RESET}")
                for r in rlf_events[:5]:
                    print(f"      {C.RED}{_ts(r.timestamp)} {r.description}{C.RESET}")
            if reest_events:
                print(f"    {C.YELLOW}RRC Reestablish  : {len(reest_events)}{C.RESET}")

            # RLF before HO analysis
            if rlf_events and not handovers:
                print(f"    {C.RED}→ RF Insight: RLF with no handover — A2/A3 thresholds too tight")
                print(f"      UE is holding onto weak cell too long before neighbor search{C.RESET}")

        # ---- Measurement Report Detection ----
        meas_reports = [e for e in events if "MeasurementReport" in e.message_type
                        or "measurementReport" in e.message_type]
        if meas_reports:
            print(f"\n  {C.BOLD}Measurement Reports:{C.RESET} {len(meas_reports)}")
            for e in meas_reports[:5]:
                print(f"    {_ts(e.timestamp)} {e.tech} {e.direction} PCI={e.pci}")

        # ---- Missing ANR Detection ----
        # Strong neighbor cells without HO command
        if result.signal_samples and not handovers:
            serving_pcis: Dict[str, int] = {}
            for tech_name in ["LTE", "NR"]:
                tech_samples = [s for s in result.signal_samples if s.tech == tech_name and s.pci is not None]
                if tech_samples:
                    pci_counts: Dict[int, int] = defaultdict(int)
                    for s in tech_samples:
                        pci_counts[s.pci] += 1
                    serving_pcis[tech_name] = max(pci_counts, key=pci_counts.get)

            strong_neighbors = []
            for tech_name, srv_pci in serving_pcis.items():
                for s in result.signal_samples:
                    if s.tech == tech_name and s.pci is not None and s.pci != srv_pci:
                        if s.rsrp is not None and s.rsrp > -100:
                            strong_neighbors.append((tech_name, s.pci, s.rsrp))

            if strong_neighbors:
                seen = set()
                print(f"\n  {C.BOLD}Strong Neighbors Without HO:{C.RESET}")
                for tech_name, pci, rsrp in strong_neighbors:
                    key = (tech_name, pci)
                    if key not in seen:
                        seen.add(key)
                        print(f"    {C.YELLOW}{tech_name} PCI {pci}: RSRP up to {rsrp:.1f} dBm — no HO triggered{C.RESET}")
                if seen:
                    print(f"    {C.YELLOW}→ Check: ANR neighbor relations may be missing, or A3/A5 thresholds not met{C.RESET}")

        # ---- Summary for no-mobility logs ----
        if not handovers and not rlf_events and not rrc_rejects and not meas_reports:
            print(f"  {C.DIM}No mobility events detected (stationary or single-cell log){C.RESET}")

        print()


# ---------------------------------------------------------------------------
# DiagnosticReport — Professional SP Engineer Dashboard
# ---------------------------------------------------------------------------

class DiagnosticReport:
    """Generate a professional diagnostic report for SP/RF engineers."""

    def render(self, proc: LogProcessor, events: List[SignalingEvent]) -> None:
        result = proc.result
        if not result:
            print("[WARN] No analysis result available.")
            return

        filepath = proc.filepath
        nr_sig = [s for s in result.signal_samples if s.tech == "NR"]
        lte_sig = [s for s in result.signal_samples if s.tech == "LTE"]

        # --- Detect network context ---
        nr_arfcn = next((s.earfcn for s in nr_sig if s.earfcn), None)
        nr_band = earfcn_to_band(nr_arfcn, "NR") if nr_arfcn else ""
        nr_scs = nr_band_to_scs(nr_band) if nr_band else None
        nr_duplex = NR_BAND_DUPLEX.get(nr_band, "")
        lte_arfcn = next((s.earfcn for s in lte_sig if s.earfcn), None)
        lte_band = earfcn_to_band(lte_arfcn, "LTE") if lte_arfcn else ""
        # Determine mode: SA / NSA / LTE-only
        mode = "NR SA" if nr_sig and not lte_sig else "NSA (EN-DC)" if nr_sig and lte_sig else "LTE"

        # --- Header ---
        print(f"\n{C.BOLD}{C.CYAN}{'=' * 80}")
        print(f"  UE Technical Diagnostic Report")
        print(f"{'=' * 80}{C.RESET}")
        print(f"  Log File : {filepath}")
        net_parts = [mode]
        if nr_band:
            net_parts.append(f"NR {nr_band} ({nr_duplex})" if nr_duplex else f"NR {nr_band}")
        if lte_band:
            net_parts.append(f"LTE {lte_band}")
        if nr_scs:
            net_parts.append(f"SCS {nr_scs}kHz")
        if nr_arfcn:
            net_parts.append(f"NR-ARFCN {nr_arfcn}")
        print(f"  Network  : {' | '.join(net_parts)}")

        # NSA Anchor Status — if LTE anchor is bad, NR will drop
        if mode == "NSA (EN-DC)" and lte_sig:
            lte_rsrp = [s.rsrp for s in lte_sig if s.rsrp is not None]
            lte_sinr = [s.sinr for s in lte_sig if s.sinr is not None]
            anchor_pci = self._dominant_pci(lte_sig)
            anchor_health = "Stable"
            color = C.GREEN
            if lte_sinr and mean(lte_sinr) < 0:
                anchor_health = "High Interference (SINR<0)"
                color = C.RED
            elif lte_sinr and mean(lte_sinr) < 5:
                anchor_health = "Marginal (SINR<5)"
                color = C.YELLOW
            if lte_rsrp and mean(lte_rsrp) < -110:
                anchor_health = "Weak Coverage (RSRP<-110)"
                color = C.RED
            anchor_desc = f"LTE {lte_band} (PCI {anchor_pci}, EARFCN {lte_arfcn})" if lte_band else f"LTE PCI {anchor_pci}"
            print(f"  Anchor   : {anchor_desc} | {color}{anchor_health}{C.RESET}")
            if "Interference" in anchor_health or "Weak" in anchor_health:
                print(f"  {C.RED}           WARNING: Poor LTE anchor degrades NR leg in NSA{C.RESET}")

        if result.first_timestamp and result.last_timestamp:
            print(f"  Period   : {_ts_full(result.first_timestamp)} -> {_ts_full(result.last_timestamp)}")
            if result.file_duration:
                secs = result.file_duration.total_seconds()
                print(f"  Duration : {int(secs // 60)}m {int(secs % 60)}s  |  {result.total_packets:,} packets  |  {len(events)} signaling events")
        print()

        # ===== Section 1: Critical Event Timeline =====
        self._critical_timeline(events, result)

        # ===== Section 2: RRM Analysis =====
        self._rrm_analysis(proc, events, result, nr_sig, lte_sig)

        # ===== Section 3: L1/L2 Efficiency =====
        self._l1_l2_efficiency(events, result, nr_sig, lte_sig)

        # ===== Section 4: Cell Info =====
        self._cell_summary(result, nr_sig, lte_sig, nr_band, nr_scs, nr_arfcn, lte_band, lte_arfcn)

        # ===== Section 5: Recommendations + Confidence =====
        self._recommendations(events, result, nr_sig, lte_sig)

    # ------------------------------------------------------------------
    # Section 1: Critical Event Timeline
    # ------------------------------------------------------------------
    def _critical_timeline(self, _events: List[SignalingEvent], result: AnalysisResult) -> None:
        print(f"{C.BOLD}{C.RED}  [1] CRITICAL EVENT TIMELINE (Chain of Failure){C.RESET}")
        print(f"  {'─' * 76}")

        # Build transaction-paired timeline from RRC events
        # Group: RRC Setup Request → Setup/Reject, Reestablishment → Result, RLF
        transactions: List[Dict[str, Any]] = []

        rrc_sorted = sorted(result.rrc_events, key=lambda e: e.timestamp)
        i = 0
        while i < len(rrc_sorted):
            evt = rrc_sorted[i]

            # --- RLF events ---
            if "Radio Link Failure" in evt.event:
                rsrp_at = self._rsrp_at_time(result, evt.timestamp, evt.tech)
                cause_str = evt.cause if evt.cause else "t310-Expiry"
                transactions.append({
                    "ts": evt.timestamp, "event": "RLF Detected",
                    "tech": evt.tech, "cause": cause_str,
                    "diag": f"RSRP={rsrp_at}" if rsrp_at else "Signal loss",
                    "severity": "critical",
                })

            # --- RRC Reject (look for preceding Setup Request) ---
            elif "Reject" in evt.event and "RRC" in evt.event:
                cause_parts = []
                if evt.cause:
                    cause_parts.append(evt.cause)
                if evt.wait_time:
                    cause_parts.append(f"waitTime={evt.wait_time}s")
                cause_str = ", ".join(cause_parts) if cause_parts else RRC_REJECT_REASONS["unknown"]

                # Find preceding Request within 500ms
                prev_req = None
                for j in range(i - 1, max(i - 5, -1), -1):
                    if j >= 0 and ("Request" in rrc_sorted[j].event or "Setup" in rrc_sorted[j].event):
                        delta = (evt.timestamp - rrc_sorted[j].timestamp).total_seconds()
                        if delta < 0.5:
                            prev_req = rrc_sorted[j]
                            break

                if prev_req:
                    latency_ms = (evt.timestamp - prev_req.timestamp).total_seconds() * 1000
                    transactions.append({
                        "ts": prev_req.timestamp,
                        "event": f"{prev_req.event} → {evt.event}",
                        "tech": evt.tech,
                        "cause": cause_str,
                        "diag": f"Latency: {latency_ms:.0f}ms | PCI {evt.pci}",
                        "severity": "critical",
                    })
                else:
                    transactions.append({
                        "ts": evt.timestamp, "event": evt.event,
                        "tech": evt.tech, "cause": cause_str,
                        "diag": f"PCI {evt.pci}" if evt.pci else "",
                        "severity": "critical",
                    })

            # --- RRC Release ---
            elif "Release" in evt.event and evt.direction == "DL":
                cause_str = evt.cause if evt.cause else ""
                if cause_str:
                    transactions.append({
                        "ts": evt.timestamp, "event": f"RRC Release ({cause_str})",
                        "tech": evt.tech, "cause": cause_str,
                        "diag": f"PCI {evt.pci}" if evt.pci else "",
                        "severity": "warning",
                    })

            # --- Reestablishment Request ---
            elif "Reestablishment" in evt.event and "Request" in evt.event:
                cause_str = evt.cause if evt.cause else RRC_REESTABLISH_CAUSES.get(2, "otherFailure")
                transactions.append({
                    "ts": evt.timestamp, "event": f"RRC Reestablishment ({cause_str})",
                    "tech": evt.tech, "cause": cause_str,
                    "diag": f"PCI {evt.pci}" if evt.pci else "",
                    "severity": "critical",
                })

            i += 1

        # Also add RACH failures and NAS rejects from anomalies (non-RRC)
        for a in result.anomalies:
            if a.severity == "critical" and a.category in ("rach_failure", "nas_reject"):
                diag = "No RAR from gNB" if a.category == "rach_failure" else "NAS rejection"
                transactions.append({
                    "ts": a.timestamp, "event": a.description,
                    "tech": a.tech, "cause": "",
                    "diag": diag, "severity": "critical",
                })

        # Sort, deduplicate
        transactions.sort(key=lambda x: x["ts"])
        seen = set()
        unique: List[Dict[str, Any]] = []
        for t in transactions:
            key = f"{_ts(t['ts'])}_{t['event']}"
            if key not in seen:
                seen.add(key)
                unique.append(t)

        if not unique:
            print(f"  {C.GREEN}  No critical events detected.{C.RESET}\n")
            return

        # Print — show most impactful events (RLF, Reject pairs, Reestablish) first
        high_impact = [t for t in unique if t["severity"] == "critical"]
        print(f"\n  {'Timestamp':<16} {'Event':<38} {'Tech':<5} {'Cause / RRC IE':<25} {'Diagnostic'}")
        print(f"  {'─' * 100}")
        for t in high_impact[:25]:
            color = C.RED if "RLF" in t["event"] or "Reject" in t["event"] else C.YELLOW
            cause_str = t["cause"][:24] if t["cause"] else ""
            print(f"  {color}{_ts(t['ts']):<16} {t['event']:<38} {t['tech']:<5} {cause_str:<25} {t['diag']}{C.RESET}")

        print(f"\n  Critical: {C.RED}{len(high_impact)}{C.RESET}  |  Total tracked: {len(unique)}")
        print()

    # ------------------------------------------------------------------
    # Section 2: RRM Analysis
    # ------------------------------------------------------------------
    def _rrm_analysis(
        self, _proc: LogProcessor, events: List[SignalingEvent],
        result: AnalysisResult, nr_sig: list, _lte_sig: list
    ) -> None:
        print(f"{C.BOLD}{C.CYAN}  [2] RADIO RESOURCE MANAGEMENT (RRM) ANALYSIS{C.RESET}")
        print(f"  {'─' * 76}")

        # --- A. Mobility Threshold Audit ---
        rlf_events = [a for a in result.anomalies if a.category == "rlf"]
        handovers = [e for e in events if "Reconfiguration" in e.message_type]

        print(f"\n  {C.BOLD}A. Mobility Audit:{C.RESET}")
        print(f"     RLF Events: {C.RED}{len(rlf_events)}{C.RESET}  |  Handovers: {len(handovers)}  |  RRC Rejects: {sum(1 for e in events if 'Reject' in e.message_type)}")

        if rlf_events:
            # Late HO detection: was a stronger neighbor available before RLF?
            for a in rlf_events[:3]:
                serving_rsrp = self._rsrp_at_time(result, a.timestamp, a.tech)
                # Check 5s before RLF for neighbors
                from datetime import timedelta as _td
                t_before = a.timestamp - _td(seconds=5)
                neighbors_before = [
                    s for s in result.signal_samples
                    if s.tech == a.tech and t_before <= s.timestamp <= a.timestamp
                    and s.pci is not None and s.rsrp is not None
                ]
                if neighbors_before:
                    best_neighbor = max(neighbors_before, key=lambda s: s.rsrp)
                    delta = (best_neighbor.rsrp - float(serving_rsrp.replace("dBm", ""))) if serving_rsrp else 0
                    n_band = earfcn_to_band(best_neighbor.earfcn, a.tech) if best_neighbor.earfcn else ""
                    n_freq = f", ARFCN {best_neighbor.earfcn}" if best_neighbor.earfcn else ""
                    n_band_str = f", {n_band}" if n_band else ""
                    cell_id = f"PCI {best_neighbor.pci}{n_band_str}{n_freq}"

                    if delta > 15:
                        # >15dB gap = ANR is almost certainly missing
                        print(f"     {C.RED}Missing ANR @ {_ts(a.timestamp)}: {cell_id} was {delta:+.1f}dB stronger{C.RESET}")
                        print(f"       {C.RED}Neighbor Relation missing in gNB — cell {best_neighbor.pci} not configured as HO target{C.RESET}")
                    elif delta > 6:
                        print(f"     {C.RED}Late HO @ {_ts(a.timestamp)}: {cell_id} was {delta:+.1f}dB stronger 5s before RLF{C.RESET}")
                    elif best_neighbor.rsrp > -100:
                        print(f"     Available: {cell_id} at RSRP {best_neighbor.rsrp:.1f} dBm before RLF @ {_ts(a.timestamp)}")

            if len(rlf_events) > 0 and len(handovers) == 0:
                print(f"     {C.RED}Finding: \"Too Late Handover\" — UE holds weak cell until RLF{C.RESET}")
                print(f"     Suggested: Reduce timeToTrigger (TTT) for fast-fading TDD bands")

        # --- B. Beam Management ---
        beam_samples = [s for s in nr_sig if s.beam_id is not None]
        if beam_samples:
            print(f"\n  {C.BOLD}B. Beam Management (0xB821):{C.RESET}")

            beams: Dict[int, List[SignalSample]] = defaultdict(list)
            for s in beam_samples:
                beams[s.beam_id].append(s)

            # Find anchor beam (most frequent) and best beam (highest avg SINR)
            anchor_id = max(beams.keys(), key=lambda b: len(beams[b]))
            anchor_sinr = [s.sinr for s in beams[anchor_id] if s.sinr is not None]
            avg_anchor_sinr = mean(anchor_sinr) if anchor_sinr else -20

            best_sinr_id = None
            best_avg_sinr = -999
            for bid, samps in beams.items():
                sinr_vals = [s.sinr for s in samps if s.sinr is not None]
                if sinr_vals and mean(sinr_vals) > best_avg_sinr:
                    best_avg_sinr = mean(sinr_vals)
                    best_sinr_id = bid

            # Stuck beam count
            stuck = 0
            timeline = sorted(beam_samples, key=lambda s: s.timestamp)
            ts_groups: Dict[str, List[SignalSample]] = defaultdict(list)
            for s in timeline:
                ts_groups[_ts(s.timestamp)].append(s)
            for group in ts_groups.values():
                if len(group) < 2:
                    continue
                best = max(group, key=lambda s: s.sinr if s.sinr is not None else -999)
                serving = group[0]
                if (best.beam_id != serving.beam_id
                        and best.sinr is not None and serving.sinr is not None
                        and best.sinr - serving.sinr > 3.0):
                    stuck += 1

            print(f"     Current Anchor : SSB Index {anchor_id} (Avg SINR: {avg_anchor_sinr:.1f} dB)")
            if best_sinr_id is not None and best_sinr_id != anchor_id:
                gain_loss = best_avg_sinr - avg_anchor_sinr
                print(f"     Best Candidate : SSB Index {best_sinr_id} (Avg SINR: {best_avg_sinr:.1f} dB)")
                if gain_loss > 3:
                    print(f"     {C.RED}SNR Gap: ~{gain_loss:.1f} dB wasted — UE not tracking best beam{C.RESET}")
            if stuck > 0:
                print(f"     Sub-Optimal Beam Residency: {C.YELLOW}{stuck} events{C.RESET}")
                print(f"     Check: beamFailureDetectionTimer, ssb-PositionsInBurst")

            # Beam table (top 5)
            print(f"\n     {'SSB':>4} {'Samples':>8} {'RSRP avg':>9} {'SINR avg':>9}")
            print(f"     {'─' * 35}")
            for bid in sorted(beams.keys(), key=lambda b: -len(beams[b]))[:8]:
                samps = beams[bid]
                rsrp = [s.rsrp for s in samps if s.rsrp is not None]
                sinr = [s.sinr for s in samps if s.sinr is not None]
                rsrp_str = f"{mean(rsrp):.1f}" if rsrp else "N/A"
                sinr_str = f"{mean(sinr):.1f}" if sinr else "N/A"
                marker = " <anchor" if bid == anchor_id else (" <best" if bid == best_sinr_id else "")
                print(f"     {bid:>4} {len(samps):>8} {rsrp_str:>9} {sinr_str:>9}{marker}")

        print()

    # ------------------------------------------------------------------
    # Section 3: L1/L2 Efficiency
    # ------------------------------------------------------------------
    def _l1_l2_efficiency(
        self, events: List[SignalingEvent], result: AnalysisResult,
        nr_sig: list, lte_sig: list
    ) -> None:
        print(f"{C.BOLD}{C.CYAN}  [3] L1/L2 EFFICIENCY & ACCESS{C.RESET}")
        print(f"  {'─' * 76}")

        # --- A. RACH / UL Analysis ---
        rach_evts = result.rach_events
        if rach_evts:
            print(f"\n  {C.BOLD}A. RACH / UL Access:{C.RESET}")
            for tech in ["NR", "LTE"]:
                msg1 = [e for e in rach_evts if e.tech == tech and e.msg_stage == "Msg1"]
                msg2 = [e for e in rach_evts if e.tech == tech and e.msg_stage == "Msg2"]
                if not msg1 and not msg2:
                    continue

                m1c, m2c = len(msg1), len(msg2)
                nr_rrc_setup = [e for e in events if e.tech == tech and "RRCSetup" in e.message_type and e.direction == "DL"]
                m4c = len(nr_rrc_setup)

                print(f"     {tech}:")
                if m1c > 0:
                    rate12 = m2c / m1c * 100 if m1c else 0
                    color = C.GREEN if rate12 >= 95 else C.YELLOW if rate12 >= 80 else C.RED
                    print(f"       Msg1->Msg2 (RACH SR): {color}{m2c}/{m1c} ({rate12:.1f}%){C.RESET}")
                if m2c > 0:
                    rate23 = m4c / m2c * 100 if m2c else 0
                    color = C.GREEN if rate23 >= 95 else C.YELLOW if rate23 >= 80 else C.RED
                    print(f"       Msg2->Msg3 (UL SR)  : {color}{m4c}/{m2c} ({rate23:.1f}%){C.RESET}")
                    if rate23 < 80:
                        print(f"       {C.RED}Bottleneck: UL interference on PUSCH — Msg3 not reaching gNB{C.RESET}")

        # --- B. Throughput vs MCS ---
        if result.phy_samples:
            print(f"\n  {C.BOLD}B. Throughput vs MCS Efficiency:{C.RESET}")
            for tech in ["NR", "LTE"]:
                samples = [s for s in result.phy_samples if s.tech == tech and s.direction == "DL"]
                if not samples:
                    continue

                mcs_vals = [s.mcs for s in samples if s.mcs is not None]
                rank_vals = [s.rank for s in samples if s.rank is not None]
                bler_vals = [s.bler for s in samples if s.bler is not None]

                if not mcs_vals:
                    continue

                # Modulation breakdown
                mod_counts: Dict[str, int] = defaultdict(int)
                for s in samples:
                    if s.mcs is not None:
                        mod_counts[s.modulation] += 1
                total = sum(mod_counts.values())
                dominant_mod = max(mod_counts, key=mod_counts.get) if mod_counts else "N/A"
                dominant_pct = mod_counts[dominant_mod] / total * 100 if total else 0

                # Rank
                dominant_rank = None
                if rank_vals:
                    rank_counts: Dict[int, int] = defaultdict(int)
                    for r in rank_vals:
                        rank_counts[r] += 1
                    dominant_rank = max(rank_counts, key=rank_counts.get)

                sig_samples = nr_sig if tech == "NR" else lte_sig
                sinr_vals = [s.sinr for s in sig_samples if s.sinr is not None]
                avg_sinr = mean(sinr_vals) if sinr_vals else None

                print(f"     {tech} DL:")
                print(f"       Dominant Modulation: {C.BOLD}{dominant_mod}{C.RESET} ({dominant_pct:.1f}%)")
                for mod_name in ["256QAM", "64QAM", "16QAM", "QPSK"]:
                    cnt = mod_counts.get(mod_name, 0)
                    if cnt > 0:
                        pct = cnt / total * 100
                        print(f"         {mod_name:<8}: {pct:5.1f}%  {_bar(pct, 20)}")
                if dominant_rank:
                    print(f"       MIMO Rank          : Rank {dominant_rank} dominant ({rank_counts[dominant_rank]}/{len(rank_vals)})")
                if bler_vals:
                    avg_bler = mean(bler_vals) * 100
                    color = C.GREEN if avg_bler < 2 else C.YELLOW if avg_bler < 10 else C.RED
                    print(f"       BLER               : {color}{avg_bler:.2f}%{C.RESET}")

                # Efficiency bottleneck detection
                if dominant_mod in ("QPSK", "16QAM") and dominant_rank and dominant_rank >= 2:
                    if avg_sinr is not None and avg_sinr < 0:
                        print(f"       {C.YELLOW}Bottleneck: {dominant_rank} MIMO layers but {dominant_mod} forced by SINR={avg_sinr:.1f}dB{C.RESET}")

        # --- C. Throughput Summary ---
        if result.throughput_samples:
            print(f"\n  {C.BOLD}C. Throughput:{C.RESET}")
            for d in ["DL", "UL"]:
                tp = [s.mbps for s in result.throughput_samples if s.direction == d and s.mbps > 0]
                if tp:
                    print(f"     {d}: Avg={mean(tp):.1f}  P50={_percentile(tp, 50):.1f}  P95={_percentile(tp, 95):.1f}  Peak={max(tp):.1f} Mbps")

        print()

    # ------------------------------------------------------------------
    # Section 4: Cell Summary
    # ------------------------------------------------------------------
    def _cell_summary(
        self, result: AnalysisResult, nr_sig: list, lte_sig: list,
        nr_band: str, nr_scs: Optional[int], nr_arfcn: Optional[int],
        lte_band: str, lte_arfcn: Optional[int]
    ) -> None:
        print(f"{C.BOLD}{C.CYAN}  [4] CELL & RF SUMMARY{C.RESET}")
        print(f"  {'─' * 76}")

        for tech, sig, band, arfcn, scs in [
            ("NR", nr_sig, nr_band, nr_arfcn, nr_scs),
            ("LTE", lte_sig, lte_band, lte_arfcn, None),
        ]:
            if not sig:
                continue
            rsrp = [s.rsrp for s in sig if s.rsrp is not None]
            sinr = [s.sinr for s in sig if s.sinr is not None]

            print(f"\n  {C.BOLD}{tech} ({len(sig)} samples):{C.RESET}")
            info_parts = []
            if band:
                info_parts.append(f"Band {band}")
            if arfcn:
                info_parts.append(f"ARFCN {arfcn}")
            if scs:
                info_parts.append(f"SCS {scs}kHz")
                info_parts.append(f"{scs_to_slots_per_frame(scs)} slots/frame")
            duplex = NR_BAND_DUPLEX.get(band, "")
            if duplex:
                info_parts.append(duplex)
            pci = self._dominant_pci(sig)
            if pci is not None:
                info_parts.append(f"PCI {pci}")
            if info_parts:
                print(f"     Config: {' | '.join(info_parts)}")

            if rsrp:
                print(f"     RSRP  : {min(rsrp):.1f} / {mean(rsrp):.1f} / {max(rsrp):.1f}  (min/avg/max)")
            if sinr:
                print(f"     SINR  : {min(sinr):.1f} / {mean(sinr):.1f} / {max(sinr):.1f}  (min/avg/max)")

            # Neighbor cells
            pci_counts: Dict[int, int] = defaultdict(int)
            for s in sig:
                if s.pci is not None:
                    pci_counts[s.pci] += 1
            if len(pci_counts) > 1:
                print(f"     Cells : {len(pci_counts)} PCIs detected:")
                # Build per-PCI freq/band info
                pci_freq: Dict[int, Optional[int]] = {}
                for s in sig:
                    if s.pci is not None and s.pci not in pci_freq and s.earfcn is not None:
                        pci_freq[s.pci] = s.earfcn
                for p in sorted(pci_counts.keys()):
                    freq = pci_freq.get(p)
                    b = earfcn_to_band(freq, tech) if freq else ""
                    freq_str = f"{b} ARFCN {freq}" if b and freq else (f"ARFCN {freq}" if freq else "")
                    cnt = pci_counts[p]
                    print(f"       PCI {p:<5} {freq_str:<20} ({cnt} samples)")

            # SSB beams for NR
            beam_ids = set(s.beam_id for s in sig if s.beam_id is not None)
            if beam_ids:
                print(f"     SSB   : {len(beam_ids)} beams (idx {min(beam_ids)}-{max(beam_ids)})")

        print()

    # ------------------------------------------------------------------
    # Section 5: Recommendations + Confidence
    # ------------------------------------------------------------------
    def _recommendations(
        self, events: List[SignalingEvent], result: AnalysisResult,
        nr_sig: list, lte_sig: list
    ) -> None:
        print(f"{C.BOLD}{C.CYAN}  [5] RECOMMENDATIONS & CONFIDENCE{C.RESET}")
        print(f"  {'─' * 76}")

        recs: List[Tuple[str, str, str]] = []  # (priority, recommendation, evidence)
        confidence_points = 0
        confidence_max = 0

        # --- PCI collision with Victim/Aggressor identification ---
        # Build per-PCI info: avg RSRP, EARFCN, band
        pci_info: Dict[Tuple[str, int], Dict[str, Any]] = {}
        for s in result.signal_samples:
            if s.pci is not None:
                key = (s.tech, s.pci)
                if key not in pci_info:
                    pci_info[key] = {"rsrp": [], "earfcn": s.earfcn, "tech": s.tech, "pci": s.pci}
                if s.rsrp is not None:
                    pci_info[key]["rsrp"].append(s.rsrp)

        all_pcis: Dict[str, set] = defaultdict(set)
        for (tech, pci) in pci_info:
            all_pcis[tech].add(pci)

        for tech, pcis in all_pcis.items():
            mod3_groups: Dict[int, List[int]] = defaultdict(list)
            for p in pcis:
                mod3_groups[p % 3].append(p)
            for mod_val, group in mod3_groups.items():
                if len(group) > 1:
                    # Identify aggressor (strongest RSRP) and victim
                    group_info = []
                    for p in group:
                        info = pci_info.get((tech, p), {})
                        avg_rsrp = mean(info["rsrp"]) if info.get("rsrp") else -999
                        earfcn = info.get("earfcn")
                        band = earfcn_to_band(earfcn, tech) if earfcn else ""
                        freq_str = f"{band} ARFCN {earfcn}" if band and earfcn else (f"ARFCN {earfcn}" if earfcn else "")
                        group_info.append({"pci": p, "rsrp": avg_rsrp, "freq": freq_str})
                    group_info.sort(key=lambda x: -x["rsrp"])
                    aggressor = group_info[0]
                    victim = group_info[-1]

                    agg_str = f"PCI {aggressor['pci']}"
                    if aggressor["freq"]:
                        agg_str += f" ({aggressor['freq']})"
                    vic_str = f"PCI {victim['pci']}"
                    if victim["freq"]:
                        vic_str += f" ({victim['freq']})"

                    rec_text = (
                        f"PCI Collision (mod-3={mod_val}): "
                        f"Aggressor={agg_str} RSRP {aggressor['rsrp']:.0f}dBm vs "
                        f"Victim={vic_str} RSRP {victim['rsrp']:.0f}dBm. "
                        f"Change PCI {aggressor['pci']} to mod-3!={mod_val}"
                    )
                    recs.append(("HIGH", rec_text, f"{tech} per-cell RF"))
                    break
        confidence_max += 1
        if any(r[0] == "HIGH" and "PCI" in r[1] for r in recs):
            confidence_points += 1

        # --- HO tuning ---
        rlf_count = sum(1 for a in result.anomalies if a.category == "rlf")
        ho_count = sum(1 for e in events if "Reconfiguration" in e.message_type)
        confidence_max += 1
        if rlf_count > 0 and ho_count == 0:
            recs.append(("HIGH", "HO Tuning: Reduce timeToTrigger (TTT) — RLF without handover indicates late HO", f"{rlf_count} RLF, 0 HO"))
            confidence_points += 1

        # --- RACH power ---
        lte_msg1 = [e for e in result.rach_events if e.tech == "LTE" and e.msg_stage == "Msg1"]
        lte_msg2 = [e for e in result.rach_events if e.tech == "LTE" and e.msg_stage == "Msg2"]
        confidence_max += 1
        if lte_msg1 and not lte_msg2:
            recs.append(("HIGH", "RACH Power: Increase preambleInitialReceivedTargetPower (-110 -> -104 dBm)", f"LTE RACH {len(lte_msg1)} Msg1, 0 Msg2"))
            confidence_points += 1

        # --- Msg2->Msg3 ---
        nr_msg2 = [e for e in result.rach_events if e.tech == "NR" and e.msg_stage == "Msg2"]
        nr_msg4 = [e for e in events if e.tech == "NR" and "RRCSetup" in e.message_type and e.direction == "DL"]
        confidence_max += 1
        if nr_msg2 and nr_msg4:
            rate = len(nr_msg4) / len(nr_msg2) * 100
            if rate < 95:
                recs.append(("MEDIUM", f"UL Interference: Msg2->Msg3 rate {rate:.1f}% (target >95%) — check PUSCH interference", f"{len(nr_msg4)}/{len(nr_msg2)} Msg2->Msg3"))
                confidence_points += 1

        # --- RRC Rejects ---
        rrc_rejects = [e for e in events if "Reject" in e.message_type and e.layer == "RRC"]
        confidence_max += 1
        if rrc_rejects:
            recs.append(("MEDIUM", f"Capacity: {len(rrc_rejects)} RRC Rejects — check PRACH congestion and max UE count on target cell", "RRC signaling"))
            confidence_points += 1

        # --- SINR / interference ---
        confidence_max += 1
        sinr_vals = [s.sinr for s in result.signal_samples if s.sinr is not None]
        if sinr_vals and mean(sinr_vals) < 0:
            avg_sinr = mean(sinr_vals)
            recs.append(("HIGH", f"Interference: Avg SINR {avg_sinr:.1f}dB — investigate PCI/antenna tilt optimization", f"{len(sinr_vals)} samples"))
            confidence_points += 1

        # --- Beam management ---
        beam_samples = [s for s in nr_sig if s.beam_id is not None]
        confidence_max += 1
        if beam_samples:
            beams: Dict[int, List[float]] = defaultdict(list)
            for s in beam_samples:
                if s.sinr is not None:
                    beams[s.beam_id].append(s.sinr)
            if len(beams) >= 2:
                beam_sinrs = {bid: mean(vals) for bid, vals in beams.items() if vals}
                anchor = max(beam_sinrs, key=lambda b: len(beams[b]))
                best = max(beam_sinrs, key=beam_sinrs.get)
                if best != anchor and beam_sinrs[best] - beam_sinrs[anchor] > 5:
                    gap = beam_sinrs[best] - beam_sinrs[anchor]
                    recs.append(("MEDIUM", f"Beam: SSB {anchor} (anchor) vs SSB {best} (best) — {gap:.1f}dB gap, check beamFailureDetectionTimer", "0xB821"))
                    confidence_points += 1

        # --- Signal quality ---
        confidence_max += 1
        rsrp_vals = [s.rsrp for s in result.signal_samples if s.rsrp is not None]
        if rsrp_vals:
            confidence_points += 1  # we have RF data

        # Print recommendations
        if recs:
            print(f"\n  {C.BOLD}Prioritized Actions:{C.RESET}")
            for i, (prio, rec, evidence) in enumerate(recs, 1):
                color = C.RED if prio == "HIGH" else C.YELLOW
                print(f"  {color}  {i}. [{prio}] {rec}")
                print(f"     Evidence: {evidence}{C.RESET}")
        else:
            print(f"\n  {C.GREEN}  No critical issues detected.{C.RESET}")

        # Confidence score
        confidence = min(10, max(1, int(confidence_points / max(confidence_max, 1) * 10) + 3))
        # Boost if we have good data coverage
        if len(result.signal_samples) > 1000:
            confidence = min(10, confidence + 1)
        if len(result.phy_samples) > 100:
            confidence = min(10, confidence + 1)

        bar = "█" * confidence + "░" * (10 - confidence)
        color = C.GREEN if confidence >= 8 else C.YELLOW if confidence >= 6 else C.RED
        print(f"\n  {C.BOLD}Diagnostic Confidence: {color}[{bar}] {confidence}/10{C.RESET}")
        detail_parts = []
        detail_parts.append(f"{len(result.signal_samples):,} RF samples")
        detail_parts.append(f"{len(result.phy_samples):,} PHY samples")
        detail_parts.append(f"{len(result.rach_events)} RACH events")
        detail_parts.append(f"{len(result.anomalies)} anomalies analyzed")
        print(f"  Based on: {' | '.join(detail_parts)}")
        print()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _dominant_pci(samples: list) -> Optional[int]:
        if not samples:
            return None
        counts: Dict[int, int] = defaultdict(int)
        for s in samples:
            if s.pci is not None:
                counts[s.pci] += 1
        return max(counts, key=counts.get) if counts else None

    @staticmethod
    def _rsrp_at_time(result: AnalysisResult, ts, tech: str) -> str:
        best = None
        best_delta = 999.0
        for s in result.signal_samples:
            if s.tech == tech and s.rsrp is not None:
                delta = abs((s.timestamp - ts).total_seconds())
                if delta < best_delta:
                    best_delta = delta
                    best = s
        if best and best_delta < 5.0:
            return f"{best.rsrp:.1f}dBm"
        return ""


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
  %(prog)s log.hdf --rf                          # RF optimization dashboard
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
    parser.add_argument("--rf", action="store_true",
                        help="RF optimization analysis (coverage, throughput, RACH, PCI, interference)")
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
    show_rf = args.rf or args.all

    # Default to summary if nothing else specified
    if not any([show_summary, show_timeline, show_ladder, show_failures,
                show_mobility, show_states, show_rf, args.csv]):
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

    if show_rf:
        DiagnosticReport().render(proc, filtered)

    # CSV export
    if args.csv:
        CSVExporter().export(filtered, args.csv)


if __name__ == "__main__":
    main()
