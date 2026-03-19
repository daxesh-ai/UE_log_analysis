#!/usr/bin/env python3
"""
Apple sysdiagnose Log Parser — Extract cellular RF data from iOS .logarchive

Parses CommCenter/QMI logs from Apple sysdiagnose to produce the same
AnalysisResult data structures as the Qualcomm DIAG parser, enabling
unified analysis with ue_signal_analyzer.py.

Requires macOS `log show` command for .logarchive reading.
"""

import os
import re
import struct
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import shared data structures from qcom_log_analyzer
_SCRIPT_DIR = Path(__file__).resolve().parent
for _candidate in [_SCRIPT_DIR.parent, _SCRIPT_DIR.parent.parent, Path.cwd()]:
    if (_candidate / "qcom_log_analyzer.py").exists():
        sys.path.insert(0, str(_candidate))
        break

from qcom_log_analyzer import (
    AnalysisResult,
    SignalSample,
    RRCEvent,
    NASEvent,
    RACHEvent,
    Anomaly,
)


# ---------------------------------------------------------------------------
# QMI NAS TLV types for signal measurements
# ---------------------------------------------------------------------------
QMI_TLV_NR5G_SIGNAL = 0x17     # int16 RSRP (dBm) + int16 SNR (0.1 dB)
QMI_TLV_NR5G_RSRQ = 0x18       # int16 RSRQ (dB)
QMI_TLV_LTE_SIGNAL = 0x14      # LTE signal: int8 RSSI + ...


class AppleLogParser:
    """Parse Apple sysdiagnose .logarchive for cellular RF data."""

    def __init__(self, logarchive_path: str, verbose: bool = False):
        self.logarchive_path = logarchive_path
        self.verbose = verbose

    def parse(self) -> AnalysisResult:
        """Run log show and parse CommCenter output into AnalysisResult."""
        result = AnalysisResult()

        # Resolve logarchive path
        archive_path = self._find_logarchive(self.logarchive_path)
        if not archive_path:
            print(f"[ERROR] Could not find .logarchive in {self.logarchive_path}")
            return result

        print(f"  Extracting cellular data from: {archive_path}")
        print(f"  Running `log show` (this may take a moment)...")

        # Run log show to extract CommCenter logs
        lines = self._run_log_show(archive_path)
        if not lines:
            print("[WARN] No CommCenter log entries found.")
            return result

        print(f"  Parsing {len(lines)} CommCenter log entries...")

        for line in lines:
            try:
                ts = self._parse_timestamp(line)
                if ts is None:
                    continue

                # QMI NAS Signal Strength Response (0x004f)
                if "MsgId=0x004f" in line and "Resp" in line and "Svc=0x03(NAS)" in line:
                    self._parse_qmi_signal(line, ts, result)

                # QMI NAS Signal Indication (0x0051)
                elif "MsgId=0x0051" in line and "Ind" in line and "Svc=0x03(NAS)" in line:
                    self._parse_qmi_signal(line, ts, result)

                # Cell Monitor Update (serving + neighbor info)
                elif "cellMonitorUpdate" in line or "cellInfo" in line:
                    self._parse_cell_info(line, ts, result)

                # Registration state
                elif "reg.qmi" in line or "reg.ctr" in line:
                    self._parse_registration(line, ts, result)

                # Data status (RAT, mode)
                elif "getDataStatus" in line and "radioTechnology" in line:
                    self._parse_data_status(line, ts, result)

                # NRARFCN/PCI from cell measurement (cm.2 category)
                elif "NRARFCN:" in line and "PCI:" in line:
                    self._parse_nr_cell_measurement(line, ts, result)

                # QMI NAS 0x0051 signal indication (also caught above, but catch stray formats)
                elif "MsgId=0x0051" in line and "Svc=0x03" in line:
                    self._parse_qmi_signal(line, ts, result)

                # Signal bars (rough quality when detailed measurements unavailable)
                elif "Computed base bars" in line:
                    self._parse_signal_bars(line, ts, result)

                # NR/LTE cell measurement from cm category with RSRP
                elif "cm." in line and ("RSRP" in line or "rsrp" in line):
                    self._parse_nr_cell_measurement(line, ts, result)

            except Exception:
                result.parse_errors += 1

        # Compute file duration
        all_ts = [s.timestamp for s in result.signal_samples]
        all_ts.extend(e.timestamp for e in result.rrc_events)
        if all_ts:
            result.first_timestamp = min(all_ts)
            result.last_timestamp = max(all_ts)
            result.file_duration = result.last_timestamp - result.first_timestamp

        print(f"  Extracted: {len(result.signal_samples)} signal samples, "
              f"{len(result.rrc_events)} RRC events")

        return result

    # ------------------------------------------------------------------
    # Log Show execution
    # ------------------------------------------------------------------
    @staticmethod
    def _find_logarchive(path: str) -> Optional[str]:
        """Find the .logarchive directory within a sysdiagnose path."""
        p = Path(path)
        # Direct logarchive
        if p.is_dir() and p.name.endswith(".logarchive"):
            return str(p)
        # sysdiagnose directory containing system_logs.logarchive
        if p.is_dir():
            candidates = list(p.rglob("system_logs.logarchive"))
            if candidates:
                return str(candidates[0])
            # Check for tar.gz inside directory — extract it
            for child in p.iterdir():
                if child.is_file() and "sysdiagnose" in child.name and child.name.endswith(".tar.gz"):
                    return AppleLogParser._find_logarchive(str(child))
            # Extracted tar.gz subfolder
            for child in p.iterdir():
                if child.is_dir():
                    inner = child / "system_logs.logarchive"
                    if inner.is_dir():
                        return str(inner)
        # tar.gz — need to extract first
        if p.is_file() and p.name.endswith(".tar.gz"):
            extract_dir = p.parent / p.stem.replace(".tar", "")
            if not extract_dir.exists():
                print(f"  Extracting {p.name}...")
                subprocess.run(["tar", "xzf", str(p), "-C", str(p.parent)],
                               capture_output=True, timeout=300)
            return AppleLogParser._find_logarchive(str(p.parent))
        return None

    def _run_log_show(self, archive_path: str) -> List[str]:
        """Execute `log show` to extract CommCenter cellular data."""
        predicate = (
            'process == "CommCenter" AND ('
            'message CONTAINS "MsgId=0x004f" OR '
            'message CONTAINS "MsgId=0x0051" OR '
            'message CONTAINS "MsgId=0x004e" OR '
            'message CONTAINS "MsgId=0x5556" OR '
            'message CONTAINS "cellMonitorUpdate" OR '
            'message CONTAINS "cellInfo" OR '
            'message CONTAINS "NRARFCN:" OR '
            'message CONTAINS "EARFCN" OR '
            'message CONTAINS "Computed base bars" OR '
            'message CONTAINS "radioTechnology" OR '
            'message CONTAINS "Serving System" OR '
            'message CONTAINS "handover" OR '
            'message CONTAINS "HO " OR '
            'message CONTAINS "reestablishment" OR '
            'message CONTAINS "Radio Link" OR '
            'message CONTAINS "RRC" OR '
            'category BEGINSWITH "sig" OR '
            'category BEGINSWITH "reg" OR '
            'category BEGINSWITH "cm")'
        )
        try:
            proc = subprocess.run(
                ["/usr/bin/log", "show", archive_path,
                 "--predicate", predicate,
                 "--style", "compact"],
                capture_output=True, text=True, timeout=300
            )
            lines = proc.stdout.strip().split("\n")
            # Filter out header and separator lines
            return [l for l in lines if l and not l.startswith("Timestamp") and not l.startswith("=")]
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"[ERROR] log show failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Timestamp parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_timestamp(line: str) -> Optional[datetime]:
        """Extract timestamp from `log show --style compact` output."""
        # Format: 2026-02-05 10:24:55.877
        m = re.match(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})", line)
        if m:
            try:
                return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                pass
        return None

    # ------------------------------------------------------------------
    # QMI NAS Signal Parsing (TLV 0x17 / 0x18)
    # ------------------------------------------------------------------
    def _parse_qmi_signal(self, line: str, ts: datetime, result: AnalysisResult) -> None:
        """Parse QMI NAS 0x004f/0x0051 response for NR5G RSRP/SINR/RSRQ."""
        m = re.search(r"Bin=\['([0-9A-Fa-f ]+)'\]", line)
        if not m:
            return

        hex_str = m.group(1).replace(" ", "")
        try:
            raw = bytes.fromhex(hex_str)
        except ValueError:
            return

        if len(raw) < 13:
            return

        # QMI message layout:
        # [0]    QMUX IF type (0x01)
        # [1:3]  QMUX length (uint16 LE)
        # [3]    QMUX flags (0x80=resp, 0x04=ind)
        # [4]    Service type (0x03=NAS)
        # [5]    Client ID
        # [6]    QMI flags (0x02=resp)
        # [7:9]  Transaction ID (uint16 LE)
        # [9:11] Message ID (uint16 LE)
        # [11:13] TLV payload length (uint16 LE)
        # [13:]  TLV data starts here
        tlv_start = 13

        rsrp = None
        sinr = None
        rsrq = None
        lte_rssi = None

        i = tlv_start
        while i + 3 <= len(raw):
            tlv_type = raw[i]
            tlv_len = struct.unpack_from("<H", raw, i + 1)[0]
            tlv_data = i + 3

            if tlv_len == 0 or tlv_data + tlv_len > len(raw):
                break

            # TLV 0x17: NR5G RSRP (int16 dBm) + SNR (int16, 0.1 dB)
            if tlv_type == QMI_TLV_NR5G_SIGNAL and tlv_len >= 4:
                rsrp_raw = struct.unpack_from("<h", raw, tlv_data)[0]
                sinr_raw = struct.unpack_from("<h", raw, tlv_data + 2)[0]
                if -140 <= rsrp_raw <= -44:
                    rsrp = float(rsrp_raw)
                if -200 <= sinr_raw <= 300:
                    sinr = sinr_raw / 10.0

            # TLV 0x18: NR5G RSRQ (int16, dB)
            elif tlv_type == QMI_TLV_NR5G_RSRQ and tlv_len >= 2:
                rsrq_raw = struct.unpack_from("<h", raw, tlv_data)[0]
                if -30 <= rsrq_raw <= 0:
                    rsrq = float(rsrq_raw)

            # TLV 0x14: LTE signal (int8 RSSI + more)
            elif tlv_type == QMI_TLV_LTE_SIGNAL and tlv_len >= 1:
                lte_rssi_raw = struct.unpack_from("<b", raw, tlv_data)[0]
                if -120 <= lte_rssi_raw <= -30:
                    lte_rssi = float(lte_rssi_raw)

            i = tlv_data + tlv_len

        # Create NR signal sample
        if rsrp is not None:
            sample = SignalSample(
                timestamp=ts, tech="NR",
                rsrp=rsrp, rsrq=rsrq, sinr=sinr,
                is_serving=True,
            )
            result.signal_samples.append(sample)
            if self.verbose:
                print(f"  [Apple QMI NR] RSRP={rsrp} RSRQ={rsrq} SINR={sinr}")

        # Create LTE signal sample
        if lte_rssi is not None and rsrp is None:
            sample = SignalSample(
                timestamp=ts, tech="LTE",
                rssi=lte_rssi, is_serving=True,
            )
            result.signal_samples.append(sample)

    # ------------------------------------------------------------------
    # Cell Info Dict Parsing
    # ------------------------------------------------------------------
    def _parse_cell_info(self, line: str, ts: datetime, result: AnalysisResult) -> None:
        """Parse cellMonitorUpdate structured dict for serving/neighbor cell info."""
        # Extract key-value pairs from the dict-like structure
        # Look for: nrarfcn = 648672; pid = 349; band = 77; scs = 1; type = serving;
        fields = {}
        for m in re.finditer(r"(\w+)\s*=\s*([^;,}]+)", line):
            key = m.group(1).strip()
            val = m.group(2).strip().rstrip(";")
            fields[key] = val

        if not fields:
            return

        tech = "NR" if fields.get("rat") == "NR" else "LTE" if fields.get("rat") == "LTE" else ""
        if not tech and ("nrarfcn" in fields or "NRARFCN" in fields):
            tech = "NR"

        pci = None
        for key in ["pid", "pci", "PCI"]:
            if key in fields:
                try:
                    pci = int(fields[key])
                except ValueError:
                    pass

        earfcn = None
        for key in ["nrarfcn", "NRARFCN", "earfcn", "EARFCN"]:
            if key in fields:
                try:
                    earfcn = int(fields[key])
                except ValueError:
                    pass

        band_num = None
        if "band" in fields:
            try:
                band_num = int(fields["band"])
            except ValueError:
                pass

        scs = None
        if "scs" in fields:
            try:
                scs_val = int(fields["scs"])
                # scs=1 means 30kHz, scs=0 means 15kHz in NR
                scs = {0: 15, 1: 30, 2: 60, 3: 120}.get(scs_val, scs_val)
            except ValueError:
                pass

        is_serving = fields.get("type", "").lower() == "serving"

        # Parse RSRP/RSRQ if present (neighbors often have these)
        rsrp = None
        rsrq = None
        if "rsrp" in fields:
            try:
                v = int(fields["rsrp"])
                if -140 <= v <= -44:
                    rsrp = float(v)
            except ValueError:
                pass
        if "rsrq" in fields:
            try:
                v = int(fields["rsrq"])
                if -30 <= v <= 0:
                    rsrq = float(v)
            except ValueError:
                pass

        if pci is not None and tech:
            sample = SignalSample(
                timestamp=ts,
                tech=tech,
                pci=pci,
                earfcn=earfcn,
                band=band_num,
                rsrp=rsrp,
                rsrq=rsrq,
                is_serving=is_serving,
            )
            result.signal_samples.append(sample)

        # Also create an RRC event for serving cell info
        if is_serving and pci is not None:
            details_parts = []
            if earfcn:
                details_parts.append(f"ARFCN={earfcn}")
            if band_num:
                details_parts.append(f"Band={band_num}")
            if scs:
                details_parts.append(f"SCS={scs}kHz")

            event = RRCEvent(
                timestamp=ts,
                tech=tech,
                event="ServingCellInfo",
                direction="",
                details=", ".join(details_parts),
                pci=pci,
                earfcn=earfcn,
            )
            result.rrc_events.append(event)

    # ------------------------------------------------------------------
    # NR Cell Measurement (NRARFCN/PCI lines from cm.2 category)
    # ------------------------------------------------------------------
    def _parse_nr_cell_measurement(self, line: str, ts: datetime, result: AnalysisResult) -> None:
        """Parse 'NRARFCN: 176910, PCI: 404, RSRP: ...' lines."""
        arfcn_m = re.search(r"NRARFCN:\s*(\d+)", line)
        pci_m = re.search(r"PCI:\s*(\d+)", line)
        rsrp_m = re.search(r"RSRP:\s*(-?\d+)", line)
        rsrq_m = re.search(r"RSRQ:\s*(-?\d+)", line)
        scs_m = re.search(r"SCS:\s*(\d+)", line)
        bw_m = re.search(r"Bandwidth:\s*(\d+)", line)
        is_sa_m = re.search(r"Is SA:\s*(\d+)", line)
        neighbor_m = re.search(r"Neighbor Type:\s*(\d+)", line)

        if not arfcn_m or not pci_m:
            return

        arfcn = int(arfcn_m.group(1))
        pci = int(pci_m.group(1))

        rsrp = None
        rsrq = None
        if rsrp_m:
            v = int(rsrp_m.group(1))
            if -140 <= v <= -44:
                rsrp = float(v)
            # 32767 = invalid/not measured
        if rsrq_m:
            v = int(rsrq_m.group(1))
            if -30 <= v <= 0:
                rsrq = float(v)

        is_neighbor = neighbor_m is not None

        sample = SignalSample(
            timestamp=ts,
            tech="NR",
            pci=pci,
            earfcn=arfcn,
            rsrp=rsrp,
            rsrq=rsrq,
            is_serving=not is_neighbor,
        )
        result.signal_samples.append(sample)

    # ------------------------------------------------------------------
    # Registration State
    # ------------------------------------------------------------------
    def _parse_registration(self, line: str, ts: datetime, result: AnalysisResult) -> None:
        """Parse registration state changes."""
        if "Serving System:" in line:
            m = re.search(r"MCC:\s*(\d+)\s+MNC:\s*(\d+)\s+Registration Status:\s*(\w+)", line)
            if m:
                status = m.group(3)
                event = RRCEvent(
                    timestamp=ts,
                    tech="NR",
                    event=f"Registration: {status}",
                    details=f"PLMN {m.group(1)}-{m.group(2)}",
                )
                result.rrc_events.append(event)

        elif "kRatNR system:" in line or "kRatLTE system:" in line:
            tech = "NR" if "kRatNR" in line else "LTE"
            if "PS attach - true" in line:
                event = RRCEvent(timestamp=ts, tech=tech, event="PS Attached")
                result.rrc_events.append(event)
            elif "PS attach - false" in line:
                event = RRCEvent(timestamp=ts, tech=tech, event="PS Detached")
                result.rrc_events.append(event)

    # ------------------------------------------------------------------
    # Data Status
    # ------------------------------------------------------------------
    def _parse_data_status(self, line: str, ts: datetime, result: AnalysisResult) -> None:
        """Parse CTDataStatus for RAT and connection info."""
        rat_m = re.search(r"radioTechnology=(\w+)\s*\((\d+)\)", line)
        indicator_m = re.search(r"indicator=(\w+)\s*\((\d+)\)", line)

        if rat_m:
            rat = rat_m.group(1)
            tech = "NR" if "NR" in rat else "LTE" if "LTE" in rat else rat
            event = RRCEvent(
                timestamp=ts, tech=tech,
                event=f"Data Status: {rat}",
                details=f"indicator={indicator_m.group(1)}" if indicator_m else "",
            )
            result.rrc_events.append(event)

    # ------------------------------------------------------------------
    # Signal Bars (approximate quality)
    # ------------------------------------------------------------------
    def _parse_signal_bars(self, line: str, ts: datetime, result: AnalysisResult) -> None:
        """Parse 'Computed base bars of N from model X' for rough signal quality."""
        m = re.search(r"Computed base bars of (\d+) from model (\w+)", line)
        if not m:
            return
        bars = int(m.group(1))
        # Map bars to approximate RSRP (rough, for when QMI data is unavailable)
        bar_to_rsrp = {0: -130, 1: -115, 2: -105, 3: -95, 4: -80, 5: -70}
        approx_rsrp = bar_to_rsrp.get(min(bars, 5), -110)
        sample = SignalSample(
            timestamp=ts, tech="NR", rsrp=float(approx_rsrp),
            is_serving=True,
        )
        result.signal_samples.append(sample)


# ---------------------------------------------------------------------------
# Utility: detect if a path is an Apple sysdiagnose
# ---------------------------------------------------------------------------
def is_apple_sysdiagnose(path: str) -> bool:
    """Check if the given path is an Apple sysdiagnose archive or directory."""
    p = Path(path)
    if p.is_dir():
        # Check for system_logs.logarchive inside
        if (p / "system_logs.logarchive").is_dir():
            return True
        # Check children: sysdiagnose subdirectory or tar.gz
        for child in p.iterdir():
            if child.is_dir() and (child / "system_logs.logarchive").is_dir():
                return True
            if child.is_file() and "sysdiagnose" in child.name and child.name.endswith(".tar.gz"):
                return True
    if p.is_file() and "sysdiagnose" in p.name and p.name.endswith(".tar.gz"):
        return True
    if p.name.endswith(".logarchive"):
        return True
    return False
