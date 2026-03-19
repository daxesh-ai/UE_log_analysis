# UE Signaling Analyzer

LTE/NR signaling message analysis tool for network optimization engineers. Provides detailed signaling views for RRC/NAS/OTA troubleshooting — protocol timelines, ladder diagrams, failure analysis, mobility tracking, state machine views, and RF optimization dashboards.

Built on top of `qcom_log_analyzer.py` which provides the binary parsing/decoding engine.

## Requirements

- Python 3.8+
- `qcom_log_analyzer.py` in the parent directory (`../qcom_log_analyzer.py`)
- No external dependencies (standard library only)

## Quick Start

```bash
# Default summary dashboard
python3 ue_signal_analyzer.py <logfile.hdf>

# Full protocol timeline
python3 ue_signal_analyzer.py <logfile.hdf> --timeline

# Failure analysis
python3 ue_signal_analyzer.py <logfile.hdf> --failures

# RF optimization dashboard
python3 ue_signal_analyzer.py <logfile.hdf> --rf

# All views at once
python3 ue_signal_analyzer.py <logfile.hdf> --all
```

## Views

| Flag | View | Description |
|------|------|-------------|
| `--summary` | Summary Dashboard | Message distribution, call mode, bands, CQI, failures, signal quality (default) |
| `--timeline` | Timeline | Chronological table of all signaling events with tech, mode, band, cause |
| `--ladder` | Ladder Diagram | ASCII UE <-> Network protocol flow grouped by procedure |
| `--failures` | Failure Analysis | Filtered view of rejects/failures with cause codes and signal context |
| `--mobility` | Mobility Analysis | Serving cell timeline, handovers, band usage, mode transitions |
| `--states` | State Machine | RRC/NAS state transitions with durations and ASCII timeline bar |
| `--rf` | RF Optimization | Signal quality analytics, throughput stats, cell statistics, RF recommendations |
| `--all` | All Views | Show every view above |
| `--csv [FILE]` | CSV Export | Export all events to CSV (default: `signaling_events.csv`) |

## Filters

```bash
# NR-only events
python3 ue_signal_analyzer.py log.hdf --timeline --filter-tech nr

# LTE-only events
python3 ue_signal_analyzer.py log.hdf --timeline --filter-tech lte

# Filter by message type substring
python3 ue_signal_analyzer.py log.hdf --timeline --filter-msg Reestablishment

# Time range filter
python3 ue_signal_analyzer.py log.hdf --timeline --time-range "10:00:00" "11:00:00"
```

## CLI Reference

```
ue_signal_analyzer.py <logfile>
  --summary          Dashboard overview (default)
  --timeline         Full chronological message timeline
  --ladder           Protocol ladder diagram
  --failures         Failure/reject analysis
  --mobility         Cell & handover analysis
  --states           RRC/NAS state machine view
  --rf               RF optimization dashboard
  --all              Show all views
  --csv [OUTFILE]    Export to CSV
  --filter-tech {lte,nr}
  --filter-msg TEXT  Filter by message type substring
  --time-range START END
  --no-color         Disable colors
  --verbose / -v     Verbose packet output
```

## Supported Log Codes

### LTE

| Code | Name |
|------|------|
| 0xB0E0 | LTE RRC OTA (UPER-decoded) |
| 0xB0C2 | LTE RRC State |
| 0xB0C1 | LTE NAS EMM OTA |
| 0xB0C0 | LTE NAS EMM State (ciphered message detection) |
| 0xB0E2 | LTE NAS EMM OTA (Security Protected) |
| 0xB0E3 | LTE NAS ESM OTA |
| 0xB060 | LTE ML1 Serving Cell Measurement |
| 0xB193 | LTE ML1 Serving Cell Measurement (v2) |
| 0xB139 | LTE ML1 PDSCH Stat (MCS/modulation/CA) |
| 0xB063 | LTE MAC DL Transport Block |
| 0xB064 | LTE MAC UL Transport Block |
| 0xB061 | LTE MAC RACH Attempt (legacy) |
| 0xB167 | LTE MAC RACH Config |
| 0xB168 | LTE MAC RACH Attempt (Msg1/Msg2/Msg3) |
| 0xB0ED | LTE RRC Serving Cell Info |
| 0xB0A0 | LTE PDCP DL Stats |
| 0xB0A1 | LTE PDCP UL Stats |

### 5G NR

| Code | Name |
|------|------|
| 0xB887 | NR RRC OTA (UPER-decoded, v13+ with NR-ARFCN) |
| 0xB801 | NR RRC OTA (SA Registration) |
| 0xB802 | NR NAS OTA (SA NAS signaling) |
| 0xB808 | NR RRC State |
| 0xB8D8 | NR NAS 5GMM State |
| 0xB809 | NR NAS 5GMM State (Alt) |
| 0xB80A | NR NAS 5GSM OTA |
| 0xB80B | NR NAS 5GMM OTA Plain |
| 0xB8D2 | NR ML1 Measurement Database |
| 0xB821 | NR ML1 Serving Cell Beam (SSB RSRP/RSRQ, SINR) |
| 0xB822 | NR ML1 PDSCH Status (MCS, Rank/MIMO, BLER) |
| 0xB823 | NR ML1 PUSCH Power (UL power control) |
| 0xB825 | NR Radio Link Failure Report |
| 0xB883 | NR MAC RACH Trigger (cause) |
| 0xB884 | NR MAC RACH Attempt (Msg1 preamble/power) |
| 0xB885 | NR MAC RACH Response (Msg2 TA/grant/RNTI) |
| 0xB868 | NR MAC PDSCH Stats |
| 0xB869 | NR MAC PUSCH Stats |
| 0xB8D0 | NR ML1 Searcher |
| 0xB814 | NR PDCP DL Stats |

## Key Features

### ASN.1 UPER RRC Decoding

RRC messages are decoded from actual PDU content using UPER (Unaligned PER) bit-level parsing:
- Extracts outer CHOICE (c1 vs messageClassExtension) from bit 7 of first PDU byte
- Decodes c1 index (N bits depending on channel type) to resolve message name
- For `SystemInformation`, identifies which SIB (SIB2-SIB16) from byte 2
- Channel-type-aware fallbacks when PDU offset can't be determined

### NAS Ciphered Message Detection

NAS messages are classified by security header type:
- **sec_hdr 0**: Plain NAS — message type decoded directly
- **sec_hdr 1/3**: Integrity-protected only — inner message type extracted
- **sec_hdr 2/4**: Ciphered — labeled as `Ciphered NAS EMM` (encrypted PDU)

### RACH Event Decoding

Decodes RACH attempts with:
- Preamble index, timing advance, contention type
- Result classification (Success/Failure/Aborted)
- Version-aware parsing (v1-2 fixed layout, v3+ sub-packet structure)
- Fallback field scanner for unknown payload layouts
- RACH failures flagged as anomalies

### SA/NSA/LTE-only Mode Detection

Automatically detects UE operating mode by correlating LTE and NR RRC state timelines:
- **NSA (EN-DC)**: LTE + NR both in RRC Connected
- **SA**: NR Connected without LTE Connected
- **LTE-only**: LTE Connected without NR

### EARFCN/NR-ARFCN to Band Mapping

Built-in lookup tables for common bands:
- **LTE**: B1-B71 (EARFCN -> Band)
- **NR**: n2-n261 (NR-ARFCN -> Band)

### NR Band Properties

- **Band -> SCS mapping**: Typical subcarrier spacing per band (15/30/120 kHz)
- **Band -> Duplex mode**: FDD, TDD, or SDL classification
- **Slots-per-frame calculation** from SCS for throughput analysis

### CQI / 5QI Extraction

- **CQI** (LTE): Extracted from MAC DL TB logs, categorized as poor/fair/good/excellent
- **5QI** (NR): Derived from PDU Session Establishment Accept messages

### RF Optimization Dashboard

All-in-one RF engineering view with:
- Signal quality analytics (RSRP/RSRQ/SINR statistics and distributions)
- Throughput statistics (DL/UL with peak/average/percentiles)
- Per-cell statistics (PCI, band, signal quality, dwell time)
- RF optimization recommendations based on detected issues

### RRC/NAS Cause Code Tables

- **EMM Cause Codes**: 3GPP TS 24.301
- **5GMM Cause Codes**: 3GPP TS 24.501
- **RRC Release Causes**: CS fallback, handover cancellation, suspend, DRB integrity failure
- **RRC Reestablishment Causes**: Reconfiguration failure, handover failure
- **RRC Reject Reasons**: Wait timer, max UE, congestion

## Architecture

```
ue_signal_analyzer.py
├── SignalingEvent (unified dataclass)
├── LogProcessor (parse -> decode -> analyze -> unify)
├── SummaryDashboard
├── TimelineRenderer
├── LadderRenderer
├── FailureAnalyzer
├── MobilityAnalyzer
├── StateMachineRenderer
├── RFOptimizationView
├── CSVExporter
└── main() with argparse
         │
         v
../qcom_log_analyzer.py
├── DLFParser (binary .dlf/.isf/.hdf parsing)
├── LTEAnalyzer (LTE packet decoding + UPER RRC + RACH)
├── NR5GAnalyzer (NR packet decoding + UPER RRC)
├── InsightEngine (anomaly detection)
├── _decode_rrc_msg_from_pdu() (ASN.1 UPER decoder)
└── Data classes (RRCEvent, NASEvent, SignalSample, ThroughputSample, etc.)
```

## Examples

### Summary Dashboard
```
================================================================================
  SIGNALING SUMMARY DASHBOARD
================================================================================
  Log Period : 2025-10-04 22:58:06 -> 2025-10-04 23:55:59
  Duration   : 0h 57m 53s
  Total Pkts : 624463  (parse errors: 0)

  Message Distribution:
    Layer                LTE       NR    Total
    ─────────────── ──────── ──────── ────────
    RRC                   55       52      107
    NAS-EMM              658        0      658
    NAS-5GMM               0      197      197
    ─────────────── ──────── ──────── ────────
    TOTAL                714      249      963

  Failure Stats:
    Critical : 30
    Warnings : 11
    Top failures:
      RACH Failure: 22
      RRCReject: 8

  Anomaly Summary:
    rach_failure            : 22
    rrc_reject              : 8
```

### Protocol Timeline
```
  TIME            TECH  DIR  LAYER      CHANNEL      MESSAGE TYPE                PCI
  ──────────────────────────────────────────────────────────────────────────────────
  23:01:41.967    LTE   UL   NAS-EMM                 Detach Request (SecProt)        [!]
  23:01:43.080    LTE   UL   RRC                     RACH Failure                    [!!]
  23:02:14.405    NR    DL   RRC        CCCH-DL      RRCSetup                    1
  23:19:54.846    NR    DL   RRC        CCCH-DL      RRCReject                   1   [!!]
```

### Protocol Ladder
```
--- [23:01:41.967] Detach (LTE) ---
    UE                                            Network
    |  ---[Detach Request (SecProt)]---->        |

--- [23:01:43.080] RACH (LTE) ---
    |  ---[RACH Failure]---->                    |

--- [23:02:14.405] RRC Setup (NR, PCI=1) ---
    |            <----[RRCSetup]---              |
```
