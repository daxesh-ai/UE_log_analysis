# UE Signaling Analyzer

LTE/NR signaling message analysis tool for network optimization engineers. Provides detailed signaling views for RRC/NAS/OTA troubleshooting — protocol timelines, ladder diagrams, failure analysis, mobility tracking, and state machine views.

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

# All views at once
python3 ue_signal_analyzer.py <logfile.hdf> --all
```

## Views

| Flag | View | Description |
|------|------|-------------|
| `--summary` | Summary Dashboard | Message distribution, call mode, bands, CQI, failures, signal quality (default) |
| `--timeline` | Timeline | Chronological table of all signaling events with tech, mode, band, cause |
| `--ladder` | Ladder Diagram | ASCII UE ↔ Network protocol flow grouped by procedure |
| `--failures` | Failure Analysis | Filtered view of rejects/failures with cause codes and signal context |
| `--mobility` | Mobility Analysis | Serving cell timeline, handovers, band usage, mode transitions |
| `--states` | State Machine | RRC/NAS state transitions with durations and ASCII timeline bar |
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
| 0xB0E0 | LTE RRC OTA |
| 0xB0C2 | LTE RRC State |
| 0xB0C1 | LTE NAS EMM OTA |
| 0xB0C0 | LTE NAS EMM State |
| 0xB0E2 | LTE NAS EMM OTA (Security Protected) |
| 0xB0E3 | LTE NAS ESM OTA |
| 0xB821 | LTE ML1 Serving Cell Measurement |
| 0xB063 | LTE MAC DL Transport Block |
| 0xB064 | LTE MAC UL Transport Block |
| 0xB061 | LTE MAC RACH Attempt |
| 0xB0ED | LTE RRC Serving Cell Info |

### 5G NR
| Code | Name |
|------|------|
| 0xB887 | NR RRC OTA |
| 0xB808 | NR RRC State |
| 0xB8D8 | NR NAS 5GMM State |
| 0xB809 | NR NAS 5GMM State (Alt) |
| 0xB80A | NR NAS 5GSM OTA |
| 0xB80B | NR NAS 5GMM OTA Plain |
| 0xB8D2 | NR ML1 Measurement Database |
| 0xB868 | NR MAC PDSCH Stats |
| 0xB869 | NR MAC PUSCH Stats |

## Key Features

### SA/NSA/LTE-only Mode Detection
Automatically detects UE operating mode by correlating LTE and NR RRC state timelines:
- **NSA (EN-DC)**: LTE + NR both in RRC Connected
- **SA**: NR Connected without LTE Connected
- **LTE-only**: LTE Connected without NR

### EARFCN/NR-ARFCN to Band Mapping
Built-in lookup tables for common bands:
- **LTE**: B1-B71 (EARFCN → Band)
- **NR**: n2-n261 (NR-ARFCN → Band)

### CQI / 5QI Extraction
- **CQI** (LTE): Extracted from MAC DL TB logs, categorized as poor/fair/good/excellent
- **5QI** (NR): Derived from PDU Session Establishment Accept messages

## Architecture

```
ue_signal_analyzer.py
├── SignalingEvent (unified dataclass)
├── LogProcessor (parse → decode → analyze → unify)
├── SummaryDashboard
├── TimelineRenderer
├── LadderRenderer
├── FailureAnalyzer
├── MobilityAnalyzer
├── StateMachineRenderer
├── CSVExporter
└── main() with argparse
         │
         ▼
../qcom_log_analyzer.py
├── DLFParser (binary .dlf/.isf/.hdf parsing)
├── LTEAnalyzer (LTE packet decoding)
├── NR5GAnalyzer (NR packet decoding)
├── InsightEngine (anomaly detection)
└── Data classes (RRCEvent, NASEvent, SignalSample, etc.)
```

## Examples

### Summary Dashboard
```
================================================================================
  SIGNALING SUMMARY DASHBOARD
================================================================================
  Log Period : 2025-10-04 16:55:43.000 → 2025-10-04 17:12:01.000
  Duration   : 0h 16m 18s
  Total Pkts : 45230  (parse errors: 12)

  Message Distribution:
    Layer             LTE       NR    Total
    ─────────────── ──────── ──────── ────────
    RRC                 412      198      610
    NAS-EMM              23        0       23
    NAS-5GMM              0       15       15
    ─────────────── ──────── ──────── ────────
    TOTAL               435      213      648
```

### Protocol Ladder
```
--- [10:23:01] RRC Setup (LTE, PCI=134, B13, NSA) ---
    UE                                            Network
    |                                              |
    |  ---[RRCConnectionRequest]---->              |
    |            <----[RRCConnectionSetup]---      |
    |  ---[RRCConnectionSetupComplete]---->        |
```
