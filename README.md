# UE Signaling Analyzer

LTE/NR signaling message analysis tool for network optimization engineers. Provides detailed signaling views for RRC/NAS/OTA troubleshooting — protocol timelines, ladder diagrams, failure analysis, mobility tracking, state machine views, and RF optimization dashboards.

Supports both **Qualcomm DIAG** binary logs (`.dlf`/`.isf`/`.hdf`) and **Apple sysdiagnose** (`.logarchive`/`.tar.gz`) with automatic format detection.

Built on top of `qcom_log_analyzer.py` (Qualcomm) and `apple_log_parser.py` (Apple) which provide the parsing/decoding engines.

## Requirements

- Python 3.8+
- `qcom_log_analyzer.py` in the parent directory (`../qcom_log_analyzer.py`)
- No external dependencies (standard library only)
- For Apple sysdiagnose: macOS with `log show` command

## Quick Start

```bash
# Qualcomm DIAG log
python3 ue_signal_analyzer.py <logfile.hdf>

# Apple sysdiagnose (auto-detected)
python3 ue_signal_analyzer.py <sysdiagnose.tar.gz>
python3 ue_signal_analyzer.py <sysdiagnose.logarchive/>

# Full protocol timeline
python3 ue_signal_analyzer.py <logfile.hdf> --timeline

# Failure analysis
python3 ue_signal_analyzer.py <logfile.hdf> --failures

# RF optimization dashboard
python3 ue_signal_analyzer.py <logfile.hdf> --rf

# Interactive Q&A agent (no API key needed)
python3 ue_signal_analyzer.py <logfile.hdf> --agent

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
| `--agent` | Interactive Agent | Ask questions in plain English — signal, RACH, failures, throughput, etc. |
| `--all` | All Views | Show every view above (except agent) |
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
  --agent            Interactive Q&A agent
  --all              Show all views
  --csv [OUTFILE]    Export to CSV
  --filter-tech {lte,nr}
  --filter-msg TEXT  Filter by message type substring
  --time-range START END
  --no-color         Disable colors
  --verbose / -v     Verbose packet output
```

## Scripts

| File | Description |
|------|-------------|
| `ue_signal_analyzer.py` | Main analysis tool — all views, filters, agent, CSV export |
| `apple_log_parser.py` | Apple sysdiagnose parser — extracts cellular data from iOS `.logarchive` |
| `../qcom_log_analyzer.py` | Core engine — Qualcomm DIAG binary parsing, UPER RRC decoding, RACH |
| `../qcom_log_agent.py` | Claude API agent — ask questions via Claude (requires `ANTHROPIC_API_KEY`) |

## Interactive Agent (`--agent`)

Built-in Q&A agent that answers RF/network questions from parsed log data — no API key required. Parses your question, matches it to relevant topics, and returns data-driven answers.

```bash
python3 ue_signal_analyzer.py log.hdf --agent
```

```
==============================================================
  UE Log Interactive Agent
==============================================================
  Ask me anything about this log. I'll analyze the data and
  give you an expert answer. Type 'q' to quit.

  Sample questions:
    > Give me a summary
    > Why is it failing?
    > Show me the call flow
    > What is the signal quality?
    > Bearer info / VoLTE / VoNR?
    > Show carrier aggregation
    > EN-DC or NR-DC info?
    > Is there interference?
    > What should we fix?
```

### Supported Topics

| Topic | Example Questions |
|-------|-------------------|
| Summary | "Give me a summary", "What happened?", "Overview" |
| Signal | "What is the RSRP?", "How is signal quality?", "Is coverage weak?" |
| Cell | "What PCIs are seen?", "Which band?", "What frequency?" |
| RACH | "How is RACH?", "Any Msg1/Msg2 issues?", "Preamble stats?" |
| Handover | "Any handovers?", "Ping-pong?", "Mobility issues?" |
| Failures | "Any drops?", "RLF count?", "Rejects?", "Reestablishments?" |
| Throughput | "What's the speed?", "DL throughput?", "MCS stats?" |
| Interference | "PCI collision?", "Mod-3 interference?", "Noise?" |
| PHY | "BLER?", "Rank/MIMO?", "256QAM usage?", "RB allocation?" |
| Beam | "SSB beam stats?", "Beam management?" |
| QoS | "CQI?", "5QI?", "VoLTE?", "PDU session?", "Slice?" |
| CA/DC | "Carrier aggregation?", "EN-DC?", "SCell?", "SCG?" |
| Timing | "Timing advance?", "Latency?" |
| Config | "SCS?", "TDD/FDD?", "Slot config?" |
| Ladder | "Show the call flow", "Message sequence?", "Signaling diagram?" |
| Why | "Why is it failing?", "Root cause?", "What caused the drops?" |
| Fix | "What should we fix?", "Recommendations?", "Next steps?" |

### Claude API Agent (separate script)

For more advanced natural-language analysis powered by Claude:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 ../qcom_log_agent.py log.hdf
python3 ../qcom_log_agent.py log.hdf --verbose --model claude-sonnet-4-20250514
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
├── LogProcessor (auto-detect format, parse -> decode -> analyze -> unify)
│   ├── _process_qualcomm()  — Qualcomm DIAG binary logs
│   └── _process_apple()     — Apple sysdiagnose .logarchive
├── SummaryDashboard
├── TimelineRenderer
├── LadderRenderer
├── FailureAnalyzer
├── MobilityAnalyzer
├── StateMachineRenderer
├── RFOptimizationView
├── InteractiveAgent (--agent, keyword-routed Q&A)
├── CSVExporter
└── main() with argparse
         │
         v
../qcom_log_analyzer.py              apple_log_parser.py
├── DLFParser (.dlf/.isf/.hdf)       ├── AppleLogParser (.logarchive)
├── LTEAnalyzer (UPER RRC + RACH)    ├── is_apple_sysdiagnose()
├── NR5GAnalyzer (UPER RRC)          └── CommCenter/QMI log parsing
├── InsightEngine (anomaly detection)
├── _decode_rrc_msg_from_pdu()
└── Data classes (RRCEvent, NASEvent, SignalSample, etc.)
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

### Interactive Agent Session
```bash
$ python3 ue_signal_analyzer.py log.hdf --agent
```
```
==============================================================
  UE Log Interactive Agent
==============================================================
  Ask me anything about this log. I'll analyze the data and
  give you an expert answer. Type 'q' to quit.

  Sample questions:
    > Give me a summary
    > Why is it failing?
    > Show me the call flow
    > What is the signal quality?
    > What should we fix?

  > Why is it failing?

  Root Cause Analysis:

    Why is the network rejecting the UE?
    8 RRC Rejects detected. Chain:
      1. UE sends RRC Setup Request (Msg3) to gNB
      2. gNB responds with RRC Reject instead of RRC Setup
      3. Possible: cell overloaded, access barring, or UE not authorized

    Why are RACH attempts failing?
    22 RACH failures detected. Chain:
      1. UE sends RACH Msg1 (preamble) on PRACH
      2. No Msg2 (RAR) received within ra-ResponseWindow
      3. UE retransmits with power ramping until maxRetries
      Fix: Check PRACH config, RACH power offset, noise floor

  > What is the signal quality?

  Signal Quality:
    NR:  44 RRCSetup / 8 RRCReject on PCI 1
    LTE: 22 RACH Failures, 3 Detach Requests

  > Show me the call flow

  Call Flow Ladder Diagram:
                    UE                   Network (gNB/eNB)
                    |                    |
    23:01:41.967  |  ---[ Detach Request (SecProt) ]---->  | [LTE]
    23:01:43.080  |  ---[ RACH Failure ]---->              | [LTE]
    23:02:14.405  |         <----[ RRCSetup ]---           | [NR]
    23:19:54.846  |         <----[ RRCReject ]---          | [NR]

  > q
  Bye!
```

### Claude API Agent (Advanced)
```bash
# Requires Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...

# Basic usage
python3 ../qcom_log_agent.py log.hdf

# With verbose mode (shows data context sent to Claude)
python3 ../qcom_log_agent.py log.hdf --verbose

# Use a specific model
python3 ../qcom_log_agent.py log.hdf --model claude-sonnet-4-20250514
```

Example session:
```
> What happened during the call drop at 23:19?

Based on the log data, at 23:19:54 the UE received an RRC Reject from
the NR cell (PCI 1). This was preceded by multiple RACH failures on
LTE starting at 23:01, suggesting the UE was having difficulty
maintaining connectivity. The network appears congested — the UE
attempted RACH 22 times without success before switching to NR where
it was rejected 8 times.

Recommendation: Check cell capacity and PRACH configuration on the
serving NR cell (PCI 1).
```
