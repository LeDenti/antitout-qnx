# antiTOUT for QNX — the immune black box

**Demo video (2:35, recorded live on QNX 8.0): https://youtu.be/SxYFBhuEeoE**

A real-time compounding robot on QNX 8.0, guarded by two halves that only work together:

* **the black box** proves what happened: every event is hash-chained with SHA3-256, sealed with
  **ML-DSA-65 (FIPS 204)** and periodically rooted with **SLH-DSA-SHA2-128s (FIPS 205)**, two
  post-quantum signature families, so the record still holds if one of them falls;
* **antiTOUT** stops it from going wrong: an immune supervisor in three layers (self, state, acts)
  that spots a foreign process stealing the CPU, demotes it, expels it on relapse, and puts the
  robot in a safe stop when doses drift. Every act lands in the black box, sealed.

Why QNX: in gravimetric dispensing the valve is driven from the scale every millisecond.
**A missed deadline is an overdose.**

## Architecture

| Process | Priority | Role | QNX features |
|---|---|---|---|
| `doseur` | FIFO 40 | 1 kHz weighing loop, prescription limits | timer pulses, named channel, `MsgSendPulse` |
| `antitout` | FIFO 50 | supervisor: self / state / acts | `/proc` + `DCMD_PROC_TIDSTATUS`, `SchedSet`, `ConnectServerInfo`, `procmgr_ability` |
| `boitenoire` | FIFO 15 | resource manager `/dev/boitenoire` | `resmgr_attach`, `iofunc_client_info_ext` membrane, `pulse_attach` |
| `intrus` | — | demo attacker, not in the self | |

The control loop never waits for the black box: events go through a lock-free ring in shared
memory, announced by a non-blocking pulse. Signing runs at low priority.

## Status (19 Nov 2026)

* Portable core (`src/`, `outils/`, `tests/`) passes its tests on macOS, Linux x86_64 **and QNX 8.0**
  (1027 checks: NIST SHA3 vectors, chain, resume, payload flip, deleted event, full chain
  recomputation without the key, corrupted seal, foreign keys, torn tail).
* All QNX processes compile with QNX SDP 8.0 (qcc 12.2, x86_64) and run on the QNX 8.0 QEMU
  quickstart image. `scripts/scenarios.sh` plays the demo on the target:

| Scene | What QNX shows |
|---|---|
| Prescription within protocol | delivered 500.05 mg for 500 mg, sealed |
| Overdose x10 | `DOSE_REFUSED`, the robot never moves |
| Foreign process at FIFO 45 (above the 40 loop) | `QUARANTINE` 45 -> 1 via `SchedSet` |
| Same binary comes back and raises its priority | recognised by immune memory, `EXPEL` |
| Foreign binary opens `/dev/boitenoire` for writing | `EACCES` in the resmgr open handler, `MEMBRANE_REFUSE` sealed at once |
| Rewrite history: 500 mg dose turned into 5000 mg on a copy | `bn_verify`: `TAMPERED: event content altered, event seq 17` |

* Found on the target, fixed: the first hunt killed `devb-eide`, `pci-server` and `slogger2`
  (an autoimmune disease: their interrupt threads run at 254 and they were not in the self).
  antiTOUT now has **central tolerance** (binaries already running when it starts are self,
  unless immune memory says otherwise) and judges relapse on `real_priority`, not on the
  priority a quarantined server inherits from its clients.
* Timings under full software emulation (QEMU TCG on an Apple M5): ML-DSA-65 seal 15 ms,
  SLH-DSA-128s root 2.5 s, dispensing loop worst lateness 2-4 ms. The whole guest can stall
  over 50 ms there, so the demo sets `ANTITOUT_HB_MS=300`; on hardware or KVM keep the 50 ms default.
* Found while filming, fixed: pulses queue by priority, so antiTOUT's watch timer (priority 50)
  overtook the dosing loop's heartbeats (priority 40) still waiting in its channel and raised false
  missed-deadline alerts of ~1.3 s. antiTOUT now drains every queued pulse (`MsgReceivePulse`
  with a zero `TimerTimeout`) before it judges lateness. Also: no second quarantine of a thread
  already at priority 1, and no `INTRUDER` record for a process already gone.

## Build

```bash
# host (macOS / Linux): liboqs minimal build, then
cmake -S . -B build-host -DOQS_PREFIX=/path/to/liboqs-install && cmake --build build-host
./build-host/test_journal

# QNX 8.0 (inside a Linux x86_64 host with QNX SDP 8.0 + host tools)
scripts/construire-qnx.sh x86_64      # or aarch64 for Raspberry Pi 5
```

On the target: `scripts/demarrer.sh`, then `cat /dev/boitenoire` and
`bn_verify /data/antitout/journal.bn /data/antitout/cles`.

## Honest limits

* XRPL anchoring of the daily root is a timestamp witness only; XRPL signatures are not post-quantum.
* Signing keys live on the device; a root attacker can sign new entries, but cannot rewrite
  sealed history without breaking the chain.
* Protocol maxima in `doseur.c` are illustrative demo values, not clinical guidance.
