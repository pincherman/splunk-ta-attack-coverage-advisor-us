# Splunk TA Attack Coverage Advisor, US edition

Full English version of the **TA-attack-coverage-advisor** package.

This repository contains:

- the Splunk app under `TA-attack-coverage-advisor/`
- the English technical operator guide
- the installation procedure

## Purpose

This package helps technical teams run a credible **Data Source
Assessment** by answering three questions:

1. what data is really visible in Splunk,
2. what ES would unlock from that existing telemetry,
3. which collection steps should come next.

## Structure

- `TA-attack-coverage-advisor/` , Splunk app
- `docs/dsa-assessment-technical-guide-en.md` , operator guide
- `TA-attack-coverage-advisor/INSTALLATION.md` , installation guide

## Packaging

```bash
tar -czf TA-attack-coverage-advisor.tgz TA-attack-coverage-advisor
```

## Audience

- Splunk SE teams
- partners
- consulting teams
- assessment workshops
- ES pre-POC work
