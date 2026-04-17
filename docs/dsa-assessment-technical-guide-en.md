# DSA, Data Source Assessment
## Technical user guide

_Date: 2026-04-17_

---

## 1. Purpose

This guide explains how to use the **DSA, Data Source Assessment**
package and dashboard to run a credible technical assessment on a Splunk
instance.

The objective is to help a technical population answer four questions:

1. **What data is really visible in Splunk today?**
2. **What would Splunk Enterprise Security unlock from that existing
   telemetry?**
3. **Which collection gaps still limit coverage?**
4. **How should the result be presented when ES is present versus when ES
   is not detected?**

---

## 2. Intended audience

This documentation is written for:

- Splunk SE teams
- partners
- consulting teams
- ES pre-POC workshops
- technical telemetry assessment sessions

This is not an operational SOC runbook.

---

## 3. What the tool is, and what it is not

### 3.1 What it is

The DSA is an **audit and analysis tool** that combines:

- telemetry really observed on the Splunk instance,
- an embedded catalog of data sources and detections derived from
  `security_content`,
- and, when possible, a view of current ES coverage.

It is meant to transform technical inventory into:

- a telemetry assessment,
- an ES value projection,
- and a prioritized collection backlog.

### 3.2 What it is not

The DSA is not:

- a real-time SOC cockpit,
- a full contractual proof of active ES coverage when ES is not detected,
- a formal readiness engine,
- or a deep audit of custom customer content outside the bundled catalog.

---

## 4. Core reading principle

## **The report can combine real observed data and calculated projection.**

### 4.1 Observed now

The following belong to the **Observed now** category:

- data sources actually seen in Splunk telemetry,
- `sourcetype` and `source` values observed through Splunk metadata,
- collection gaps calculated from that real presence,
- family distributions derived from matching the observed data source set.

### 4.2 Projected with ES

The following belong to the **Projected with ES** category:

- detections that would be activable in ES,
- adjacent candidates,
- the message:
  **"with the data you already have, here is what ES would unlock"**.

This is **not fake data**. It is calculated from real observed telemetry,
but it represents **projected value**, not already active coverage.

---

## 5. Two report reading modes

## 5.1 ES detected

When ES is correctly detected, the tool can combine:

- real telemetry assessment,
- current active ES coverage,
- activable but not yet enabled content,
- strategic collection gaps.

In that case, the readout can legitimately talk about:

- active coverage,
- content already in place,
- content still not enabled,
- next collection steps.

## 5.2 ES not detected, degraded `DSA++ classic` mode

If ES is not detected, the report still remains fully useful.

It switches to a degraded **DSA++ classic** mode with this logic:

- start from what is really observed,
- calculate what ES would unlock from that existing telemetry,
- prioritize what extra collection would unlock next.

The correct technical message is:

> This is not proof of active ES coverage.
> It is a real telemetry assessment enriched with an ES value projection.

The correct commercial message is:

> With the data already present in Splunk, ES would immediately unlock a
> meaningful part of the coverage by simple activation.

---

## 6. Dashboard structure

The dashboard is organized in four tabs.

## 6.1 Summary

Purpose: deliver an immediate assessment readout.

This tab contains:

- the report reading mode,
- key KPIs,
- the distinction between **Observed now** and **Projected with ES**,
- the reporting mode table,
- key readout messages,
- a shortlist of what ES would unlock immediately,
- a shortlist of what collection would unlock next.

## 6.2 Audit

Purpose: justify the assessment technically.

This view contains:

- the framing logic,
- assessment findings,
- key readout messages,
- value distribution by family,
- collection pressure by family.

## 6.3 Quick wins

Purpose: isolate what the customer could move quickly.

This view is useful for:

- workshop prioritization,
- pre-POC shortlists,
- ES value storytelling,
- quick-win conversations.

## 6.4 Collection plan

Purpose: turn the assessment into an onboarding roadmap.

This view is useful for:

- onboarding planning,
- TA prioritization,
- partner or consulting follow-up,
- phased collection strategy.

## 6.5 Sizing

Purpose: add a **data capacity** dimension to the assessment.

This view provides:

- a histogram of historical daily ingestion,
- statistical indicators such as average, median, P95, and peak,
- a variability readout over time,
- a table of the heaviest ingestion days.

For readability:

- the histogram and statistical table are displayed in **GB/day**,
- the quick KPI cards are displayed in **MB/day** so small volumes remain readable.

This view helps answer questions like:

- what is the typical **daily ingest volume**,
- how **stable or variable** that ingest is,
- which days are the **peak days**,
- what order of magnitude should be used for a sizing discussion.

The metric used in this view is based on daily ingest visibility from
Splunk internal license logs (`_internal`, `license_usage.log`,
`type=Usage`).

---

## 7. KPI interpretation

## 7.1 Observed data sources

Number of catalog data sources that found a match in real Splunk
telemetry.

This is a **real observed metric**.

## 7.2 Activable techniques

Number of ATT&CK techniques already addressable with the telemetry that
is present.

This is **not automatically active ES coverage**. It is a measure of
accessible value.

## 7.3 Detections activable in ES

Number of detections that ES would be able to activate immediately from
the telemetry already present.

This is the strongest **commercial KPI** in degraded DSA++ mode.

## 7.4 Adjacent candidates

Detections close to being activable, but still dependent on companion
telemetry.

This is the second circle of value.

## 7.5 Techniques blocked by gaps

Number of techniques still limited by collection gaps.

This does not cancel the immediate value. It shows what is still blocked.

## 7.6 Key missing sources

Number of catalog sources still missing and carrying meaningful coverage
value.

This is a **collection roadmap metric**.

## 7.7 Average GB/day

Average daily ingest volume across the selected period.

This is the simplest sizing baseline.

## 7.8 Median GB/day

Median daily ingest volume across the selected period.

This is often more robust than the average when a few days are atypical.

## 7.9 P95 GB/day

The daily ingest level that 95 percent of the observed days stay below.

This is especially useful for **capacity sizing** conversations.

## 7.10 Peak GB/day

Highest observed daily ingest value during the selected period.

This highlights the worst observed day and should be read together with
the average and P95.

## 7.11 Ingest statistical analysis

The statistical table provides:

- number of observed days,
- average,
- median,
- P95,
- minimum,
- maximum,
- standard deviation,
- coefficient of variation,
- trend direction.

Interpretation guidance:

- **low coefficient of variation** means a relatively stable ingest
  pattern,
- **high coefficient of variation** means a more irregular ingest
  profile,
- **upward trend** means rising load,
- **stable trend** means a more predictable profile.

---

## 8. Recommended workshop flow

1. Start with **Summary**
2. Move to **Quick wins**
3. Continue with **Collection plan**
4. Use **Sizing** for daily ingest and variability analysis
5. Use **Audit** for technical challenge or justification

---

## 9. Recommended operator flow

### Before the session

Check:

- access to Splunk,
- app installation,
- dashboard availability,
- useful time window,
- apparent telemetry quality,
- whether ES is detected or not.

### During the session, ES not detected

Use this storyline:

1. this is what we really see,
2. this is what ES would unlock from the existing data,
3. this is what extra collection would unlock next.

### During the session, ES detected

Use this storyline:

1. this is what is visible,
2. this is current active coverage,
3. this is still activable,
4. this is what collection should unlock next.

### After the session

Produce a short report with:

- findings,
- quick wins,
- collection backlog,
- assumptions and limits,
- next steps.

---

## 10. Command usage

The TA exposes:

```spl
| attackcoverageadvisor mode=<summary|inventory|current|potential|gaps|full>
```

### Summary

```spl
| attackcoverageadvisor mode=summary
```

### Inventory

```spl
| attackcoverageadvisor mode=inventory
| table family data_source_name inventory_match supported_ta_names
```

### Current

```spl
| attackcoverageadvisor mode=current limit=100
| table detection_name mitre_attack_ids technique_count reason
```

### Potential

```spl
| attackcoverageadvisor mode=potential include_partial=true limit=50
| table detection_name data_source_name technique_count reason recommendation
```

### Gaps

```spl
| attackcoverageadvisor mode=gaps limit=20
| table data_source_name technique_count detection_count reason recommendation supported_ta_names
```

### Full

```spl
| attackcoverageadvisor mode=full limit=100
```

---

## 11. Recommended readout messages

### Neutral technical message

> We built this assessment from telemetry really observed in Splunk, then
> crossed that existing data with a bundled detection and data-source
> catalog to identify what is already exploitable, what ES would unlock,
> and what still depends on collection.

### Technical message when ES is not detected

> This is not proof of active ES coverage. It is a DSA++ classic report,
> built on real observed data, used to project the value ES would unlock.

### Commercial message when ES is not detected

> With the data you already have in Splunk, ES would immediately unlock a
> meaningful part of the coverage by simple activation.

### Collection transition message

> The immediate value is already significant, but the next level depends
> on a few structural sources that should be prioritized in the
> onboarding plan.

---

## 12. Known limits

### 12.1 `current` is still the least robust part of V1

The `current` mode depends on:

- correct ES detection,
- REST visibility,
- bundled catalog matching,
- live annotations when available.

Treat it as informative until fully hardened.

### 12.2 Matching is directional, not contractual

The engine produces credible assessment guidance, not contractual proof.

### 12.3 The bundled catalog does not fully represent custom customer
content

Anything outside the bundled snapshot can remain only partially visible.

### 12.4 Degraded mode is not an error

The degraded **DSA++ classic** mode is a valid operating mode for:

- pre-sales,
- partner workshops,
- consulting assessments,
- ES qualification before adoption.

---

## 13. Fast FAQ

### Is this real data?

**Partly yes.**

- observed now is real,
- projected with ES is calculated from that real base.

### Is this a live ES dashboard?

**Not necessarily.**

If `current` is not reliable, describe it as an ES value projection, not
as active coverage.

### Is it useful without ES?

**Yes.**

That is exactly why the **DSA++ classic** mode exists.

### What is the one-line operator message?

> The DSA is a real telemetry assessment enriched with an ES value
> projection and a prioritized collection roadmap.
