# Installation Guide, DSA++ Maturity Accelerator

## Purpose

This document explains how to install and validate the `DSA++ Maturity Accelerator` / `TA-attack-coverage-advisor` app on a Splunk Enterprise or Splunk ES search head.

The app is built for DSA++ workshops:

- Splunk SE teams
- partner teams
- consulting teams
- PvP follow-up conversations
- pre-POC security assessment workshops
- Enterprise Security value and maturity conversations with existing Splunk customers

The goal is to move beyond a pure ingestion sizing conversation and structure the discussion around risk, security use cases, data sources, ES detections, MITRE ATT&CK, roadmap and sizing context.

---

## 1. What gets installed

The package contains:

- the generating command `attackcoverageadvisor`
- the embedded lookup catalog derived from Splunk `security_content`
- the Dashboard Studio v2 view `attack_coverage_advisor_command_center`, rebuilt for the DSA++ maturity workflow
- packaged runtime dependencies under `bin/lib/`

No runtime internet access is required once the app is installed.

Results are directional and intended for SE workshop qualification; they are not contractual coverage or licensing commitments.

For the French SE usage playbook, customer talk-track, interpretation rules and guardrails, read [`GUIDE_UTILISATION_FR.md`](GUIDE_UTILISATION_FR.md).

---

## 2. Supported target

Install the app on a **search head** or single-instance Splunk host.

Minimum expected target:

- Splunk Enterprise 10.x or recent equivalent
- access to Splunk Web or Splunk management port `8089`
- a user allowed to install apps and access REST endpoints

Enterprise Security is not required for the projection mode, but if ES is installed the app can also provide a directional view of enabled correlation searches.

---

## 3. Package the app

From a workspace containing the app folder:

```bash
tar -czf TA-attack-coverage-advisor.tgz TA-attack-coverage-advisor
```

The archive root must contain the app directory itself.

Expected structure inside the package:

```text
TA-attack-coverage-advisor/
  bin/
  default/
  lookups/
  metadata/
  README.md
  INSTALLATION.md
  GUIDE_UTILISATION_FR.md
```

---

## 4. Installation methods

## Method A, Splunk Web upload, recommended when SSH is not available

1. Log in to Splunk Web as an admin-capable user.
2. Open **Apps** → **Manage Apps**.
3. Click **Install App From File**.
4. Upload `TA-attack-coverage-advisor.tgz`.
5. If upgrading an existing copy, enable **Upgrade app**.
6. Click **Upload**.

Expected result:

```text
Install - Success
DSA++ Maturity Accelerator has been successfully installed.
```

## Method B, manual filesystem deployment, recommended when SSH is available

```bash
sudo tar -xzf TA-attack-coverage-advisor.tgz -C /opt/splunk/etc/apps
```

For a clean replacement:

```bash
sudo rm -rf /opt/splunk/etc/apps/TA-attack-coverage-advisor
sudo tar -xzf TA-attack-coverage-advisor.tgz -C /opt/splunk/etc/apps
```

---

## 5. Reload after install

Recommended REST reload sequence:

```bash
curl -k -u <user>:<password> -X POST https://<splunk-host>:8089/services/apps/local/_reload
curl -k -u <user>:<password> -X POST https://<splunk-host>:8089/services/data/ui/views/_reload
curl -k -u <user>:<password> -X POST https://<splunk-host>:8089/servicesNS/nobody/TA-attack-coverage-advisor/data/ui/nav/_reload
curl -k -u <user>:<password> -X POST https://<splunk-host>:8089/services/admin/commandsconf/_reload
```

A Splunk restart also works if it matches the target environment policy.

---

## 6. Validate the install

## 6.1 Validate the app exists

```bash
curl -k -u <user>:<password> \
  https://<splunk-host>:8089/services/apps/local/TA-attack-coverage-advisor?output_mode=json
```

## 6.2 Validate the dashboard view exists

```bash
curl -k -u <user>:<password> \
  https://<splunk-host>:8089/servicesNS/nobody/TA-attack-coverage-advisor/data/ui/views/attack_coverage_advisor_command_center?output_mode=json
```

## 6.3 Validate the web URL

Open:

```text
http://<splunk-host>:8000/en-US/app/TA-attack-coverage-advisor/attack_coverage_advisor_command_center
```

You should see the dashboard with these tabs:

- Maturité DSA++
- Sources
- Règles ES
- MITRE
- Roadmap
- Sizing

---

## 7. Validate the search command

Run the simplest smoke test:

```spl
| attackcoverageadvisor mode=summary
```

Expected behavior:

- the search returns rows
- `summary` lines are visible
- no Python import error occurs

Useful follow-up tests:

```spl
| attackcoverageadvisor mode=inventory
```

```spl
| attackcoverageadvisor mode=potential include_partial=true limit=20
```

```spl
| attackcoverageadvisor mode=gaps limit=20
```

If Enterprise Security is installed:

```spl
| attackcoverageadvisor mode=current
```

---

## 8. How to interpret the result

The dashboard can operate in two normal modes.

## 8.1 ES detected

If ES is detected correctly, the app can expose:

- observed telemetry
- enabled ES correlation searches mapped directionally to the bundled catalog
- additional ES detections activable or nearly activable
- missing sources that unlock further coverage

Use this to drive adoption and maturity conversations.

## 8.2 ES not detected

If ES is not installed, the app runs in DSA++ projection mode:

- it starts from telemetry already indexed in Splunk
- it maps that telemetry to ES OOTB detection potential
- it shows quick wins and source gaps
- it helps create the business and technical case for ES

This is expected for Enterprise-only customers.

---

## 9. Workshop flow

Recommended DSA++ workshop sequence:

1. Start with the **Maturité DSA++** tab to frame the conversation with risk and use cases.
2. Use **Sources** to validate what Splunk already sees.
3. Use **Règles ES** to show immediate or near-term ES value.
4. Use **MITRE** to translate detections into threat behavior and maturity.
5. Use **Roadmap** to prioritize missing sources.
6. Use **Sizing** to contextualize volume and architecture.

---

## 10. Guardrails

- The dashboard is an accelerator, not a contractual audit.
- Activable detections still require validation, tuning and ownership before production.
- Partial detections do not prove all prerequisites are met.
- Custom customer detections may be unmapped.
- Pricing/licensing belongs with the RSM.
- Implementation commitments belong with PS.

See also the French usage guide: [`GUIDE_UTILISATION_FR.md`](GUIDE_UTILISATION_FR.md).
