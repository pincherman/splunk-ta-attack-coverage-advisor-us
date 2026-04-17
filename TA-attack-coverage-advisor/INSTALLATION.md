# Installation Guide, TA-attack-coverage-advisor

## Purpose

This document explains how to install and validate the
`TA-attack-coverage-advisor` app on a Splunk Enterprise or Splunk ES
search head.

The goal is to make the app easy to deploy for:

- Splunk SE teams
- partner teams
- consulting teams
- pre-POC assessment workshops

---

## 1. What gets installed

The package contains:

- the generating command `attackcoverageadvisor`
- the embedded lookup catalog derived from `security_content`
- the Dashboard Studio view `attack_coverage_advisor_command_center`
- the packaged runtime dependencies under `bin/lib/`

No runtime internet access is required once the app is installed.

---

## 2. Supported target

Install the app on a **search head** or single-instance Splunk host.

Minimum expected target:

- Splunk Enterprise 10.x or recent equivalent
- access to Splunk Web or Splunk management port `8089`
- a user allowed to install apps and access REST endpoints

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
```

---

## 4. Installation methods

## Method A, Splunk Web upload, recommended when SSH is not available

Use this method when you can access Splunk Web but do not have shell
access to the target host.

### Steps

1. Log in to Splunk Web as an admin-capable user.
2. Open:
   - **Apps**
   - **Manage Apps**
3. Click **Install App From File**.
4. Upload `TA-attack-coverage-advisor.tgz`.
5. If upgrading an existing copy, enable **Upgrade app**.
6. Click **Upload**.

### Expected result

Splunk displays a success message similar to:

```text
Install - Success
DSA, Data Source Assessment has been successfully installed.
```

---

## Method B, manual filesystem deployment, recommended when SSH is available

Use this method when you have OS access to the Splunk host.

### Steps

1. Copy the package to the target server.
2. Extract it into the Splunk apps directory.

Typical target path:

```bash
/opt/splunk/etc/apps/
```

Example:

```bash
sudo tar -xzf TA-attack-coverage-advisor.tgz -C /opt/splunk/etc/apps
```

If an older copy already exists and you want a clean replacement:

```bash
sudo rm -rf /opt/splunk/etc/apps/TA-attack-coverage-advisor
sudo tar -xzf TA-attack-coverage-advisor.tgz -C /opt/splunk/etc/apps
```

---

## 5. Reload after install

After installation, reload the relevant Splunk objects.

### Recommended REST reload sequence

```bash
curl -k -u <user>:<password> -X POST https://<splunk-host>:8089/services/apps/local/_reload
curl -k -u <user>:<password> -X POST https://<splunk-host>:8089/services/data/ui/views/_reload
curl -k -u <user>:<password> -X POST https://<splunk-host>:8089/servicesNS/nobody/TA-attack-coverage-advisor/data/ui/nav/_reload
curl -k -u <user>:<password> -X POST https://<splunk-host>:8089/services/admin/commandsconf/_reload
```

If your environment prefers a restart policy, a Splunk restart also works,
but the reload sequence is lighter and was sufficient in validation.

---

## 6. Validate the install

## 6.1 Validate the app exists

Check the app through the REST API:

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

- Synthèse
- Audit
- Activations rapides
- Plan de collecte

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

---

## 8. How to interpret the result after install

The dashboard can operate in two normal modes.

## 8.1 ES detected

If ES is detected correctly, the app can expose:

- observed telemetry
- current ES coverage view
- activable but non-active content
- strategic gaps

## 8.2 ES not detected, degraded `DSA++ classique` mode

If ES is not detected, the app still remains useful.

In that case, the report is intentionally presented as:

- a **real telemetry assessment**
- plus a **projected ES value**
- plus a **prioritized collection roadmap**

This is not a failure mode. It is a valid mode for:

- pre-sales
- partner workshops
- consulting assessments
- ES qualification before adoption

---

## 9. Recommended installation checklist

Before declaring the install complete, confirm all of the following:

- app is present under `services/apps/local`
- dashboard view exists under `data/ui/views`
- command `attackcoverageadvisor` runs without import errors
- dashboard opens in Splunk Web
- at least one test mode returns rows
- the operator understands the difference between:
  - observed now
  - projected with ES

---

## 10. Troubleshooting

## Problem, app uploads but does not appear

Check:

- app reload completed
- permissions of the installed app directory
- package root contains the app folder and not only its contents

## Problem, dashboard opens but is empty

Check:

- command reload was executed
- the user can run metadata and rest searches
- the selected time range is broad enough

## Problem, `current` mode looks incomplete

This is the most fragile part of the V1.

Check:

- ES is actually installed and enabled
- REST visibility on saved searches is available
- detection annotations exist when expected

Until that part is fully hardened, treat `current` as informative,
not contractual.

## Problem, users confuse real data and projection

Use the dashboard legend and say explicitly:

- **Observed now** = real telemetry seen in Splunk
- **Projected with ES** = value calculated from that real telemetry

---

## 11. Proven validation paths

The app has been validated through two concrete deployment patterns:

### Pattern 1

- install on a host with SSH access
- extract under `/opt/splunk/etc/apps`
- reload app, views, nav, commands

### Pattern 2

- install through Splunk Web
- **Apps > Manage Apps > Install App From File**
- validate app + dashboard through REST and UI

Both patterns were successfully used on live Splunk instances.

---

## 12. Community sharing recommendation

If you publish this TA for a wider Splunk audience, keep the public repo
focused on:

- the app itself
- the README
- this installation guide
- the technical operator guide
- optional screenshots

Do not publish:

- customer credentials
- customer hostnames that should remain private
- internal-only demo data that should not leave the workspace

---

## 13. Minimal operator message

If you need one sentence to explain the app after install:

> This TA turns observed Splunk telemetry into a DSA assessment, an ES
> value projection, and a prioritized collection roadmap.
