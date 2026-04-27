#!/usr/bin/env python3
"""Build the DSA++ Maturity Accelerator Dashboard Studio view.

The dashboard follows the team DSA++ method:
PvP/risk conversation -> observed data sources -> ES use cases -> MITRE
coverage -> collection roadmap -> sizing context.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any

WORKSPACE = Path("/home/openclaw/.openclaw/workspace-splunk")
APP_ROOT = WORKSPACE / "TA-attack-coverage-advisor"
GENERATED_DIR = WORKSPACE / "generated" / "attack_coverage_advisor"
JSON_PATH = GENERATED_DIR / "attack_coverage_advisor_command_center.json"
VIEW_PATH = (
    APP_ROOT
    / "default"
    / "data"
    / "ui"
    / "views"
    / "attack_coverage_advisor_command_center.xml"
)
NAV_PATH = APP_ROOT / "default" / "data" / "ui" / "nav" / "default.xml"
STATIC_DIR = APP_ROOT / "appserver" / "static"
IMAGE_ASSETS_DIR = WORKSPACE / "generated" / "images"
HERO_ASSET = IMAGE_ASSETS_DIR / "dsa_maturity_images2_hero.png"
MESH_ASSET = IMAGE_ASSETS_DIR / "dsa_maturity_images2_signal_mesh.png"
VIEW_NAME = "attack_coverage_advisor_command_center"


COLORS = {
    "bg": "#050B15",
    "panel": "#0B1628",
    "panel2": "#10213A",
    "panel3": "#132C47",
    "green": "#3DFF91",
    "blue": "#5EDBFF",
    "violet": "#A78BFA",
    "orange": "#FDBA74",
    "red": "#FB7185",
    "text": "#EAF2FF",
    "muted": "#C9D6EA",
}


def search(query: str) -> dict[str, Any]:
    return {
        "type": "ds.search",
        "options": {
            "query": query,
            "queryParameters": {
                "earliest": "$global_time.earliest$",
                "latest": "$global_time.latest$",
            },
        },
    }


def md(text: str, color: str = COLORS["text"]) -> dict[str, Any]:
    return {
        "type": "splunk.markdown",
        "options": {
            "markdown": text,
            "fontColor": color,
            "backgroundColor": "transparent",
        },
    }


def rect(fill: str, stroke: str = "transparent") -> dict[str, Any]:
    return {
        "type": "splunk.rectangle",
        "options": {"fillColor": fill, "strokeColor": stroke},
    }


def image(src: str) -> dict[str, Any]:
    return {
        "type": "splunk.image",
        "options": {"src": src, "preserveAspectRatio": False},
        "showProgressBar": False,
        "showLastUpdated": False,
    }


def single(title: str, ds_name: str, bg: str, color: str = "#FFFFFF") -> dict[str, Any]:
    return {
        "type": "splunk.singlevalue",
        "title": title,
        "dataSources": {"primary": ds_name},
        "options": {
            "majorColor": color,
            "backgroundColor": bg,
            "sparklineDisplay": "off",
        },
    }


def table(title: str, ds_name: str, header: str, count: int = 20) -> dict[str, Any]:
    return {
        "type": "splunk.table",
        "title": title,
        "dataSources": {"primary": ds_name},
        "options": {
            "backgroundColor": COLORS["panel"],
            "headerBackgroundColor": header,
            "fontColor": COLORS["text"],
            "headerFontColor": "#FFFFFF",
            "rowNumbers": False,
            "count": count,
        },
    }


def bar(title: str, ds_name: str, color: str) -> dict[str, Any]:
    return {
        "type": "splunk.bar",
        "title": title,
        "dataSources": {"primary": ds_name},
        "options": {
            "backgroundColor": "transparent",
            "legendDisplay": "off",
            "seriesColors": [color],
            "orientation": "horizontal",
        },
    }


def column(title: str, ds_name: str, color: str) -> dict[str, Any]:
    return {
        "type": "splunk.column",
        "title": title,
        "dataSources": {"primary": ds_name},
        "options": {
            "backgroundColor": "transparent",
            "legendDisplay": "off",
            "seriesColors": [color],
        },
    }


def block(item: str, x: int, y: int, w: int, h: int) -> dict[str, Any]:
    return {"item": item, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}


def splunk_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_mitre_cases(limit: int = 1000) -> tuple[str, str]:
    """Create compact SPL case() mappings for common ATT&CK IDs."""
    detection_path = APP_ROOT / "lookups" / "attack_coverage_detections.csv"
    enrichment_path = APP_ROOT / "lookups" / "attack_coverage_mitre_enrichment.csv"
    counts: Counter[str] = Counter()
    with detection_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            for technique_id in row.get("mitre_attack_ids", "").split(";"):
                technique_id = technique_id.strip()
                if technique_id:
                    counts[technique_id] += 1

    enrichment: dict[str, tuple[str, str]] = {}
    if enrichment_path.exists():
        with enrichment_path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                enrichment[row["mitre_id"]] = (row["technique"], row["tactics"])

    technique_parts: list[str] = []
    tactic_parts: list[str] = []
    for technique_id, _ in counts.most_common(limit):
        technique_name, tactic_name = enrichment.get(
            technique_id,
            (technique_id, "Tactique à qualifier"),
        )
        technique_parts.append(
            f'mitre_attack_ids="{technique_id}","{splunk_quote(technique_name)}"'
        )
        tactic_parts.append(
            f'mitre_attack_ids="{technique_id}","{splunk_quote(tactic_name)}"'
        )
    return (
        "case(" + ",".join(technique_parts) + ",true(),mitre_attack_ids)",
        "case(" + ",".join(tactic_parts) + ',true(),"Tactique à qualifier")',
    )


def build_dashboard() -> dict[str, Any]:
    mitre_technique_case, mitre_tactic_case = build_mitre_cases()
    data_sources = {
        "dsObservedSources": search(
            "| attackcoverageadvisor mode=summary "
            "| search status=inventory "
            "| stats first(technique_count) as value"
        ),
        "dsActivableDetections": search(
            "| attackcoverageadvisor mode=summary "
            "| search status=potential "
            "| rex field=reason \"(?<activables>\\d+) detections "
            "are immediately activable and (?<adjacents>\\d+) are adjacent candidates\" "
            "| stats first(activables) as value"
        ),
        "dsProjectedTechniques": search(
            "| attackcoverageadvisor mode=summary "
            "| search status=potential "
            "| stats first(technique_count) as value"
        ),
        "dsMissingSources": search(
            "| attackcoverageadvisor mode=gaps limit=500 "
            "| stats dc(data_source_name) as value"
        ),
        "dsOpportunityScore": search(
            "| attackcoverageadvisor mode=summary "
            "| rex field=reason \"(?<activables>\\d+) detections "
            "are immediately activable and (?<adjacents>\\d+) are adjacent candidates\" "
            "| stats max(eval(if(status=\"potential\", technique_count, null()))) "
            "as techniques max(activables) as activables max(adjacents) as adjacents "
            "| eval raw=(coalesce(activables,0)*1.5)+(coalesce(techniques,0)*0.25)+(coalesce(adjacents,0)*0.06) "
            "| eval value=round(if(raw>100,100,raw),0) | table value"
        ),
        "dsContextMode": search(
            "| attackcoverageadvisor mode=summary "
            "| search status=potential "
            "| eval lecture=if(es_installed=\"true\",\"ES détecté : adoption + expansion\",\"ES non détecté : projection DSA++ / upsell\") "
            "| eval promesse=if(es_installed=\"true\",\"Mesurer les contenus ES activés, activables et sous-exploités.\",\"Prouver la valeur ES avec la télémétrie Splunk déjà collectée.\") "
            "| table lecture promesse fenêtre"
        ),
        "dsWorkshopFlow": search(
            "| makeresults "
            "| eval étape=\"1. PvP / contexte\", objectif=\"Cadrer risques, priorités SOC, périmètre\", sortie=\"Use cases + périmètre validés\" "
            "| append [| makeresults | eval étape=\"2. Inventaire DSA\", objectif=\"Lister sources / sourcetypes / hosts visibles\", sortie=\"Inventaire DSA factuel\"] "
            "| append [| makeresults | eval étape=\"3. Sources de données\", objectif=\"Relier l’existant aux familles sécurité\", sortie=\"Sources couvertes / manquantes\"] "
            "| append [| makeresults | eval étape=\"4. Contenus ES\", objectif=\"Identifier règles ES activables/proches\", sortie=\"Gains rapides + règles critiques\"] "
            "| append [| makeresults | eval étape=\"5. MITRE & risque\", objectif=\"Traduire en comportements adverses\", sortie=\"Lecture MITRE / maturité\"] "
            "| append [| makeresults | eval étape=\"6. Roadmap & sizing\", objectif=\"Prioriser collecte et ingestion\", sortie=\"Roadmap + next step ES\"] "
            "| table étape objectif sortie"
        ),
        "dsDecisionGuide": search(
            "| makeresults "
            "| eval signal=\"Données déjà présentes + règles activables\", lecture=\"Atelier gains rapides ES\", décision=\"Montrer valeur, puis tuning/activation\" "
            "| append [| makeresults | eval signal=\"Données présentes mais règles partielles\", lecture=\"Maturité collecte / CIM\", décision=\"Qualifier sources + prérequis TA/CIM\"] "
            "| append [| makeresults | eval signal=\"Peu de sources mappées\", lecture=\"Roadmap de collecte\", décision=\"Prioriser 3-5 sources à forte valeur\"] "
            "| append [| makeresults | eval signal=\"ES déjà installé\", lecture=\"Adoption / sous-utilisation\", décision=\"Comparer actifs / activables / non exploités\"] "
            "| table signal lecture décision"
        ),
        "dsRiskQuestions": search(
            "| makeresults "
            "| eval thème=\"Gestion du risque\", question=\"Quels risques détecter / investiguer mieux ?\", preuve=\"Cas d’usage → règle ES → MITRE\" "
            "| append [| makeresults | eval thème=\"Sources\", question=\"Quelles données sont visibles / hors radar ?\", preuve=\"Inventaire source/sourcetype + gaps\"] "
            "| append [| makeresults | eval thème=\"Use cases\", question=\"Quelles règles activer vite ?\", preuve=\"Gains rapides P1/P2\"] "
            "| append [| makeresults | eval thème=\"Maturité SOC\", question=\"Quelle couverture MITRE est crédible ?\", preuve=\"Techniques couvertes / bloquées\"] "
            "| append [| makeresults | eval thème=\"Roadmap\", question=\"Quelle source débloque le plus de valeur ?\", preuve=\"Roadmap par valeur détection\"] "
            "| table thème question preuve"
        ),
        "dsDomainReadiness": search(
            "| attackcoverageadvisor mode=full limit=1000 include_partial=true "
            "| eval domaine=if(len(family)>0,family,\"Non classé\") "
            "| stats count(eval(section=\"inventory\")) as sources_observees "
            "count(eval(section=\"potential\" AND status=\"activable\")) as regles_activables "
            "count(eval(section=\"potential\" AND status=\"partial\")) as regles_proches "
            "sum(eval(if(section=\"gaps\", detection_count, 0))) as regles_bloquees "
            "dc(eval(if(section=\"potential\", mitre_attack_ids, null()))) as familles_mitre by domaine "
            "| eval lecture=case(regles_activables>0,\"Valeur ES immédiate\",regles_proches>0,\"Proche activation\",regles_bloquees>0,\"Dépend de la collecte\",true(),\"A qualifier\") "
            "| sort 0 - regles_activables - regles_proches - regles_bloquees "
            "| head 12"
        ),
        "dsSourceChecklist": search(
            "| attackcoverageadvisor mode=full limit=1000 include_partial=true "
            "| eval statut=case(section=\"inventory\",\"Observée dans Splunk\",section=\"gaps\",\"A intégrer / normaliser\",true(),null()) "
            "| where isnotnull(statut) "
            "| eval valeur=case(section=\"inventory\",\"Base déjà exploitable\",section=\"gaps\",\"Débloque \" . detection_count . \" détections / \" . technique_count . \" techniques\") "
            "| eval action=case(section=\"inventory\",\"Valider qualité, CIM et contexte métier\",section=\"gaps\",\"Onboarder TA / source et réévaluer activation ES\") "
            "| rename family as domaine data_source_name as source supported_ta_names as TA supported_ta_versions as version_TA inventory_match as preuve "
            "| sort 0 statut domaine source "
            "| head $result_limit$ "
            "| table statut source domaine TA version_TA preuve valeur action"
        ),
        "dsSourceFamilies": search(
            "| attackcoverageadvisor mode=inventory limit=1000 "
            "| stats count as sources by family "
            "| rename family as domaine "
            "| sort - sources"
        ),
        "dsRulesActivable": search(
            "| attackcoverageadvisor mode=potential limit=500 include_partial=true "
            "| eval priorité=case(match_ratio>=1 AND technique_count>=5,\"P1\",match_ratio>=1,\"P2\",match_ratio>=0.5,\"P3\",true(),\"P4\") "
            "| eval état=case(match_ratio>=1,\"Activable avec l’existant\",match_ratio>=0.5,\"Presque activable\",true(),\"A qualifier\") "
            "| eval atelier=case(match_ratio>=1,\"Tester/tuner/activer dans ES\",match_ratio>=0.5,\"Compléter collecte ou CIM\",true(),\"Backlog cas d’usage\") "
            "| rename detection_name as règle_ES family as domaine data_source_name as sources_visibles mitre_attack_ids as MITRE technique_count as techniques "
            "| sort 0 priorité - techniques règle_ES "
            "| head $result_limit$ "
            "| table priorité règle_ES domaine état sources_visibles MITRE techniques atelier"
        ),
        "dsRulesByDomain": search(
            "| attackcoverageadvisor mode=potential limit=500 include_partial=true "
            "| search match_ratio>=1 "
            "| stats count as règles by family "
            "| rename family as domaine "
            "| sort - règles"
        ),
        "dsMitreTechniques": search(
            "| attackcoverageadvisor mode=potential limit=1000 include_partial=true "
            "| where len(mitre_attack_ids)>0 "
            "| makemv delim=\"; \" mitre_attack_ids "
            "| mvexpand mitre_attack_ids "
            f"| eval technique={mitre_technique_case}, tactique={mitre_tactic_case} "
            "| eval activable=if(match_ratio>=1,1,0) "
            "| stats count as règles sum(activable) as activables values(family) as domaines values(data_source_name) as sources values(detection_name) as exemples by mitre_attack_ids technique tactique "
            "| eval lecture=if(activables>0,\"Couverture immédiate à discuter\",\"A débloquer via collecte\") "
            "| eval exemples=mvjoin(mvindex(exemples,0,2),\" | \"), sources=mvjoin(mvindex(sources,0,4),\" | \"), domaines=mvjoin(domaines,\" | \") "
            "| sort 0 - activables - règles technique "
            "| head $result_limit$ "
            "| table mitre_attack_ids technique tactique règles activables domaines sources exemples lecture"
        ),
        "dsMitreTactics": search(
            "| attackcoverageadvisor mode=potential limit=1000 include_partial=true "
            "| where len(mitre_attack_ids)>0 "
            "| makemv delim=\"; \" mitre_attack_ids "
            "| mvexpand mitre_attack_ids "
            f"| eval tactique={mitre_tactic_case} "
            "| eval activable=if(match_ratio>=1,1,0) "
            "| stats count as règles sum(activable) as activables by tactique "
            "| sort - activables - règles"
        ),
        "dsRoadmap": search(
            "| attackcoverageadvisor mode=gaps limit=500 "
            "| eval priorité=case(technique_count>=20 OR detection_count>=100,\"P1\",technique_count>=10 OR detection_count>=25,\"P2\",true(),\"P3\") "
            "| eval phase=case(priorité=\"P1\",\"0-30 jours\",priorité=\"P2\",\"30-90 jours\",true(),\"Backlog\") "
            "| eval raison=\"Débloque \" . detection_count . \" règles et \" . technique_count . \" techniques ATT&CK\" "
            "| eval prochaine_action=\"Valider propriétaire, TA/CIM, index cible et prérequis de collecte\" "
            "| rename data_source_name as source family as domaine supported_ta_names as TA detection_count as règles technique_count as techniques "
            "| sort 0 priorité - techniques - règles source "
            "| head $result_limit$ "
            "| table priorité phase source domaine règles techniques TA raison prochaine_action"
        ),
        "dsRoadmapPhases": search(
            "| attackcoverageadvisor mode=gaps limit=500 "
            "| eval phase=case(technique_count>=20 OR detection_count>=100,\"0-30 jours\",technique_count>=10 OR detection_count>=25,\"30-90 jours\",true(),\"Backlog\") "
            "| stats count as sources sum(detection_count) as règles sum(technique_count) as techniques by phase "
            "| sort phase"
        ),
        "dsSizingDaily": search(
            "search index=_internal source=*license_usage.log* type=Usage idx=* "
            "| bin _time span=1d "
            "| stats sum(b) as bytes by _time "
            "| eval volume_Go=round(bytes/1024/1024/1024,3) "
            "| eval jour=strftime(_time, \"%d/%m\") "
            "| table jour volume_Go"
        ),
        "dsSizingAvgVolume": search(
            "search index=_internal source=*license_usage.log* type=Usage idx=* "
            "| bin _time span=1d "
            "| stats sum(b) as bytes by _time "
            "| stats avg(bytes) as avg_bytes "
            "| eval value=case(avg_bytes>=1099511627776, round(avg_bytes/1024/1024/1024/1024,2).\" To/j\", avg_bytes>=1073741824, round(avg_bytes/1024/1024/1024,2).\" Go/j\", true(), round(avg_bytes/1024/1024,1).\" Mo/j\") "
            "| table value"
        ),
        "dsSizingStats": search(
            "search index=_internal source=*license_usage.log* type=Usage idx=* "
            "| bin _time span=1d "
            "| stats sum(b) as bytes by _time "
            "| stats count as jours_mesures avg(bytes) as moyenne_bytes max(bytes) as pic_bytes min(bytes) as min_bytes "
            "| eval moyenne_jour=case(moyenne_bytes>=1099511627776, round(moyenne_bytes/1024/1024/1024/1024,2).\" To/j\", moyenne_bytes>=1073741824, round(moyenne_bytes/1024/1024/1024,2).\" Go/j\", true(), round(moyenne_bytes/1024/1024,1).\" Mo/j\") "
            "| eval pic_jour=case(pic_bytes>=1099511627776, round(pic_bytes/1024/1024/1024/1024,2).\" To/j\", pic_bytes>=1073741824, round(pic_bytes/1024/1024/1024,2).\" Go/j\", true(), round(pic_bytes/1024/1024,1).\" Mo/j\") "
            "| eval min_jour=case(min_bytes>=1099511627776, round(min_bytes/1024/1024/1024/1024,2).\" To/j\", min_bytes>=1073741824, round(min_bytes/1024/1024/1024,2).\" Go/j\", true(), round(min_bytes/1024/1024,1).\" Mo/j\") "
            "| table jours_mesures moyenne_jour pic_jour min_jour"
        ),
    }

    visualizations = {
        "bg": rect(COLORS["bg"]),
        "haloTop": rect("#0E2A43", "#1E4D72"),
        "haloBottom": rect("#10213A", "#2D4B74"),
        "accent": rect(COLORS["green"]),
        "hero": md(
            "# **DSA++ MATURITY ACCELERATOR**\n"
            "### Passer du calcul de volumétrie à la conversation risque, use cases et roadmap ES",
            "#FFFFFF",
        ),
        "heroSub": md(
            "**Méthode équipe** : partir du PvP et des données déjà ingérées, "
            "identifier les sources sécurité, relier aux règles ES OOTB, "
            "cartographier MITRE ATT&CK, puis construire une roadmap de collecte "
            "et de maturité SOC.",
            COLORS["muted"],
        ),
        "mode": table("Contexte de lecture", "dsContextMode", "#134E4A", 1),
        "kpiScore": single("Potentiel DSA++", "dsOpportunityScore", "#0D2A23", COLORS["green"]),
        "kpiObserved": single("Sources observées", "dsObservedSources", "#111C2F", "#FFFFFF"),
        "kpiRules": single("Règles ES activables", "dsActivableDetections", "#112A43", COLORS["blue"]),
        "kpiMitre": single("Techniques MITRE", "dsProjectedTechniques", "#1B2146", COLORS["violet"]),
        "kpiMissing": single("Sources roadmap", "dsMissingSources", "#3A1F17", COLORS["orange"]),
        "methodCard": md(
            "## La bonne posture\n"
            "DSA++ n’est pas un tableur de GB/jour. C’est un **atelier de "
            "maturité SOC** : risques client, sources déjà présentes, cas "
            "d’usage ES, MITRE ATT&CK, puis roadmap priorisée.",
            COLORS["text"],
        ),
        "pvpCard": md(
            "## Complément du PvP\n"
            "Le PvP donne le contexte et les risques. Le DSA++ apporte la "
            "preuve par la donnée : ce que Splunk voit déjà, ce qu’ES peut "
            "activer, et quelles sources débloquent la suite.",
            COLORS["text"],
        ),
        "flowTable": table("Déroulé atelier DSA++", "dsWorkshopFlow", "#14532D", 6),
        "decisionTable": table("Décision atelier", "dsDecisionGuide", "#1D4ED8", 4),
        "riskQuestions": table("Questions de conversation client", "dsRiskQuestions", "#7C2D12", 5),
        "domainReadiness": table("Maturité par domaine sécurité", "dsDomainReadiness", "#0E7490", 12),
        "sourceChecklist": table("Checklist sources : observées vs à intégrer", "dsSourceChecklist", "#14532D", 20),
        "sourceFamilies": bar("Sources observées par domaine", "dsSourceFamilies", COLORS["green"]),
        "sourceNote": md(
            "## Lecture des sources\n"
            "Chaque source doit être reliée à une valeur : règles ES activables, "
            "techniques MITRE couvertes, ou use cases à débloquer. La collecte "
            "devient une conversation risque, pas une liste technique.",
            "#D1FAE5",
        ),
        "rulesTable": table("Règles ES OOTB activables ou proches", "dsRulesActivable", "#0E7490", 20),
        "rulesBar": bar("Règles activables par domaine", "dsRulesByDomain", COLORS["blue"]),
        "rulesNote": md(
            "## Conversation use cases\n"
            "Les P1/P2 sont le cœur du rendez-vous : montrer les règles activables "
            "avec l’existant, puis discuter tuning, ownership SOC et conditions "
            "d’activation.",
            "#CFFAFE",
        ),
        "mitreTable": table("Techniques MITRE : couverture projetée", "dsMitreTechniques", "#5B21B6", 20),
        "mitreBar": bar("Tactiques MITRE couvertes", "dsMitreTactics", COLORS["violet"]),
        "mitreNote": md(
            "## Lecture MITRE\n"
            "MITRE sert à raconter la maturité détection en langage menace. "
            "L’objectif n’est pas de cocher toute la matrice, mais de relier "
            "les priorités de risque aux comportements adverses détectables.",
            "#E9D5FF",
        ),
        "roadmapTable": table("Roadmap sources priorisée par valeur", "dsRoadmap", "#9A3412", 20),
        "roadmapBar": bar("Roadmap par phase", "dsRoadmapPhases", COLORS["orange"]),
        "roadmapNote": md(
            "## Sortie attendue\n"
            "Un bon DSA++ se termine par un plan : quick wins, sources à "
            "onboarder, contenus ES à tester, trajectoire MITRE, et décision "
            "sur le niveau de maturité à viser.",
            "#FED7AA",
        ),
        "kpiAvgIngest": single("Moyenne ingestion / jour", "dsSizingAvgVolume", "#0B3B4A", COLORS["blue"]),
        "sizingChart": column("Volume quotidien ingéré (Go/jour)", "dsSizingDaily", COLORS["blue"]),
        "sizingStats": table("Profil capacité d’ingestion", "dsSizingStats", "#1D4ED8", 5),
        "sizingNote": md(
            "## Dimensionnement contextualisé\n"
            "La volumétrie est exprimée en capacité d’ingestion moyenne par jour "
            "à partir des logs de licence Splunk. Elle cadre l’architecture "
            "et la croissance liée à la roadmap. Pricing/licensing : RSM.",
            "#DBEAFE",
        ),
    }

    maturity = {
        "type": "absolute",
        "options": {"width": 1600, "height": 900, "backgroundColor": COLORS["bg"]},
        "structure": [
            block("bg", 0, 0, 1600, 900),
            block("accent", 24, 28, 8, 124),
            block("hero", 48, 26, 780, 86),
            block("heroSub", 50, 118, 760, 66),
            block("mode", 1040, 34, 536, 132),
            block("kpiScore", 24, 210, 284, 112),
            block("kpiObserved", 328, 210, 284, 112),
            block("kpiRules", 632, 210, 284, 112),
            block("kpiMitre", 936, 210, 284, 112),
            block("kpiMissing", 1240, 210, 284, 112),
            block("methodCard", 24, 350, 492, 142),
            block("pvpCard", 540, 350, 492, 142),
            block("decisionTable", 1040, 350, 536, 154),
            block("flowTable", 24, 536, 748, 340),
            block("riskQuestions", 800, 536, 776, 340),
        ],
    }

    sources = {
        "type": "absolute",
        "options": {"width": 1600, "height": 980, "backgroundColor": COLORS["bg"]},
        "structure": [
            block("bg", 0, 0, 1600, 980),
            block("accent", 24, 28, 8, 86),
            block("hero", 48, 26, 1000, 82),
            block("sourceNote", 1070, 34, 490, 132),
            block("kpiObserved", 24, 164, 310, 112),
            block("kpiMissing", 354, 164, 310, 112),
            block("kpiRules", 684, 164, 310, 112),
            block("sourceFamilies", 1014, 164, 562, 286),
            block("sourceChecklist", 24, 310, 970, 612),
            block("domainReadiness", 1014, 482, 562, 440),
        ],
    }

    rules = {
        "type": "absolute",
        "options": {"width": 1600, "height": 980, "backgroundColor": COLORS["bg"]},
        "structure": [
            block("bg", 0, 0, 1600, 980),
            block("accent", 24, 28, 8, 86),
            block("hero", 48, 26, 1000, 82),
            block("rulesNote", 1070, 34, 490, 132),
            block("kpiRules", 24, 164, 310, 112),
            block("kpiMitre", 354, 164, 310, 112),
            block("kpiScore", 684, 164, 310, 112),
            block("rulesBar", 1014, 164, 562, 286),
            block("rulesTable", 24, 310, 1552, 612),
        ],
    }

    mitre = {
        "type": "absolute",
        "options": {"width": 1600, "height": 980, "backgroundColor": COLORS["bg"]},
        "structure": [
            block("bg", 0, 0, 1600, 980),
            block("accent", 24, 28, 8, 86),
            block("hero", 48, 26, 1000, 82),
            block("mitreNote", 1070, 34, 490, 132),
            block("kpiMitre", 24, 164, 310, 112),
            block("kpiRules", 354, 164, 310, 112),
            block("kpiMissing", 684, 164, 310, 112),
            block("mitreBar", 1014, 164, 562, 286),
            block("mitreTable", 24, 310, 1552, 612),
        ],
    }

    roadmap = {
        "type": "absolute",
        "options": {"width": 1600, "height": 980, "backgroundColor": COLORS["bg"]},
        "structure": [
            block("bg", 0, 0, 1600, 980),
            block("accent", 24, 28, 8, 86),
            block("hero", 48, 26, 1000, 82),
            block("roadmapNote", 1070, 34, 490, 132),
            block("kpiMissing", 24, 164, 310, 112),
            block("kpiObserved", 354, 164, 310, 112),
            block("kpiMitre", 684, 164, 310, 112),
            block("roadmapBar", 1014, 164, 562, 286),
            block("roadmapTable", 24, 310, 1552, 612),
        ],
    }

    sizing = {
        "type": "absolute",
        "options": {"width": 1600, "height": 980, "backgroundColor": COLORS["bg"]},
        "structure": [
            block("bg", 0, 0, 1600, 980),
            block("accent", 24, 28, 8, 86),
            block("hero", 48, 26, 1000, 82),
            block("sizingNote", 1070, 34, 490, 132),
            block("kpiObserved", 24, 164, 270, 112),
            block("kpiRules", 314, 164, 270, 112),
            block("kpiMissing", 604, 164, 270, 112),
            block("kpiAvgIngest", 894, 164, 300, 112),
            block("sizingStats", 1214, 190, 362, 156),
            block("sizingChart", 24, 320, 1552, 420),
            block("domainReadiness", 24, 772, 1552, 172),
        ],
    }

    return {
        "title": "DSA++ Maturity Accelerator",
        "description": (
            "Atelier DSA++ : PvP, risk management, data sources, règles ES, "
            "MITRE ATT&CK, roadmap de collecte et sizing contextualisé."
        ),
        "inputs": {
            "input_time": {
                "type": "input.timerange",
                "title": "Fenêtre d’analyse",
                "options": {"token": "global_time", "defaultValue": "-30d@d,now"},
            },
            "input_limit": {
                "type": "input.dropdown",
                "title": "Profondeur",
                "options": {
                    "token": "result_limit",
                    "defaultValue": "20",
                    "items": [
                        {"label": "10 lignes", "value": "10"},
                        {"label": "20 lignes", "value": "20"},
                        {"label": "50 lignes", "value": "50"},
                    ],
                },
            },
        },
        "defaults": {
            "dataSources": {"ds.search": {"options": {}}},
            "visualizations": {
                "global": {"showProgressBar": False, "showLastUpdated": False}
            },
        },
        "dataSources": data_sources,
        "visualizations": visualizations,
        "layout": {
            "tabs": {
                "items": [
                    {"layoutId": "layout_maturity", "label": "Maturité DSA++"},
                    {"layoutId": "layout_sources", "label": "Sources"},
                    {"layoutId": "layout_rules", "label": "Règles ES"},
                    {"layoutId": "layout_mitre", "label": "MITRE"},
                    {"layoutId": "layout_roadmap", "label": "Roadmap"},
                    {"layoutId": "layout_sizing", "label": "Sizing"},
                ]
            },
            "layoutDefinitions": {
                "layout_maturity": maturity,
                "layout_sources": sources,
                "layout_rules": rules,
                "layout_mitre": mitre,
                "layout_roadmap": roadmap,
                "layout_sizing": sizing,
            },
            "globalInputs": ["input_time", "input_limit"],
            "options": {"showTitleAndDescription": False},
        },
    }


def build_xml(dashboard: dict[str, Any]) -> str:
    definition = json.dumps(dashboard, ensure_ascii=False, separators=(",", ":"))
    label = escape(dashboard["title"])
    return (
        '<dashboard version="2" theme="dark">\n'
        f"  <label>{label}</label>\n"
        f"  <definition><![CDATA[{definition}]]></definition>\n"
        '  <meta type="hiddenElements">'
        '{"hideEdit":false,"hideOpenInSearch":false,"hideExport":false}</meta>\n'
        "</dashboard>\n"
    )


def main() -> None:
    dashboard = build_dashboard()
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    VIEW_PATH.parent.mkdir(parents=True, exist_ok=True)
    NAV_PATH.parent.mkdir(parents=True, exist_ok=True)
    JSON_PATH.write_text(json.dumps(dashboard, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    VIEW_PATH.write_text(build_xml(dashboard), encoding="utf-8")
    NAV_PATH.write_text(f'<nav>\n  <view name="{VIEW_NAME}" default="true" />\n</nav>\n', encoding="utf-8")
    print(JSON_PATH)
    print(VIEW_PATH)
    print(NAV_PATH)


if __name__ == "__main__":
    main()
