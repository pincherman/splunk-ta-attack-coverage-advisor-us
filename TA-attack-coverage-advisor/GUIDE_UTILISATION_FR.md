# Guide d’utilisation — DSA++ Maturity Accelerator

Version de documentation : v0.9.2  
App Splunk : `TA-attack-coverage-advisor`  
Dashboard : `attack_coverage_advisor_command_center`  
Commande SPL : `attackcoverageadvisor`

---

## 1. À quoi sert ce TA ?

Le **DSA++ Maturity Accelerator** est un accélérateur d’atelier avant-vente pour les clients qui ont déjà Splunk, avec ou sans Enterprise Security.

Son objectif n’est pas de produire un audit contractuel, ni un calcul de licence. Son objectif est de structurer une conversation DSA++ autour de questions concrètes :

- Quelles données sécurité Splunk voit-il déjà ?
- Quelles règles ES OOTB deviennent crédibles avec ces données ?
- Quels comportements MITRE ATT&CK peut-on couvrir ou projeter ?
- Quelles sources manquantes débloquent le plus de valeur ?
- Quelle roadmap de collecte proposer avant un POC ou une extension ES ?
- Comment contextualiser le sizing sans réduire la discussion aux GB/jour ?

Message à porter en client :

> Vos données Splunk actuelles contiennent déjà de la valeur sécurité. DSA++ permet de montrer comment cette télémétrie peut être transformée en détections, investigation, risk-based alerting et roadmap de maturité SOC avec Enterprise Security.

---

## 2. Quand l’utiliser ?

### Bons cas d’usage

Utiliser ce TA pour :

- préparer ou animer un atelier DSA++ ;
- compléter un PvP avec une lecture data-driven ;
- qualifier la valeur potentielle d’Enterprise Security chez un client Splunk existant ;
- préparer un POC sécurité ;
- identifier les sources prioritaires à onboarder ;
- parler MITRE ATT&CK, règles de corrélation et use cases sans partir d’une page blanche ;
- nourrir une discussion RSM / SE / client sur la prochaine étape.

### Mauvais cas d’usage

Ne pas l’utiliser comme :

- outil de pricing ou de licensing ;
- engagement contractuel de couverture MITRE ;
- preuve que des règles sont prêtes à passer en production ;
- audit SOC complet ;
- outil de validation CIM automatique ;
- substitut à une vraie analyse PS / architecture.

---

## 3. Sources du mapping

Le TA s’appuie sur le dépôt officiel Splunk **Security Content** :

- repository : `https://github.com/splunk/security_content`
- data sources : `security_content/data_sources/*.yml`
- detections : `security_content/detections/**/*.yml`

Les fichiers `data_sources/*.yml` décrivent les sources attendues par les contenus de détection Splunk :

- nom de la data source ;
- `source` ;
- `sourcetype` ;
- TA recommandé ;
- champs attendus ;
- composants MITRE ;
- exemple de log quand disponible.

Les fichiers `detections/**/*.yml` décrivent les règles / analytics Splunk Security Content :

- nom de la détection ;
- statut (`production`, `experimental`, etc.) ;
- data sources requises ;
- tags MITRE ATT&CK ;
- analytic stories ;
- SPL de référence ;
- consignes d’implémentation.

Au build du TA, ces YAML sont transformés en lookups embarqués :

- `lookups/attack_coverage_data_sources.csv`
- `lookups/attack_coverage_detections.csv`
- `lookups/attack_coverage_detection_data_sources.csv`

Le runtime n’a pas besoin d’accès Internet.

---

## 4. Comment fonctionne le mapping source → règle ?

Le TA ne fait pas de mapping par IA et ne devine pas les règles.

Il suit cette chaîne :

```text
Splunk Security Content
  → data source officielle
  → source / sourcetype attendu
  → règle ES / détection qui référence cette data source
  → techniques MITRE associées
```

Puis, sur l’instance client, il regarde ce qui est réellement visible dans Splunk avec :

```spl
| metadata type=sourcetypes
| metadata type=sources
```

Ensuite il compare :

```text
Data sources attendues par les détections
VS
Data sources observées dans les données Splunk du client
```

Résultat :

| Statut | Signification | Usage SE |
|---|---|---|
| `present` / observée | La source ou le sourcetype attendu est visible dans Splunk | Base factuelle : Splunk collecte déjà quelque chose d’exploitable |
| `activable` | Toutes les data sources mappées pour une règle sont visibles | Quick win potentiel, à valider et tuner avant production |
| `partial` | Une partie des sources requises est visible | Conversation maturité collecte / CIM / source complémentaire |
| `gap` | Une source absente débloquerait des règles ou techniques | Roadmap de collecte priorisée |
| `current` | Une correlation search ES active est détectée | Lecture adoption / sous-utilisation d’ES |

---

## 5. Interpréter les principaux badges

### Sources observées

Nombre de data sources du catalogue Security Content dont le `source` ou `sourcetype` est visible dans Splunk.

À dire au client :

> “Voici la matière sécurité que Splunk voit déjà et que l’on peut relier à des contenus de détection.”

À ne pas dire :

> “Toutes ces sources sont propres, normalisées CIM et prêtes pour production.”

### Règles ES activables

Nombre de détections pour lesquelles les data sources requises sont présentes selon le catalogue.

À dire :

> “Ces règles méritent une revue rapide : les prérequis data semblent présents.”

Garde-fou :

> Activation ne veut pas dire production immédiate. Il faut valider champs, CIM, qualité, bruit, seuils, ownership et runbook.

### Techniques MITRE

Nombre de techniques MITRE ATT&CK projetées via les détections potentiellement activables ou proches.

À dire :

> “Cela traduit les sources et règles en comportements adverses compréhensibles par le SOC et le RSSI.”

Garde-fou :

> Ce n’est pas une couverture MITRE contractuelle ; c’est une projection basée sur le catalogue Splunk Security Content.

### Sources roadmap

Nombre de sources manquantes priorisées parce qu’elles débloquent des règles ou des techniques.

À dire :

> “Voici les 3 à 5 sources qui créeraient le plus d’effet de levier pour le prochain trimestre.”

### Momentum DSA++

Score synthétique de potentiel d’atelier, plafonné à 100.

Il combine :

- règles ES activables ;
- techniques MITRE projetées ;
- règles adjacentes / presque activables.

Formule actuelle :

```spl
raw = activables * 1.5
    + techniques MITRE * 0.25
    + règles adjacentes * 0.06

Momentum = min(raw, 100)
```

Lecture :

- score bas : atelier orienté qualification et collecte ;
- score moyen : atelier intéressant, avec des quick wins ciblés ;
- score élevé : forte matière pour une conversation ES / SOC maturity.

Garde-fou : ce n’est pas un score officiel Splunk, ni un score de maturité SOC. C’est un thermomètre avant-vente.

---

## 6. Lire les onglets du dashboard

### 6.1 Maturité DSA++

Onglet d’ouverture.

Objectif : cadrer l’histoire : PvP, risques, sources, règles ES, MITRE, roadmap.

Conseil d’usage : commencer ici en client. Ne pas aller directement dans les tableaux techniques.

Questions utiles :

- Quels scénarios de risque voulez-vous mieux détecter ?
- Quelles données sécurité sont déjà dans Splunk ?
- Quelles règles ES pourraient être testées rapidement ?
- Quelles sources manquantes bloquent la maturité ?

### 6.2 Sources

Montre les sources observées et les sources à intégrer.

Conseil d’usage : l’utiliser avec un profil SOC / plateforme pour valider la réalité des données.

À vérifier :

- le sourcetype existe-t-il vraiment ?
- la source est-elle active récemment ?
- le TA recommandé est-il présent ?
- les champs clés sont-ils exploitables ?
- la normalisation CIM est-elle suffisante ?

### 6.3 Règles ES

Montre les règles OOTB activables ou proches.

Conseil d’usage : choisir quelques règles P1/P2 pour construire un plan de test, pas tout activer.

Approche recommandée :

1. sélectionner 3 à 5 règles à forte valeur métier ;
2. vérifier les champs requis ;
3. lancer un test sur historique ;
4. estimer le bruit ;
5. définir owner, seuils et runbook ;
6. seulement ensuite discuter activation.

### 6.4 MITRE

Traduit la conversation en tactiques / techniques ATT&CK.

Conseil d’usage : utile avec RSSI, SOC manager, architecte sécurité.

À éviter : transformer l’onglet MITRE en promesse de couverture exhaustive.

### 6.5 Roadmap

Priorise les sources manquantes par valeur débloquée.

Conseil d’usage : faire sortir une roadmap courte : 3 à 5 sources maximum pour le prochain incrément.

Bonne formulation :

> “Si nous intégrons cette source, nous débloquons potentiellement X règles et Y techniques ATT&CK. Cela devient un bon candidat pour le prochain sprint de collecte.”

### 6.6 Sizing

Contextualise la volumétrie et la trajectoire d’ingestion.

Conseil d’usage : s’en servir après la conversation valeur, jamais comme point de départ.

Message :

> “Le sizing doit découler de la roadmap de use cases et de sources, pas l’inverse.”

---

## 7. Séquence d’atelier recommandée

### Avant l’atelier

1. Installer le TA sur un search head adapté.
2. Lancer un smoke test :

```spl
| attackcoverageadvisor mode=summary
```

3. Vérifier que le dashboard charge correctement.
4. Identifier les 5 à 10 signaux forts : sources observées, règles activables, gaps majeurs.
5. Préparer 3 questions de risque client issues du PvP ou de la qualification.

### Pendant l’atelier

Séquence conseillée :

1. **Maturité DSA++** — cadrer l’objectif : risque, use cases, ES value.
2. **Sources** — montrer ce que Splunk voit déjà.
3. **Règles ES** — sélectionner quelques quick wins crédibles.
4. **MITRE** — traduire en comportements adverses.
5. **Roadmap** — prioriser les sources à intégrer.
6. **Sizing** — contextualiser l’impact volumétrique.

### Après l’atelier

Produire une synthèse simple :

- 3 constats data ;
- 3 règles / use cases à tester ;
- 3 sources à prioriser ;
- 1 prochain pas : workshop, POC, revue ES, qualification PS ou discussion RSM.

---

## 8. SPL utiles

### Résumé exécutif

```spl
| attackcoverageadvisor mode=summary
```

### Sources observées

```spl
| attackcoverageadvisor mode=inventory limit=100
| table family data_source_name inventory_match supported_ta_names recommendation
```

### Règles activables ou proches

```spl
| attackcoverageadvisor mode=potential include_partial=true limit=50
| table status detection_name family data_source_name matched_data_source_count required_data_source_count mitre_attack_ids reason recommendation
```

### Roadmap sources manquantes

```spl
| attackcoverageadvisor mode=gaps limit=25
| table data_source_name family detection_count technique_count supported_ta_names reason recommendation
```

### Couverture ES active, si ES est installé

```spl
| attackcoverageadvisor mode=current limit=100
| table status detection_name data_source_name mitre_attack_ids reason recommendation
```

### Vue complète exportable

```spl
| attackcoverageadvisor mode=full include_partial=true limit=1000
```

---

## 9. Réponses aux questions fréquentes

### “D’où vient le mapping source → règle ?”

Du repository Splunk Security Content. Les data sources et les détections sont déclarées dans des YAML maintenus côté Splunk Research / Security Content. Le TA les transforme en lookups embarqués.

### “Est-ce que le TA lit les événements bruts ?”

Non, pas pour le mapping principal. Il utilise `metadata` pour identifier les sources et sourcetypes visibles. Cela le rend léger et adapté à un atelier. Une validation production doit ensuite inspecter les événements, les champs et la qualité CIM.

### “Pourquoi une règle est activable alors que je sais qu’elle nécessite plus de tuning ?”

Parce que “activable” signifie uniquement : les data sources mappées sont visibles. Le tuning, les seuils, la qualité des champs et l’ownership restent à faire.

### “Pourquoi une source semble absente alors que le client collecte bien cette technologie ?”

Causes fréquentes :

- sourcetype custom ;
- source renommée ;
- TA non standard ;
- données dans un index non inclus ;
- données anciennes hors fenêtre ;
- mapping Security Content différent du naming client.

Action : vérifier `index`, `sourcetype`, `source`, puis adapter l’analyse ou documenter l’écart.

### “Est-ce que cela couvre les règles custom du client ?”

Pas complètement. Les règles custom peuvent apparaître comme actives si ES les expose, mais le mapping catalogue est centré sur Splunk Security Content / ES OOTB.

### “Peut-on l’utiliser sans ES ?”

Oui. Sans ES, le TA fonctionne comme projection DSA++ : il montre ce que les données Splunk actuelles pourraient débloquer avec ES et une roadmap de collecte.

### “Peut-on l’utiliser avec ES déjà installé ?”

Oui. Avec ES, le TA ajoute une lecture d’adoption : contenus actifs, contenus activables, contenus sous-exploités et gaps de sources.

---

## 10. Garde-fous commerciaux et delivery

### À dire

- “C’est un accélérateur d’atelier.”
- “Les résultats sont directionnels.”
- “On part des données réellement visibles dans Splunk.”
- “On relie données, règles ES, MITRE et roadmap.”
- “La validation production nécessite tuning et ownership.”

### À éviter

- “Vous êtes couvert à X % MITRE.”
- “Ces règles peuvent être activées directement.”
- “Voici votre sizing contractuel.”
- “Cette analyse remplace un audit SOC.”
- “Cette roadmap engage PS sans cadrage.”

### Scope recommandé

- Pricing / licensing : RSM.
- Implémentation détaillée : PS.
- Contrats / engagements : équipe commerciale / juridique.
- Tuning de règles : SOC owner + SE/PS selon contexte.

---

## 11. Conseils de présentation client

### Ton recommandé

Parler de **valeur et de maturité**, pas de catalogue technique.

Mauvaise ouverture :

> “On a trouvé 664 règles activables.”

Bonne ouverture :

> “Vos données actuelles permettent déjà d’ouvrir plusieurs conversations sécurité concrètes : identité, endpoint, réseau, cloud. Regardons lesquelles créent le plus de valeur pour vos risques prioritaires.”

### Storyline simple

```text
1. Vos risques prioritaires
2. Vos données déjà présentes
3. Les détections ES crédibles
4. La lecture MITRE
5. Les sources qui manquent
6. La roadmap et le prochain pas
```

### Sortie attendue

Un bon atelier ne doit pas finir avec “beaucoup de chiffres”. Il doit finir avec :

- une liste courte de use cases ;
- une liste courte de sources ;
- une décision claire sur le prochain pas.

---

## 12. Limites connues

- Le mapping dépend de la fraîcheur du catalogue Security Content embarqué.
- Le matching principal est basé sur `source` / `sourcetype`, pas sur l’analyse exhaustive des champs.
- Les environnements très custom peuvent nécessiter une adaptation du mapping.
- Les détections expérimentales ne sont incluses que si le catalogue est régénéré avec `--include-experimental`.
- Les résultats MITRE sont projetés via les tags des détections, pas mesurés par simulation d’attaque.
- Le score Momentum DSA++ est un indicateur avant-vente, pas un KPI officiel produit.

---

## 13. Checklist rapide SE

Avant de montrer le dashboard :

- [ ] Le dashboard charge sans erreur.
- [ ] `| attackcoverageadvisor mode=summary` retourne des lignes.
- [ ] Le contexte ES détecté / non détecté est cohérent.
- [ ] Les sources observées semblent plausibles.
- [ ] Les règles activables sont expliquées comme “à valider”.
- [ ] Les gaps sont priorisés, pas présentés comme une liste infinie.
- [ ] Le sizing est présenté après la valeur.
- [ ] Les limites directionnelles sont explicitées.

---

## 14. Références

- Splunk Security Content : https://github.com/splunk/security_content
- Data sources Security Content : https://github.com/splunk/security_content/tree/develop/data_sources
- Splunk Enterprise Security overview : https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.5/introduction/about-splunk-enterprise-security
- ES detection annotations : https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.2/detections/add-annotations-to-detections-in-splunk-enterprise-security
- MITRE ATT&CK in Splunk Security Essentials : https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-the-analytics-advisor-in-splunk-security-essentials/the-mitre-attck-framework-dashboard
