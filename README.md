# S-Filer MCP Server — Okiok

Serveur **Model Context Protocol (MCP)** permettant à un agent d'intelligence artificielle d'interagir avec la plateforme de transfert sécurisé de fichiers **S-Filer**.

Le projet expose des outils permettant de rechercher des fichiers, de téléverser des documents, de créer des partages externes et de consulter l'activité récente d'un compte S-Filer. Il intègre également plusieurs mécanismes de sécurité visant à limiter les risques associés à l'utilisation d'un agent IA disposant d'un accès à des ressources sensibles.

---

## Fonctionnalités

Le serveur expose quatre outils MCP :

| Outil | Description |
|---|---|
| `rechercher_fichiers` | Recherche des fichiers dans S-Filer à partir d'un nom, d'un mot-clé ou d'un expéditeur. |
| `televerser` | Téléverse un fichier local vers S-Filer, avec la possibilité de cibler un dossier à l'aide de son identifiant. |
| `partager` | Crée un transfert externe à destination d'un destinataire, avec une durée d'expiration configurable et une confirmation explicite. |
| `lister_activite` | Consulte l'activité récente du compte S-Filer. |

### Détails des fonctionnalités

**Recherche de fichiers**
- Recherche par nom ou mot-clé.
- Filtrage facultatif par expéditeur.
- Récupération des résultats à partir des fichiers récents et, en cas de réponse vide, de l'arborescence S-Filer.

**Téléversement**
- Envoi de fichiers locaux vers S-Filer.
- Récupération automatique de la clé publique du système.
- Chiffrement du contenu avant son transfert.
- Possibilité de cibler un dossier à l'aide de son identifiant `node_id`.
- Utilisation du dossier racine lorsque aucun identifiant de dossier n'est fourni.

**Partage externe**
- Création d'un transfert anonyme de type envoi (`SEND`).
- Définition du destinataire par adresse courriel.
- Définition d'une durée d'expiration comprise entre 1 et 30 jours.
- Confirmation explicite obligatoire avant la création du partage.
- Téléversement du fichier local associé au transfert lorsque les informations de destination nécessaires sont retournées par S-Filer.

**Suivi de l'activité**
- Consultation de l'activité récente du compte.
- Période configurable de 1 à 90 jours.

---

## Architecture

Le projet est organisé autour de trois modules principaux :

```text
src/
└── okiokdefi/
    ├── __init__.py
    ├── server.py
    ├── sfiler_client.py
    └── security.py
```

### `server.py` — Serveur MCP

Point d'entrée du serveur MCP, développé avec **FastMCP**.

Responsabilités :
- Déclaration et exposition des outils MCP.
- Validation des paramètres avant leur transmission au client S-Filer.
- Application des règles de sécurité propres à chaque opération.
- Gestion des erreurs et journalisation des exceptions.
- Assainissement des résultats avant leur transmission à l'agent IA.

Les instructions du serveur définissent également des règles de sécurité destinées à encadrer le comportement de l'agent, notamment concernant la confirmation des opérations sensibles et le traitement des données externes.

### `sfiler_client.py` — Client S-Filer

Gère les communications HTTP avec S-Filer à l'aide de `httpx`.

Responsabilités :
- Authentification et gestion des sessions utilisateur.
- Gestion des cookies de session et du jeton CSRF.
- Exécution des requêtes HTTP nécessaires aux différentes opérations.
- Chiffrement des fichiers avant leur téléversement.
- Création de transferts externes et consultation de l'activité.

Le chiffrement des fichiers repose sur une approche hybride :
- **AES-128-CTR** pour chiffrer le contenu du fichier.
- **RSA-OAEP avec SHA-256** pour protéger la clé symétrique.
- Génération aléatoire d'une clé AES et d'un vecteur d'initialisation (IV) pour chaque opération.

Cette approche permet de chiffrer le contenu localement avant son envoi. AES-CTR ne fournit toutefois pas, à lui seul, de mécanisme d'authentification ou de vérification de l'intégrité du contenu.

### `security.py` — Couche de sécurité

Centralise les mécanismes de validation et de protection contre les entrées et les données malveillantes.

Responsabilités :
- Validation des chemins de fichiers locaux.
- Prévention du Path Traversal et des accès aux fichiers cachés.
- Détection des caractères potentiellement dangereux dans les paramètres transmis à S-Filer.
- Limitation de la longueur des paramètres.
- Validation des adresses courriel et des durées d'expiration.
- Vérification de la confirmation humaine avant un partage externe.
- Encapsulation des données provenant de S-Filer comme données non fiables.

---

## Sécurité

La sécurité constitue un élément central du projet.

L'approche retenue repose sur un principe de **Zero Trust envers l'agent IA** : les décisions du modèle ne sont pas considérées comme intrinsèquement fiables. Les opérations sensibles sont encadrées par des validations réalisées directement dans le code Python, plutôt que de dépendre uniquement des instructions transmises au modèle.

### Analyse des menaces et contre-mesures

| Menace | Risque | Contre-mesure |
|---|---|---|
| Indirect Prompt Injection | Un fichier ou une métadonnée malveillante tente de manipuler l'agent. | Encapsulation des données externes dans des balises `<untrusted_data>`, échappement de la balise de fermeture et instructions de sécurité explicites. |
| Tool-Chain Escalation | L'agent enchaîne plusieurs outils pour effectuer une action non autorisée. | Vérification de la confirmation explicite avant la création d'un partage externe. |
| Exfiltration de données | Transmission non autorisée de fichiers à un destinataire externe. | Validation du destinataire, de la durée d'expiration et approbation humaine. |
| Path Traversal | Accès à des fichiers situés en dehors du répertoire autorisé. | Résolution canonique des chemins, confinement avec `is_relative_to()` et rejet des chemins contenant des fichiers ou dossiers cachés. |
| Downstream System Injection | Injection de caractères de contrôle ou de contenu potentiellement dangereux dans les paramètres transmis à S-Filer. | Filtrage des caractères interdits et limitation de la longueur des paramètres. |
| Memory Poisoning | Tentative d'altération de la mémoire persistante de l'agent à partir de données externes. | Marquage explicite des données non fiables et avertissement demandant à l'agent de ne pas les mémoriser. |
| Credential Exposure | Divulgation d'informations sensibles à travers les erreurs retournées à l'agent. | Interception des exceptions et retour de messages d'erreur génériques, avec journalisation des détails techniques côté serveur. |
| Tool Metadata Poisoning | Altération ou substitution des outils disponibles pour l'agent. | Verrouillage des dépendances avec `uv.lock` et contrôle de l'intégrité du code source. |

### Confirmation humaine

Le partage externe constitue une opération sensible.

Avant de procéder, l'outil `partager` exige une confirmation explicite de l'utilisateur. En l'absence de confirmation, aucune opération de partage n'est effectuée.

La confirmation doit porter sur les trois éléments suivants :

- Le fichier à partager.
- L'adresse du destinataire.
- La durée d'expiration.

Le paramètre `confirme` doit être explicitement défini à `True` uniquement après obtention de l'accord de l'utilisateur.

La vérification est réalisée dans le code Python : elle ne repose donc pas uniquement sur les instructions données à l'agent IA.

### Limite de sécurité

Les mécanismes implémentés réduisent les risques d'utilisation abusive des outils par l'agent IA. Ils ne peuvent toutefois pas empêcher un utilisateur légitime d'approuver volontairement un partage malveillant.

De plus, les mécanismes d'encapsulation des données non fiables constituent une mesure de défense contre les injections d'instructions, mais ne garantissent pas à eux seuls qu'un modèle ne sera jamais influencé par un contenu malveillant.

---

## Communication avec S-Filer

### Méthode d'intégration

**Le projet n'utilise pas l'API publique documentée de S-Filer.**

En raison des contraintes rencontrées lors de l'intégration, nous avons retenu une approche alternative consistant à reproduire les requêtes HTTP utilisées directement par l'interface Web de S-Filer.

Les communications sont effectuées avec un compte utilisateur S-Filer existant, au moyen de ses identifiants de connexion.

Cette approche permet notamment :
- De reproduire le processus d'authentification de l'interface Web.
- De maintenir une session utilisateur à l'aide des cookies et du jeton CSRF.
- D'utiliser les requêtes AJAX de l'interface pour rechercher et téléverser des fichiers.
- D'accéder à certains points de terminaison internes nécessaires aux opérations de transfert.

Les requêtes sont exécutées directement depuis le client Python avec `httpx`.

### Particularités et limites

Cette méthode d'intégration présente certaines limites :

- Les requêtes utilisées ne constituent pas une interface publique officiellement garantie.
- Les points de terminaison internes et les paramètres des requêtes peuvent évoluer lors d'une mise à jour de S-Filer.
- Le fonctionnement dépend des autorisations associées au compte utilisateur configuré.
- Les mécanismes d'authentification et de session doivent rester compatibles avec l'interface Web.

Cette solution a été retenue afin de permettre une intégration avec l'environnement S-Filer disponible, malgré les contraintes rencontrées avec l'API publique.

---

## Installation (en 2 étapes)

### Prérequis

- [uv](https://docs.astral.sh/uv/) installé sur la machine (`curl -LsSf https://astral.sh/uv/install.sh | sh` sous Linux/macOS ou `winget install astral-sh.uv` sous Windows).
- Un compte utilisateur disposant d'un accès à S-Filer.

---

Une fois le projet cloné (`git clone <URL> && cd okiokdefi`), l'installation s'effectue en **deux étapes simples** :

### Étape 1 — Configuration des variables d'environnement

Copier le fichier d'exemple et renseigner vos identifiants S-Filer :

```bash
cp .env.example .env
```

Éditer le fichier `.env` avec vos accès S-Filer :

```env
SFILER_BASE_URL=https://sfilerdemo2.sfiler.com/sfiler
SFILER_USERNAME=votre_courriel@exemple.com
SFILER_PASSWORD=votre_mot_de_passe
SFILER_DOMAIN_ID=1
```

| Variable | Description |
|---|---|
| `SFILER_BASE_URL` | Adresse de l'instance S-Filer. |
| `SFILER_USERNAME` | Identifiant du compte utilisateur (adresse courriel). |
| `SFILER_PASSWORD` | Mot de passe du compte utilisateur. |
| `SFILER_DOMAIN_ID` | Identifiant du domaine S-Filer (par défaut `1`). |

> **Important :** Le fichier `.env` contient des secrets et est automatiquement ignoré par Git via le `.gitignore`.

### Étape 2 — Installation des dépendances

Exécuter la synchronisation de l'environnement :

```bash
uv sync
```

Cette commande unique crée l'environnement virtuel `.venv`, installe l'interpréteur Python approprié et verrouille les dépendances exactement selon le fichier `uv.lock`. L'installation est terminée.

---

## Démarrage

### Lancement manuel

Le serveur MCP doit être démarré depuis la **racine du projet**, c'est-à-dire le répertoire contenant `pyproject.toml`.

Exécuter les commandes suivantes :

```powershell
uv sync
uv run python -m okiokdefi.server
```

Le serveur utilise le transport MCP configuré par FastMCP. Le transport standard utilisé pour une intégration locale est STDIO.

**Important :** ne pas lancer directement le fichier avec `uv run server.py` ou `uv run src/okiokdefi/server.py`.

Le serveur utilise des imports relatifs, notamment :

```python
from . import security, sfiler_client
```

L'option `-m` permet à Python d'exécuter `okiokdefi.server` en tant que module du package `okiokdefi`. Python peut ainsi résoudre correctement les imports relatifs.

### Intégration avec Antigravity

Le serveur peut être intégré directement à **Antigravity** (Antigravity CLI `agy` ou Antigravity IDE) afin que l'agent IA puisse découvrir et exploiter ses outils MCP en langage naturel.

Deux méthodes d'intégration sont disponibles :

- **Méthode 1 — En une commande via le CLI `agy` (recommandée)** : Enregistrement instantané du serveur MCP dans Antigravity.
- **Méthode 2 — Configuration déclarative via `.mcp.json`** : Pratique pour le partage de configuration au niveau de l'espace de travail.

---

#### Méthode 1 — En une commande via le CLI `agy` (recommandée)

Depuis la racine du projet, exécuter simplement :

```bash
agy mcp add sfiler-mcp -- uv run python -m okiokdefi.server
```

*(Ou en spécifiant le chemin absolu du projet avec `--directory`) :*

```bash
agy mcp add sfiler-mcp -- uv run --directory /CHEMIN/VERS/LE/PROJET python -m okiokdefi.server
```

> **Pourquoi cette méthode est idéale ?**
> Grâce au gestionnaire `uv`, la commande `uv run` détecte automatiquement `pyproject.toml` et `uv.lock`, crée le `.venv` à la volée s'il n'existe pas encore, installe les dépendances et démarre le serveur MCP STDIO. Aucun `uv sync` préalable n'est obligatoire !

---

#### Méthode 2 — Configuration déclarative via `.mcp.json`

Pour enregistrer le serveur au niveau du projet (partageable dans l'équipe), créer un fichier nommé `.mcp.json` à la racine du dépôt :

```text
okiok-JCXTeam/
├── .mcp.json
├── pyproject.toml
├── uv.lock
└── src/
```

Contenu du fichier `.mcp.json` :

```json
{
  "mcpServers": {
    "sfiler-mcp": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "run",
        "python",
        "-m",
        "okiokdefi.server"
      ],
      "cwd": "/CHEMIN/VERS/LE/PROJET",
      "tools": ["*"]
    }
  }
}
```

Remplacer `/CHEMIN/VERS/LE/PROJET` par le chemin absolu du répertoire du projet (ou `C:\\CHEMIN\\VERS\\LE\\PROJET` sous Windows), c'est-à-dire le dossier contenant `pyproject.toml`.

**Explication des paramètres :**

| Paramètre | Rôle |
|---|---|
| `type` | Définit le transport utilisé. `stdio` permet une communication locale par entrée/sortie standard. |
| `command` | Commande exécutée pour démarrer le serveur (`uv`). |
| `args` | Arguments transmis à `uv` pour lancer le module Python (`run python -m okiokdefi.server`). |
| `cwd` | Répertoire de travail du processus. Il permet notamment de charger le projet et son fichier `.env`. |
| `tools` | Définit les outils exposés à l'agent. `["*"]` rend tous les outils du serveur disponibles. |

Le processus lancé par Antigravity utilise directement l'environnement virtuel du projet grâce à `uv run`. Il n'est donc pas nécessaire de démarrer manuellement le serveur dans un terminal séparé.

#### Option 2 — Configuration globale Antigravity

Sur votre machine, le répertoire de configuration des serveurs MCP d'Antigravity se trouve à l'emplacement suivant :

```text
~/.gemini/antigravity-cli/mcp/sfiler-mcp/
```
(ou sous Windows : `%USERPROFILE%\.gemini\antigravity-cli\mcp\sfiler-mcp\`)

Exemple de bloc de configuration globale :

```json
{
  "mcpServers": {
    "sfiler": {
      "command": "uv",
      "args": [
        "--directory",
        "/CHEMIN/VERS/LE/PROJET",
        "run",
        "python",
        "-m",
        "okiokdefi.server"
      ],
      "tools": ["*"]
    }
  }
}
```

#### Activation et vérification dans Antigravity

Après avoir enregistré la configuration :

1. Lancer la session Antigravity (CLI ou IDE) dans le répertoire du projet.
2. Vérifier que le serveur `sfiler` apparaît bien dans la liste des serveurs MCP actifs.
3. Poser directement vos requêtes en langage naturel à Antigravity, par exemple :

```text
Liste l'activité récente sur S-Filer des 7 derniers jours.
```

Ou pour tester la recherche :

```text
Quels fichiers ai-je reçus de akinlolaagboidji@gmail.com ce mois-ci ?
```

Antigravity convertit automatiquement la demande en appels d'outils MCP sécurisés, applique les validations requises et présente le compte rendu formaté.

#### Dépannage

En cas de problème de démarrage ou de découverte des outils :

- Vérifier que `uv` est installé et accessible dans le `PATH`.
- Vérifier que le paramètre `cwd` ou `--directory` pointe bien vers le répertoire contenant `pyproject.toml`.
- Vérifier que le fichier `.env` est présent à la racine du projet avec les identifiants S-Filer.
- Vérifier la validité syntaxique du JSON de configuration.
- Vérifier que les dépendances ont été installées avec `uv sync`.

Pour consulter les journaux d'erreurs ou logs du serveur MCP, vérifier les logs de session d'Antigravity.

**Note de sécurité :** `tools: ["*"]` expose tous les outils du serveur à Antigravity. Ce paramètre ne remplace pas les validations de sécurité implémentées dans le code Python : toute action irréversible ou externe (ex. `partager`) requiert impérativement un code de confirmation éphémère approuvé par l'utilisateur.

---

### Intégration avec un autre client MCP

Pour un autre client MCP prenant en charge le transport STDIO, il faut configurer celui-ci afin qu'il exécute la commande de démarrage avec le répertoire du projet comme répertoire de travail.

Exemple de configuration générique :

```json
{
  "mcpServers": {
    "sfiler": {
      "command": "uv",
      "args": [
        "--directory",
        "CHEMIN_DU_PROJET",
        "run",
        "python",
        "-m",
        "okiokdefi.server"
      ]
    }
  }
}
```

Remplacer `CHEMIN_DU_PROJET` par le chemin absolu du dépôt sur la machine exécutant le client MCP.

---

## Dépendances principales

| Dépendance | Utilisation |
|---|---|
| `fastmcp` | Création du serveur et exposition des outils MCP. |
| `httpx` | Communications HTTP asynchrones avec S-Filer. |
| `cryptography` | Chiffrement AES/RSA et manipulation des certificats. |
| `python-dotenv` | Chargement des variables d'environnement depuis `.env`. |

Les versions minimales sont définies dans `pyproject.toml`.

---

## Structure du projet

```text
okiok-JCXTeam/
│
├── src/
│   └── okiokdefi/
│       ├── __init__.py
│       ├── server.py
│       ├── sfiler_client.py
│       └── security.py
│
├── .env
├── .gitignore
├── pyproject.toml
├── uv.lock
└── README.md
```

---

## Technologies utilisées

- **Python** — Langage principal.
- **Model Context Protocol (MCP)** — Protocole d'intégration des outils avec les agents IA.
- **FastMCP** — Framework de développement du serveur MCP.
- **HTTPX** — Client HTTP asynchrone.
- **Cryptography** — Bibliothèque cryptographique.
- **uv** — Gestionnaire de dépendances et d'environnements Python.

---

## Limites connues

1. **Intégration hybride S-Filer** : En raison des permissions restreintes du compte utilisateur bac à sable sur l'API REST interne (codes 401 sur `/reports/*`), la consultation de l'activité et la recherche de fichiers s'appuient sur les requêtes authentifiées du portail web (`RecentFilesAjax.action`), couplées à un parseur strict qui élimine tout artefact HTML. Une implémentation 100% basée sur le Swagger REST officiel est également disponible sur la branche Git `swagger-rest-api`.
2. **Chiffrement E2EE AES-128-CTR** : Le chiffrement symétrique respecte le standard imposé par le client S-Filer (AES-CTR + enveloppement RSA-OAEP SHA-256). Il assure la confidentialité des fichiers en transit mais ne fournit pas d'authentification cryptographique de message (HMAC) native sans signature applicative additionnelle.
3. **Confirmation humaine** : La protection par code éphémère à usage unique garantit qu'aucune exfiltration ou action sensible ne peut être déclenchée automatiquement par une injection de prompt indirecte. Cependant, cette protection dépend de la vigilance de l'utilisateur qui approuve le partage.

---

## Crédits

- **Projet** : Assistant IA pour S-Filer — Défi Étudiant S-Filer 2026.
- **Équipe** : JCXTeam / Drag0flyer (`khobaib_ayyaz@outlook.fr`).
- **Organisation** : [OKIOK](https://www.okiok.com/) — La cybersécurité simplifiée.

---

## Licence

Projet réalisé dans le cadre du Défi Étudiant OKIOK 2026. Tous droits réservés.