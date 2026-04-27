# 📋 Audit, Logs & Journalisation avec Git

> Git est bien plus qu'un outil de versionnage : il embarque un système complet de traçabilité et d'audit permettant de retracer l'historique complet d'un projet, d'identifier des régressions, de comprendre les décisions passées et de garantir la conformité.

---

## Table des matières

1. [Concepts fondamentaux](#1-concepts-fondamentaux)
2. [git log — Explorer l'historique](#2-git-log--explorer-lhistorique)
3. [git blame — Identifier l'auteur ligne par ligne](#3-git-blame--identifier-lauteur-ligne-par-ligne)
4. [git diff — Comparer les états](#4-git-diff--comparer-les-états)
5. [git show — Inspecter un commit](#5-git-show--inspecter-un-commit)
6. [git reflog — Journal interne de Git](#6-git-reflog--journal-interne-de-git)
7. [git bisect — Audit par dichotomie](#7-git-bisect--audit-par-dichotomie)
8. [git shortlog — Résumé des contributions](#8-git-shortlog--résumé-des-contributions)
9. [git stash — Journalisation des travaux en cours](#9-git-stash--journalisation-des-travaux-en-cours)
10. [Hooks Git — Audit automatisé](#10-hooks-git--audit-automatisé)
11. [Bonnes pratiques d'audit avec Git](#11-bonnes-pratiques-daudit-avec-git)
12. [Tableau récapitulatif des commandes](#12-tableau-récapitulatif-des-commandes)

---

## 1. Concepts fondamentaux

### Le commit comme unité d'audit

Chaque commit Git est une **unité d'audit immuable** contenant :

| Métadonnée      | Description                              |
|-----------------|------------------------------------------|
| `SHA-1 / SHA-256` | Empreinte cryptographique unique        |
| `author`        | Nom + email de l'auteur + horodatage     |
| `committer`     | Nom + email du commiteur + horodatage    |
| `parent`        | Référence(s) au(x) commit(s) précédent(s)|
| `message`       | Description libre de la modification     |
| `tree`          | Snapshot de l'arbre de fichiers          |

> ⚠️ Le SHA est calculé sur le contenu **et** les métadonnées : toute falsification casse la chaîne de hachage.

### Niveaux de journalisation Git

```
Projet
 └── Dépôt (.git/)
      ├── COMMIT_EDITMSG     ← dernier message de commit
      ├── logs/
      │    ├── HEAD          ← journal de toutes les actions sur HEAD
      │    └── refs/         ← journal par branche/tag
      └── objects/           ← stockage immuable des objets
```

---

## 2. `git log` — Explorer l'historique

### Syntaxe de base

```bash
git log
```

### Options essentielles

```bash
# Affichage compact sur une ligne
git log --oneline

# Visualisation graphique des branches
git log --oneline --graph --all --decorate

# Limiter le nombre de commits affichés
git log -n 10

# Filtrer par auteur
git log --author="Alice"

# Filtrer par période
git log --since="2024-01-01" --until="2024-12-31"

# Filtrer par mot-clé dans le message
git log --grep="fix" --grep="hotfix" --all-match

# Recherche dans le contenu des modifications (pickaxe)
git log -S "nomDeFonction"        # commits où cette chaîne apparaît/disparaît
git log -G "regex.*pattern"       # commits où le diff matche une regex

# Afficher les fichiers modifiés à chaque commit
git log --stat

# Afficher le diff complet de chaque commit
git log -p

# Format personnalisé
git log --pretty=format:"%h | %ad | %an | %s" --date=short
```

### `git log` sur un fichier en particulier

Passer `-- <fichier>` à la fin de la commande restreint l'historique **uniquement aux commits ayant touché ce fichier**.

```bash
# Historique simple d'un fichier
git log -- chemin/vers/fichier.js

# Compact sur une ligne
git log --oneline -- chemin/vers/fichier.js

# Suivre le fichier même après un renommage
git log --follow -- chemin/vers/fichier.js
git log --follow --oneline -- chemin/vers/fichier.js

# Afficher le diff complet à chaque commit (qui a changé quoi dans le fichier)
git log -p -- chemin/vers/fichier.js

# Afficher le diff complet en suivant les renommages
git log -p --follow -- chemin/vers/fichier.js

# Résumé des lignes ajoutées/supprimées à chaque commit
git log --stat -- chemin/vers/fichier.js

# Filtrer par auteur sur un fichier précis
git log --author="Alice" -- chemin/vers/fichier.js

# Filtrer par période sur un fichier précis
git log --since="2024-01-01" --until="2024-12-31" -- chemin/vers/fichier.js

# Rechercher un mot-clé dans les messages, sur un fichier précis
git log --grep="fix" -- chemin/vers/fichier.js

# Trouver quand une chaîne précise est apparue/disparue dans le fichier (pickaxe)
git log -S "nomDeFonction" -- chemin/vers/fichier.js

# Format personnalisé sur un fichier
git log --pretty=format:"%h | %ad | %an | %s" --date=short -- chemin/vers/fichier.js

# Voir le contenu du fichier à un commit précis (depuis le log)
git show abc1234:chemin/vers/fichier.js

# Comparer le fichier entre deux commits
git diff abc1234 def5678 -- chemin/vers/fichier.js
```

> 💡 **Astuce** : le double tiret `--` est une convention Unix pour séparer les options des chemins de fichiers. Il évite toute ambiguïté si un fichier porte le même nom qu'une branche.
>
> ```bash
> # Sans -- : Git ne sait pas si "main" est une branche ou un fichier
> git log main
>
> # Avec -- : Git traite explicitement "main" comme un chemin de fichier
> git log -- main
> ```

### Formats de `--pretty`

| Placeholder | Signification              |
|-------------|----------------------------|
| `%H`        | Hash complet               |
| `%h`        | Hash court                 |
| `%an`       | Nom de l'auteur            |
| `%ae`       | Email de l'auteur          |
| `%ad`       | Date de l'auteur           |
| `%cn`       | Nom du commiteur           |
| `%s`        | Sujet du message           |
| `%b`        | Corps du message           |
| `%D`        | Refs (branches, tags)      |

```bash
# Exemple d'un log style audit complet
git log --pretty=format:"[%h] %ad — %an <%ae>%n  %s%n" --date=iso --all
```

### Comparaison entre branches

```bash
# Commits dans main absents de develop
git log develop..main

# Commits dans l'un ou l'autre (différence symétrique)
git log develop...main

# Commits en avance par rapport à origin
git log origin/main..HEAD
```

---

## 3. `git blame` — Identifier l'auteur ligne par ligne

`git blame` est l'outil d'audit **par excellence** : il associe chaque ligne d'un fichier au commit qui l'a introduite.

```bash
# Blame d'un fichier complet
git blame fichier.js

# Blame avec hash complet
git blame -l fichier.js

# Blame d'un intervalle de lignes
git blame -L 10,50 fichier.js

# Blame d'un intervalle par fonction (nécessite .gitattributes)
git blame -L :nomDeFonction fichier.js

# Ignorer les changements d'espacement
git blame -w fichier.js

# Détecter les lignes copiées/déplacées depuis d'autres fichiers
git blame -C -C fichier.js

# Blame à une date ou un commit précis
git blame abc1234 -- fichier.js
git blame --date=short fichier.js
```

### Lire la sortie de `git blame`

```
^abc1234 (Alice   2024-03-15 14:22:01 +0100  10) function calculate() {
 def5678 (Bob     2024-06-01 09:11:44 +0100  11)   return a + b;
```

| Colonne      | Description                       |
|--------------|-----------------------------------|
| `^abc1234`   | Hash du commit (^ = commit initial)|
| `(Alice ...)`| Auteur + date + heure + fuseau    |
| `10`         | Numéro de ligne                   |
| Reste        | Contenu de la ligne               |

---

## 4. `git diff` — Comparer les états

```bash
# Différences non indexées (working tree vs index)
git diff

# Différences indexées (index vs dernier commit)
git diff --staged
git diff --cached   # synonyme

# Différences entre deux commits
git diff abc1234 def5678

# Différences entre deux branches
git diff main..feature/ma-branche

# Différences d'un fichier spécifique
git diff -- chemin/vers/fichier.js

# Résumé des fichiers modifiés seulement
git diff --stat main..feature

# Diff d'un commit précis (vs son parent)
git diff HEAD~1 HEAD

# Afficher uniquement les noms des fichiers modifiés
git diff --name-only main..feature

# Diff avec contexte réduit
git diff -U1 HEAD~1 HEAD
```

---

## 5. `git show` — Inspecter un commit

```bash
# Afficher un commit (métadonnées + diff)
git show abc1234

# Afficher uniquement le message
git show -s abc1234
git show -s --format="%an %ae %ad %s" abc1234

# Afficher un fichier à l'état d'un commit
git show abc1234:chemin/vers/fichier.js

# Afficher les fichiers modifiés d'un commit
git show --stat abc1234

# Afficher un tag annoté
git show v1.0.0
```

---

## 6. `git reflog` — Journal interne de Git

Le **reflog** est le journal de bord de Git lui-même : il enregistre **toutes les actions** qui déplacent `HEAD` (checkout, merge, rebase, reset, etc.), même celles qui ne créent pas de commit.

> 💡 C'est l'outil de **récupération ultime** : il permet de retrouver des commits « perdus » après un reset ou un rebase.

```bash
# Afficher le reflog de HEAD
git reflog

# Afficher le reflog d'une branche spécifique
git reflog show main

# Afficher avec dates absolues
git reflog --date=iso

# Afficher un nombre limité d'entrées
git reflog -n 20

# Récupérer un commit perdu (ex: après reset --hard)
git reflog                          # repérer le SHA voulu
git checkout -b branche-rescue SHA  # recréer une branche dessus

# Voir l'état d'une ref à un moment donné
git show HEAD@{2}                   # HEAD il y a 2 actions
git show main@{yesterday}
git show HEAD@{2024-06-01}
```

### Structure d'un reflog

```
abc1234 HEAD@{0}: commit: fix: correction du calcul de TVA
def5678 HEAD@{1}: checkout: moving from main to feature/tva
ghi9012 HEAD@{2}: merge feature/login: Fast-forward
```

> ⚠️ Le reflog est **local** à chaque dépôt clone. Il n'est pas partagé via `git push`.

---

## 7. `git bisect` — Audit par dichotomie

`git bisect` permet de **localiser automatiquement** le commit responsable d'une régression via une recherche binaire.

```bash
# 1. Démarrer la session bisect
git bisect start

# 2. Marquer le commit actuel comme "mauvais"
git bisect bad

# 3. Marquer un commit connu comme "bon"
git bisect good v1.2.0
# ou par SHA
git bisect good abc1234

# 4. Git checkout automatiquement un commit intermédiaire
# → Tester, puis indiquer le résultat :
git bisect good   # si le bug est absent
git bisect bad    # si le bug est présent

# 5. Répéter jusqu'à l'identification du commit fautif
# Git affiche : "abc1234 is the first bad commit"

# 6. Terminer et revenir à HEAD
git bisect reset

# Automatiser avec un script de test
git bisect start
git bisect bad HEAD
git bisect good v1.0.0
git bisect run npm test   # ou ./mon-script-de-test.sh
```

---

## 8. `git shortlog` — Résumé des contributions

```bash
# Résumé des commits par auteur
git shortlog

# Trié par nombre de commits (décroissant)
git shortlog -sn

# Inclure les commits de toutes les branches
git shortlog -sn --all

# Sur une période donnée
git shortlog -sn --since="2024-01-01"

# Résumé pour un fichier spécifique
git shortlog -sn -- chemin/vers/fichier.js
```

### Exemple de sortie

```
  42  Alice Martin
  28  Bob Dupont
  15  Claire Lefèvre
```

---

## 9. `git stash` — Journalisation des travaux en cours

```bash
# Mettre de côté les modifications en cours
git stash push -m "WIP: refactoring authentification"

# Lister les stashs
git stash list

# Afficher le contenu d'un stash
git stash show -p stash@{0}

# Appliquer et supprimer le dernier stash
git stash pop

# Appliquer sans supprimer
git stash apply stash@{1}

# Supprimer un stash
git stash drop stash@{0}

# Vider tous les stashs
git stash clear
```

---

## 10. Hooks Git — Audit automatisé

Les **hooks** sont des scripts déclenchés automatiquement à des moments clés du workflow Git. Ils permettent d'automatiser les vérifications d'audit.

### Emplacement

```
.git/hooks/
├── pre-commit          ← avant chaque commit
├── commit-msg          ← validation du message de commit
├── post-commit         ← après chaque commit
├── pre-push            ← avant chaque push
└── post-merge          ← après chaque merge
```

### Exemples pratiques

#### `pre-commit` — Vérifier la qualité du code

```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "🔍 Audit pré-commit : vérification du code..."
npm run lint || { echo "❌ Lint échoué. Commit annulé."; exit 1; }
echo "✅ Audit OK"
```

#### `commit-msg` — Imposer une convention de message

```bash
#!/bin/sh
# .git/hooks/commit-msg
# Impose le format : type(scope): message

MSG=$(cat "$1")
PATTERN="^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?: .{1,72}$"

if ! echo "$MSG" | grep -qE "$PATTERN"; then
  echo "❌ Message de commit invalide."
  echo "   Format attendu : type(scope): description"
  echo "   Exemple        : fix(auth): correction du token expiré"
  exit 1
fi
```

#### `post-commit` — Logger les commits dans un fichier d'audit

```bash
#!/bin/sh
# .git/hooks/post-commit

LOG_FILE="$HOME/git-audit.log"
REPO=$(basename "$(git rev-parse --show-toplevel)")
HASH=$(git rev-parse --short HEAD)
AUTHOR=$(git log -1 --format="%an <%ae>")
DATE=$(git log -1 --format="%ad" --date=iso)
MSG=$(git log -1 --format="%s")

echo "[$DATE] [$REPO] [$HASH] $AUTHOR — $MSG" >> "$LOG_FILE"
```

> 💡 Pour partager les hooks avec l'équipe, utilisez un dossier `.githooks/` versionné et configurez Git :
> ```bash
> git config core.hooksPath .githooks
> ```

---

## 11. Bonnes pratiques d'audit avec Git

### ✅ Messages de commit structurés (Conventional Commits)

```
type(scope): description courte

Corps détaillé (pourquoi, pas comment)

Refs: #123, #456
```

| Type       | Usage                                      |
|------------|--------------------------------------------|
| `feat`     | Nouvelle fonctionnalité                    |
| `fix`      | Correction de bug                          |
| `docs`     | Documentation uniquement                  |
| `refactor` | Refactoring sans changement fonctionnel    |
| `test`     | Ajout ou modification de tests            |
| `chore`    | Maintenance, dépendances, configuration   |
| `security` | Correctif de sécurité                     |

### ✅ Configurer l'identité de l'auteur

```bash
# Identité globale
git config --global user.name  "Prénom Nom"
git config --global user.email "email@domaine.com"

# Identité locale (par dépôt)
git config user.name  "Prénom Nom"
git config user.email "email@domaine.com"
```

### ✅ Signer les commits avec GPG

```bash
# Générer une clé GPG
gpg --full-generate-key

# Lister les clés
gpg --list-secret-keys --keyid-format=long

# Configurer Git pour signer
git config --global user.signingkey VOTRE_KEY_ID
git config --global commit.gpgsign true

# Commit signé
git commit -S -m "feat: ajout du module de paiement"

# Vérifier la signature
git verify-commit abc1234
git log --show-signature
```

### ✅ Protéger les branches sensibles

```bash
# Voir les branches protégées (GitHub CLI)
gh api repos/:owner/:repo/branches/main/protection

# Configurer via l'interface GitHub/GitLab :
# - Interdire les push directs sur main
# - Exiger des Pull Requests avec revue
# - Exiger des commits signés
# - Activer l'historique linéaire (no merge commits)
```

### ✅ Générer un rapport d'activité

```bash
# Rapport de la semaine écoulée
git log \
  --since="1 week ago" \
  --pretty=format:"%ad | %h | %an | %s" \
  --date=short \
  --all \
  | sort > rapport-audit-$(date +%Y%m%d).txt
```

---

## 12. Tableau récapitulatif des commandes

| Commande                         | Objectif d'audit                                    |
|----------------------------------|-----------------------------------------------------|
| `git log`                        | Explorer l'historique des commits                   |
| `git log --oneline --graph`      | Vue graphique de l'historique des branches          |
| `git log -S "texte"`             | Trouver quand un code a été introduit/supprimé      |
| `git log --follow -- fichier`    | Historique d'un fichier, même après renommage       |
| `git blame fichier`              | Identifier l'auteur de chaque ligne                 |
| `git blame -L 10,50 fichier`     | Blame sur un intervalle de lignes                   |
| `git diff`                       | Voir les modifications en cours                     |
| `git diff commit1 commit2`       | Comparer deux états du dépôt                        |
| `git show <sha>`                 | Inspecter un commit précis                          |
| `git show <sha>:fichier`         | Voir un fichier à un instant donné                  |
| `git reflog`                     | Journal de toutes les actions Git locales           |
| `git bisect`                     | Localiser le commit responsable d'une régression    |
| `git shortlog -sn`               | Résumé des contributions par auteur                 |
| `git stash list`                 | Lister les travaux mis de côté                      |
| `git verify-commit <sha>`        | Vérifier la signature GPG d'un commit               |
| `git log --show-signature`       | Afficher les signatures dans l'historique           |

---

> 📌 **Ressources complémentaires**
> - [Documentation officielle Git](https://git-scm.com/docs)
> - [Conventional Commits](https://www.conventionalcommits.org/fr/)
> - [Pro Git Book (fr)](https://git-scm.com/book/fr/v2)
