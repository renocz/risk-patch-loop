# risk-patch-loop

[![tests](https://github.com/renocz/risk-patch-loop/actions/workflows/tests.yml/badge.svg)](https://github.com/renocz/risk-patch-loop/actions/workflows/tests.yml)

[English](README.md) · **Français**

**Quelles vulnérabilités de conteneurs comptent vraiment sur *votre* hôte, existe-t-il un correctif qui les supprime réellement, et peut-on l'appliquer sans risque, avec un humain qui dit oui ?**

En une minute :
- Un scanner vous donne une liste. Sur le homelab de l'auteur, un scan de nuit a renvoyé 2 297 constats HIGH/CRITICAL corrigeables. Ce n'est pas une liste de tâches.
- rpl les classe selon l'exposition réelle de chaque conteneur, vérifie qu'une image plus récente supprime bien le constat (scannée depuis le registre, rien n'est téléchargé) et prépare des propositions.
- En appliquer une est une commande séparée qui ne touche qu'**un service à la fois** : instantané, sauvegarde de base de données, image épinglée, essai à blanc, recréation, contrôle de santé et d'une route, et un retour arrière automatique vérifié si le contrôle échoue.
- Rien ne se passe sans un humain : l'outil prépare, vous décidez.

C'est une preuve de concept construite et utilisée pendant une semaine sur un hôte Docker, dont les limites sont [écrites, pas cachées](#limites-connues). Elle s'adresse à qui accepte de lire 1 000 lignes de Python, pas à un produit.

## La boucle en une image

Chaque nuit, en lecture seule : rpl lit quatre choses qu'un scanner seul ne combine pas. Après votre oui, un service est mis à jour, et si le contrôle échoue l'ancienne image revient.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/loop-dark.png">
  <img alt="Schéma : Trivy, Traefik, CISA KEV et les registres alimentent rpl, qui écrit des propositions ; après le oui de l'humain, Docker Compose met à jour un service, et un retour arrière automatique rétablit l'ancienne image si le contrôle échoue." src="docs/loop.png">
</picture>

```
scan ──► inventaire ──► score de risque ──► vérif. du correctif ──► propositions ──► vous dites oui ──► patch + retour arrière automatique
```

- **Score selon l'exposition.** Gravité, « exploité dans la nature » (CISA KEV), accès au socket Docker et rôle du service, le tout pondéré par l'accessibilité du conteneur : Internet sans authentification, derrière une authentification, port du réseau local, localhost seul, interne.
- **Un correctif est prouvé avant d'être proposé.** La version candidate est scannée *depuis le registre* (rien n'est téléchargé). Si le mainteneur n'a pas publié d'image reconstruite, la réponse est « pas de correctif », pas un changement de tag qui ne change rien.
- **Un service à la fois.** Instantané, sauvegarde de base de données, image épinglée, essai à blanc, recréation, contrôle de santé et d'une route, retour arrière automatique si le contrôle échoue. Un conteneur VPN et les services derrière lui ne sont jamais mis à jour un par un : ils forment un groupe, mis à jour en bloc par `rpl group` (nouveau, testé sur des doubles et une fois sur un Docker de bac à sable, jamais sur un vrai VPN).
- **Rien ne se passe sans un humain.** L'outil prépare des propositions ; en appliquer une est une commande séparée et explicite.

## Par où commencer

- **J'ai Docker Compose derrière Traefik et je veux l'essayer :** le [démarrage rapide](#démarrage-rapide), puis les [fichiers à écrire à la main](#fichiers-à-écrire-à-la-main-voir-examples).
- **Je veux savoir à quoi me fier :** les [limites connues](#limites-connues), puis [docs/results.md](docs/results.md) (en anglais) : ce qui a été mesuré, ce qui ne l'a pas été, et les défauts de l'outil à sa première utilisation sur un vrai hôte.
- **Je dirige ou je gère une infra et je veux l'essentiel :** [docs/fr/pour-les-dirigeants-it.md](docs/fr/pour-les-dirigeants-it.md), cinq minutes, aucun code.
- **J'ai des questions (différence avec Trivy, Renovate, Watchtower, retour arrière, données) :** la [FAQ](docs/fr/faq.md).
- **Je veux voir comment il décide :** [docs/design.md](docs/design.md) (en anglais : la boucle, les décisions, les limites).
- **Un agent IA pilote mon infrastructure :** donnez-lui les étapes en lecture seule et gardez `--apply` derrière une approbation qu'il ne peut pas s'accorder lui-même, voir [Avec un agent IA](#avec-un-agent-ia).

## État : v0.9, un hôte, des chiffres honnêtes

Construit et utilisé pendant une semaine sur un hôte Docker (65 conteneurs, Traefik, un propriétaire). **Lisez [docs/results.md](docs/results.md) avant de lui faire confiance** (en anglais) : le score n'est **pas validé**. Il est d'accord avec les verdicts de son propriétaire 14 fois sur 20, mais une réponse triviale « toujours différer » en obtient 13 : cela ne montre encore aucune valeur ajoutée ; les rôles ont aussi été réglés après avoir vu ces verdicts. Le retour arrière automatique n'a jamais été déclenché sur un vrai service. Il gère Docker Compose + Traefik, Docker Hub et ghcr.io.

Testé : 471 tests automatiques contre un faux hôte Docker (enchaînement et refus), lancés en CI sur Python 3.9 et 3.12 ; quelques comportements ont aussi été vérifiés à la main sur un vrai Docker (voir les limites ci-dessous).

## Limites connues

Reprises de [docs/results.md](docs/results.md) (en anglais) ; aucune n'est cachée, aucune n'est encore corrigée.

- **Un seul hôte.** Tout a été mesuré sur un homelab (65 conteneurs, un propriétaire, une semaine). Aucun deuxième hôte ne l'a fait tourner.
- **Traefik seulement.** L'exposition vient des labels Traefik. Un autre reverse proxy, ou des routes définies dans un fichier, seront lus comme « non routé ».
- **Docker Hub et ghcr.io seulement.** Tout autre registre donne « UNKNOWN », jamais une supposition.
- **Le retour arrière automatique ne s'est jamais déclenché tout seul sur une vraie panne.** Il a été exercé volontairement, avec des pannes provoquées : trois fois sur un service jetable (2 novembre 2026), puis trois fois sur un vrai service d'un vrai hôte Docker (14 novembre 2026, une petite page web sans données) : une route qui répond un statut inattendu alors que le conteneur est sain, un conteneur qui ne devient jamais sain, et un `docker compose up` dont le nouveau conteneur ne peut pas démarrer. À chaque fois l'ancienne image est revenue (même identifiant), la route a de nouveau répondu, le fichier compose a été restauré et le journal indiquait `rollback ok`. Cela ne prouve ni une application avec base de données, ni un vrai conflit de port, ni une panne que personne n'a provoquée. À considérer comme testé, pas comme prouvé.
- **Les tests automatiques n'exécutent ni vrai Docker, ni Compose, ni Trivy, ni registre réel.** Ils prouvent l'enchaînement et les refus contre un faux hôte. Quelques comportements ont été vérifiés à la main, une fois, sur Docker 29.9.2 et Compose v5.6.1 (voir [docs/results.md](docs/results.md)) ; les autres versions ne sont pas couvertes et la CI ne répète pas ces vérifications.
- **Le score n'est pas validé.** C'est un classement, pas un verdict. Il est d'accord avec son propriétaire 14 fois sur 20 (la réponse triviale « toujours différer » : 13), sur vingt cas, avec des rôles choisis après avoir vu les verdicts : cela ne montre pas qu'il apporte de la valeur. Ni taux de faux négatifs ni précision n'ont été mesurés.
- **Le socket Docker, c'est root.** `rpl patch` pilote `docker` et `docker compose` ; qui peut le lancer peut devenir root sur cet hôte. Ne le lancez qu'avec un compte à qui vous confieriez root, gardez `--apply` derrière une approbation que l'appelant ne peut pas s'accorder, et ne l'exposez pas à une entrée non fiable.
- **Les migrations de données ne sont pas couvertes.** Un retour arrière d'image n'annule pas ce qu'une nouvelle version a fait à sa base ; la sauvegarde et l'instantané sont le seul retour possible, et `rpl` ne teste pas une restauration. Vérifiez que vous savez restaurer avant de vous y fier.
- **Groupes de mise à jour : un par un ils sont refusés ; en bloc, `rpl group` est nouveau et non éprouvé.** Un conteneur qui partage le réseau d'un autre (`network_mode: service:X` ou `container:X`), et celui dont il partage le réseau, forment un groupe (`rpl/groups.py`). `rpl patch` et `rpl proposals` refusent tous ses membres, quel que soit leur nom (le nom « gluetun » reste refusé par précaution) ; ils regardent le fichier compose et Docker lui-même (tous les conteneurs, arrêtés compris), et refusent quand Docker ne peut pas répondre. `rpl group` met à jour le groupe entier, parent d'abord, chaque dépendant recréé après lui, avec une sauvegarde des répertoires de configuration et un retour arrière. **Il n'a jamais tourné sur un vrai groupe VPN ni sur une vraie application** : 65 tests contre un modèle de Docker, des essais sur un Docker de bac à sable, et un essai surveillé sur l'hôte de l'auteur, sur un groupe de test jetable de conteneurs `alpine` et `busybox` (22 novembre 2026 : une application complète, et deux applications tuées par SIGTERM puis ramenées en arrière par `--resume` ; `docs/results.md`). Considérez-le comme non testé chez vous tant que vous n'avez pas lancé `--plan` puis une première application sous vos yeux.
- **Un groupe non exposé n'est presque jamais mis à jour, par conception.** `rpl group` n'agit que sur une correction prouvée d'une faille que le score classe ACT (45 ou plus), et le score est pondéré par l'exposition : un conteneur sans port publié ni route est « internal » (facteur 0,2) et ne peut pas dépasser 22, quelle que soit la faille ; sur un port LAN (0,55), une faille CRITICAL corrigeable seule vaut 22. Un conteneur VPN joignable seulement depuis le LAN restera donc intact la plupart du temps, et ce silence est le classement qui fait son travail, pas une panne. Le groupe de test a dû déclarer une exposition Internet pour être éligible.
- **Une mise à jour en bonne santé mais cassée passe.** Le contrôle prouve que le conteneur est sain, qu'il exécute la nouvelle image et qu'une route répond ; il ne prouve pas que l'application fonctionne.
- **Le retour arrière rétablit l'image, pas les données.** Une migration de base exécutée par la nouvelle version n'est pas annulée ; seules la sauvegarde ou l'instantané le peuvent.
- **Les images tirées ne sont pas vérifiées.** L'outil fait confiance au tag et au registre : pas de vérification de signature (cosign ou équivalent), et pour un tag mobile seul le digest que le registre indique à ce moment est épinglé. Un registre ou un mainteneur compromis échappe à ce qu'il peut détecter.
- **L'interrupteur de pause et le verrou partagé sont un cran de sûreté, pas un contrôle d'accès.** `rpl pause on` arrête tout `rpl patch` et tout `rpl proposals --apply` lancés ensuite (code de sortie 5), et un fichier de verrou empêche deux exécutions d'appliquer en même temps. Les deux sont dans le répertoire d'état : deux exécutants dont le `state_dir` diffère ne se voient pas, et quiconque peut écrire dans ce répertoire peut les retirer. Une exécution déjà commencée n'est pas interrompue par l'interrupteur. Une seconde exécution n'attend pas, elle est refusée. Le verrou est un `flock` : Unix seulement (sans lui rien n'est appliqué), testé sous Linux sur un système de fichiers local, pas sur NFS ni macOS, et jamais avec deux vraies mises à jour concurrentes sur un vrai hôte Docker. Les commandes en lecture seule et `--dry` ignorent les deux.
- **Ce que `rpl group` ne couvre pas.** La détection des groupes lit le mode réseau, pas ce que fait le conteneur : un conteneur qui joint les mêmes pairs autrement (port publié, sidecar sans `network_mode`) n'est pas un groupe. Un groupe doit tenir dans UN seul fichier compose : si Docker connaît un dépendant que le fichier ne nomme pas, l'application est refusée. Seuls les montages situés sous le répertoire du fichier compose sont sauvegardés et restaurés ; les volumes nommés, les montages situés ailleurs et les bases de données d'autres conteneurs ne le sont pas. La copie est prise membres arrêtés (`quiesce: stop`, valeur par défaut d'un membre qui monte un répertoire de configuration), et c'est la seule garantie de cohérence : aucun outil SQLite ou LevelDB n'est lancé. Un membre dont la restauration échoue est laissé arrêté, bruyamment (code de sortie 4). Une application qui modifie des données hors de son répertoire de configuration n'est pas ramenée en arrière. Les sauvegardes contiennent des secrets : elles sont réservées au propriétaire (mode 0700), gardées 7 jours par défaut, supprimées par `rpl group --purge`, et rien ne les supprime à votre place. La purge ne supprime jamais la sauvegarde d'une application inachevée ou dont le retour arrière a échoué : celle-là vous attend. La preuve de correction n'est liée à un digest que pour l'application de groupe : `rpl patch` et `rpl proposals` épinglent encore un tag versionné sans digest.
- **Les notifications sont nouvelles et non éprouvées sur un vrai hôte.** `rpl watch` ne lit que `group-journal.json` et signale une entrée sans résultat après un délai de grâce (60 minutes par défaut, `group_unfinished_grace_minutes`) : une application interrompue est annoncée après ce délai, une application qui dure vraiment plus longtemps donne une fausse alerte, et il signale l'enregistrement, pas l'état réel des services. C'est le seul avertissement pour un processus arrêté par SIGTERM : il doit donc tourner depuis un timer à lui ; si ce timer est mort, rien ne vous prévient. `rpl notify` lit les fichiers d'état, pas Docker : les événements « exécution de nuit absente ou échouée » ne fonctionnent que si le job de nuit se termine par `rpl notify --record ok|failed` (un job qui l'oublie ressemble à une exécution absente) ; la première exécution enregistre les conteneurs présents comme référence sans les annoncer ; les résultats de patch de plus de 72 heures ne sont pas rejoués ; les constats acceptés à la main ne sont pas signalés comme exclusions ; une remise signifie que le service a répondu 2xx, pas que quelqu'un a lu ; deux exécutions au même instant partagent `notifs.json` sans verrou et peuvent toutes deux envoyer. Testé avec des doublures, puis une fois le 23 novembre 2026 sur l'hôte de l'auteur avec un récepteur sur l'interface locale, deux applications tuées par SIGTERM et un timer système lancé en root (`docs/results.md`) : jamais contre un vrai Telegram ou un webhook distant, jamais sous un compte non root, jamais pendant des jours. Cet essai a aussi montré que le message « annulé » de l'application de groupe n'est envoyé qu'une fois par plan, puis plus jamais (pas encore corrigé).

## Feuille de route vers la 1.0

La 1.0 sort quand deux choses sont vraies, chacune avec ses preuves dans `docs/results.md`. Les chiffres sont les cibles de l'auteur, discutables dans une issue. La 1.0 ne veut pas dire « validé partout » : elle n'aura tourné que sur un hôte, le socket Docker reste équivalent à root et le score garde les limites listées plus haut.

1. **Retour arrière exercé sur un vrai service.** Fait le 14 novembre 2026 : trois retours arrière automatiques (une route qui répond un statut inattendu, un conteneur qui ne devient jamais sain, un `docker compose up` qui échoue) sur un vrai service, avec des pannes provoquées volontairement, chacun journalisé `rollback ok` avec l'image d'origine revenue. Une restauration depuis un snapshot ne compte pas. Journaux et limites dans `docs/results.md`.
2. **Un taux de faux négatifs mesuré, publié tel qu'il sort.** Un échantillon étiqueté de constats (100 si l'hôte en a autant), tiré au hasard avec une graine publiée après gel des rôles et des seuils (pas les 20 cas ayant servi au réglage), étiqueté à l'aveugle sur les critères écrits de [docs/labelling-criteria.md](docs/labelling-criteria.md) par l'auteur et par un panel de modèles de langage d'au moins 3 familles (la majorité du panel compte pour UN relecteur, un modèle hors du panel départage). Publier combien de verdicts « agir » le score classe sous ACT avec un intervalle de confiance, la précision à côté de la réponse triviale « toujours différer », et la matrice de confusion, quel que soit le résultat. Cible : au plus 10 % de verdicts « agir » manqués ; si elle n'est pas atteinte, le score change et la mesure est refaite. C'est publié comme « 1 humain + 1 panel de modèles, un hôte » : plus faible que deux humains sur plusieurs hôtes, et écrit comme tel. Avec peu de verdicts « agir », l'intervalle est large, et le texte le dit.

Après la 1.0 (1.1 et suivantes) : 4 semaines sur un deuxième hôte indépendant tenu par quelqu'un d'autre, un second relecteur humain, et un reverse proxy autre que Traefik. Les testeurs sont attendus avec l'annonce de la 1.0.

## Démarrage rapide

Python 3.9 ou plus, aucune dépendance. Docker avec le plugin Compose ; Trivy tourne en conteneur.

```bash
git clone https://github.com/renocz/risk-patch-loop && cd risk-patch-loop
cp examples/rpl.json rpl.json            # à adapter : state_dir, snapshot_command, fichiers ci-dessous
cp examples/roles.json examples/patch-apps.json .   # décrivez VOS services
export RPL_CONFIG=$PWD/rpl.json

python -m rpl scan         # Trivy sur les images en cours + CISA KEV  -> findings.json
python -m rpl inventory    # exposition de chaque conteneur            -> inventory.json
python -m rpl risk         # score et ACT / PLAN / WATCH
python -m rpl fixcheck     # quelles versions candidates corrigent vraiment les lignes ACT (lecture seule)
python -m rpl proposals    # mises à jour prêtes à approuver
python -m rpl proposals --list
python -m rpl proposals --apply myapp --dry      # puis sans --dry
```

`rpl patch` est la dernière étape seule (`rpl patch --help`). Lancez les cinq premières chaque nuit (cron ou timer systemd).

Deux commandes tournent depuis des timers à elles, pas depuis le job de nuit (limites dans « Limites connues ») :

```bash
python -m rpl watch                      # toutes les quelques minutes : une application de groupe qui n'a jamais enregistré de résultat (code 1 ; 2 si le journal est illisible)
python -m rpl notify                     # toutes les heures : collecte les événements et les remet (canaux de rpl/notify.py dans rpl.json)
python -m rpl notify --record ok         # la DERNIÈRE ligne du job de nuit (ou : --record failed --reason "...")
```

`python -m rpl pause on --reason "..."` empêche toute application jusqu'à `python -m rpl pause off` (`pause status` sort avec le code 1 pendant la pause) ; `touch <state_dir>/PAUSED` fait la même chose sans Python.

Un groupe (par exemple un conteneur VPN et les services derrière lui) se déclare dans `rpl.json` sous le nom de **conteneur** du parent, puis se planifie et s'applique :

```json
"groups": {"proj-vpn-1": {"policy": "ask", "reason": "VPN : le recréer coupe tous les services derrière lui", "confirmed": true,
                          "controls": ["members_healthy", "exit_differs", "no_leak"],
                          "services": {"indexer": {"quiesce": "none"}}}}
```

```bash
python -m rpl group --compose /srv/proj/compose.yaml --parent vpn --plan       # ne change rien ; affiche le plan et son empreinte
python -m rpl group --compose /srv/proj/compose.yaml --parent vpn --approve <empreinte>
python -m rpl group --compose /srv/proj/compose.yaml --parent vpn --resume     # après une interruption : retour arrière
python -m rpl group --purge                                                    # supprime les sauvegardes de groupe de plus de 7 jours
```

| Politique | Qui lance l'application | Ce qu'il faut |
|---|---|---|
| `auto` | l'exécution nocturne, sans humain | `confirmed: true` |
| `ask` (à choisir par défaut) | un humain, en ligne de commande | `confirmed: true`, une raison, et `--approve <empreinte>` |
| `never` | personne | une raison ; toujours refusé |

## Fichiers à écrire à la main (voir `examples/`)

| Fichier | Rôle |
|---|---|
| `rpl.json` | chemins, commande d'instantané, mots des middlewares Traefik qui signifient « authentification requise » |
| `patch-apps.json` | les services que l'outil a le droit de *proposer*, chacun avec une route de santé et une base à sauvegarder |
| `roles.json` | services du plan de contrôle et services qui traitent des entrées non fiables (ils pèsent plus) |
| `tunnel-hosts.json` | noms d'hôtes publiés sur Internet (tunnel ou pare-feu) ; sans lui, l'exposition Internet est « inconnue », jamais devinée |
| `accepted.json` | constats examinés et acceptés : `{"image|CVE-...": "raison"}` |

## Règles de sécurité, écrites dans le code

- Un scan qui n'a pas pu faire son travail (base périmée, liste KEV indisponible, image non analysée) n'est pas « OK », et les constats ne sont pas réécrits.
- `rpl patch` refuse de démarrer sans commande d'instantané, sauf `--no-snapshot` ; un instantané ou une sauvegarde de base en échec arrête tout avant tout changement.
- L'essai à blanc doit montrer exactement une recréation, celle du conteneur du service ; tout autre cas (aucune, deux, un autre service, sortie illisible) arrête tout et restaure le fichier compose.
- Un service qui partage le réseau d'un autre conteneur, ou dont le réseau est partagé (un groupe de mise à jour, par exemple un conteneur VPN et ce qui tourne derrière), est refusé par `rpl patch`, qui interroge le fichier compose et Docker (tous les conteneurs, arrêtés compris, sous le verrou partagé) ; quand Docker ne peut pas répondre, il refuse.
- `rpl group` n'applique un groupe que si un membre a une correction de sécurité prouvée en attente, et seulement selon sa politique : `auto` (l'exécution nocturne, sans humain), `ask` (par défaut : un humain donne `--approve <empreinte du plan>`), `never`. `auto` et `ask` exigent aussi `"confirmed": true` ; `ask` et `never` exigent une raison. La politique la plus restrictive entre celle du groupe et celles de ses services l'emporte. L'empreinte couvre chaque membre, l'image qu'il exécute et la nouvelle référence épinglée par digest ; ce digest doit être celui que la vérification de correction a analysé et celui que le registre sert maintenant, sinon la réponse est UNKNOWN et rien n'est appliqué. Le plan est recalculé sous le verrou : une approbation donnée avant qu'un tag ait bougé est refusée.
- Un groupe qui ne pourrait pas être restauré (lien symbolique sortant d'un répertoire de configuration, fichier spécial, fichiers d'un autre propriétaire, plus de `group_backup_max_mb`) est refusé avant tout changement. Une entrée de journal est écrite avant tout arrêt ; après une interruption, toute application de groupe est refusée tant que `rpl group ... --resume` n'a pas fait le retour arrière.
- Avant de lancer la moindre commande, `rpl patch` vérifie l'interrupteur de pause, prend le verrou partagé, puis revérifie l'interrupteur sous le verrou ; il garde le verrou jusqu'à la fin, retour arrière compris. En pause, ou verrou tenu par une autre exécution : code de sortie 5, rien n'est touché. Un interrupteur illisible compte comme une pause ; un verrou impossible à prendre signifie que rien n'est appliqué (`rpl/gate.py`).
- `rpl proposals --apply` prend les paramètres de la proposition enregistrée, rien de libre, et refuse une proposition vieille de plus de 36 heures, ou dont le fichier a été modifié après son calcul (contrôle SHA-256 : intégrité, pas authentification).
- `rpl patch` valide les noms de service, de base et d'image avant de lancer quoi que ce soit, et refuse un service que le fichier Compose ne définit pas. Un `docker compose up` ou un essai à blanc en échec compte comme une mise à jour échouée, pas comme un succès. L'épinglage est lié au service demandé : l'image que Compose résout pour lui doit être égale à `--old`, et la ligne modifiée doit se trouver dans son bloc. `--route` et `--codes` sont validés.
- Après une mise à jour, le conteneur doit exécuter la nouvelle image ; après un retour arrière, il doit exécuter la référence d'origine avec le même identifiant d'image, sinon le résultat est `rollback FAILED: CHECK BY HAND` (code de sortie 4 ; 2 signifie un retour arrière vérifié).

## Avec un agent IA

Si un agent pilote votre infrastructure, donnez-lui les étapes en lecture seule et gardez `--apply` derrière une approbation qu'il ne peut pas s'accorder lui-même. [agent-ops-guardrails](https://github.com/renocz/agent-ops-guardrails) est la tentative de l'auteur pour cette étape d'approbation ; ce projet fonctionne sans lui.

## Documentation

- [SECURITY.md](SECURITY.md) : signaler une faille, ce que l'outil fait et ne fait pas (en anglais)
- [CONTRIBUTING.md](CONTRIBUTING.md) : lancer les tests et les règles (bibliothèque standard seule, chiffres réels et limites écrites) (en anglais)
- [docs/fr/faq.md](docs/fr/faq.md) : les questions probables, avec des réponses chiffrées
- [docs/fr/pour-les-dirigeants-it.md](docs/fr/pour-les-dirigeants-it.md) : l'essentiel pour un responsable, en cinq minutes
- [docs/design.md](docs/design.md) : la boucle, les décisions, les limites (en anglais)
- [docs/results.md](docs/results.md) : ce qui a été mesuré, ce qui ne l'a pas été, les défauts trouvés à l'usage (en anglais)

## Licence

MIT. Utilisez-le, copiez-le, dites-moi ce qui casse.
