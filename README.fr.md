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
- **Un service à la fois.** Instantané, sauvegarde de base de données, image épinglée, essai à blanc, recréation, contrôle de santé et d'une route, retour arrière automatique si le contrôle échoue. Un conteneur VPN et les services derrière lui sont refusés.
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

Testé : 225 tests automatiques contre un faux hôte Docker (enchaînement et refus), lancés en CI sur Python 3.9 et 3.12 ; quelques comportements ont aussi été vérifiés à la main sur un vrai Docker (voir les limites ci-dessous).

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
- **Les groupes de mise à jour sont un refus, pas une protection.** Un conteneur qui partage le réseau d'un autre (`network_mode: service:X` ou `container:X`), et celui dont il partage le réseau, forment un groupe (`rpl/groups.py`). `rpl patch` et `rpl proposals` refusent tous ses membres, quel que soit leur nom ; le nom « gluetun » reste refusé par précaution. Patcher un groupe entier, parent d'abord, n'existe pas encore.
- **Une mise à jour en bonne santé mais cassée passe.** Le contrôle prouve que le conteneur est sain, qu'il exécute la nouvelle image et qu'une route répond ; il ne prouve pas que l'application fonctionne.
- **Le retour arrière rétablit l'image, pas les données.** Une migration de base exécutée par la nouvelle version n'est pas annulée ; seules la sauvegarde ou l'instantané le peuvent.
- **Les images tirées ne sont pas vérifiées.** L'outil fait confiance au tag et au registre : pas de vérification de signature (cosign ou équivalent), et pour un tag mobile seul le digest que le registre indique à ce moment est épinglé. Un registre ou un mainteneur compromis échappe à ce qu'il peut détecter.
- **La détection des groupes lit le mode réseau, pas ce que fait le conteneur.** Un conteneur qui joint les mêmes pairs autrement (port publié, sidecar sans `network_mode`) n'est pas un groupe. La clé de configuration `groups` (politique `auto`/`ask`/`never`, raison, `confirmed`) est lue par `rpl.groups` mais pas encore appliquée par une mise à jour de groupe ; tant qu'elle n'existe pas, tous les membres sont refusés quelle que soit la politique.

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
- Un service qui partage le réseau d'un autre conteneur, ou dont le réseau est partagé (un groupe de mise à jour, par exemple un conteneur VPN et ce qui tourne derrière), est refusé.
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
