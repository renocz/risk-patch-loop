# risk-patch-loop

[English](README.md) · **Français**

**Quelles vulnérabilités de conteneurs comptent vraiment sur *votre* hôte, existe-t-il un correctif qui les supprime réellement, et peut-on l'appliquer sans risque, avec un humain qui dit oui ?**

Sur le homelab de l'auteur, un scan de nuit a renvoyé 2 297 constats HIGH/CRITICAL corrigeables. Ce n'est pas une liste de tâches. Cet outil en fait une, grâce à trois choses qu'un scanner ignore : l'exposition réelle de chaque conteneur, la preuve qu'une version plus récente supprime bien le constat, et ce qu'est une mise à jour sûre d'un seul service.

```
scan ──► inventaire ──► score de risque ──► vérif. du correctif ──► propositions ──► vous dites oui ──► patch + retour arrière automatique
```

- **Score selon l'exposition.** Gravité, « exploité dans la nature » (CISA KEV), accès au socket Docker et rôle du service, le tout pondéré par l'accessibilité du conteneur : Internet sans authentification, derrière une authentification, port du réseau local, localhost seul, interne.
- **Un correctif est prouvé avant d'être proposé.** La version candidate est scannée *depuis le registre* (rien n'est téléchargé). Si le mainteneur n'a pas publié d'image reconstruite, la réponse est « pas de correctif », pas un changement de tag qui ne change rien.
- **Un service à la fois.** Instantané, sauvegarde de base de données, image épinglée, essai à blanc, recréation, contrôle de santé et d'une route, retour arrière automatique si le contrôle échoue. Un conteneur VPN et les services derrière lui sont refusés.
- **Rien ne se passe sans un humain.** L'outil prépare des propositions ; en appliquer une est une commande séparée et explicite.

## État : v0.9, un hôte, des chiffres honnêtes

Construit et utilisé pendant une semaine sur un hôte Docker (65 conteneurs, Traefik, un propriétaire). **Lisez [docs/results.md](docs/results.md) avant de lui faire confiance** (en anglais) : le score est d'accord avec les verdicts de son propriétaire 14 fois sur 20 (une réponse triviale « toujours différer » en obtient 13), les rôles ont été réglés après avoir vu ces verdicts, et le retour arrière automatique n'a jamais été déclenché en production. Il gère Docker Compose + Traefik, Docker Hub et ghcr.io. C'est une preuve de concept pour qui accepte de lire 1 000 lignes de Python, pas un produit.

## Limites connues

Reprises de [docs/results.md](docs/results.md) (en anglais) ; aucune n'est cachée, aucune n'est encore corrigée.

- **Un seul hôte.** Tout a été mesuré sur un homelab (65 conteneurs, un propriétaire, une semaine). Aucun deuxième hôte ne l'a fait tourner.
- **Traefik seulement.** L'exposition vient des labels Traefik. Un autre reverse proxy, ou des routes définies dans un fichier, seront lus comme « non routé ».
- **Docker Hub et ghcr.io seulement.** Tout autre registre donne « UNKNOWN », jamais une supposition.
- **Le retour arrière automatique n'a jamais été déclenché en production.** Toutes les vraies mises à jour ont passé leur contrôle. Le retour arrière est couvert par des tests déterministes contre un *faux* hôte Docker (fichier compose restauré, ancienne image recréée, résultat journalisé), pas par une vraie panne sur un vrai hôte. À considérer comme non prouvé tant qu'il n'a pas été exercé.
- **Les tests n'exécutent ni vrai Docker, ni Compose, ni Trivy, ni registre réel.** Ils prouvent l'enchaînement et les refus ; ils ne peuvent pas prouver que la vraie sortie de Compose ressemble à ce que l'analyseur attend.
- **Le score est un classement, pas un verdict.** Il est d'accord avec son propriétaire 14 fois sur 20 (la réponse triviale « toujours différer » : 13), sur vingt cas, avec des rôles choisis après avoir vu les verdicts. Aucun taux de faux négatifs n'a été mesuré.
- **Une mise à jour en bonne santé mais cassée passe.** Le contrôle prouve que le conteneur est sain et qu'une route répond, pas que l'application fonctionne.
- **Le retour arrière rétablit l'image, pas les données.** Une base migrée par la nouvelle version a besoin de la sauvegarde ou de l'instantané.
- **Les conteneurs VPN sont reconnus par leur nom** (« gluetun »), pas par ce qu'ils font.

## Feuille de route vers la 1.0

La 1.0 sort quand les trois conditions sont remplies, chacune avec ses preuves dans `docs/results.md`. Les chiffres sont des cibles proposées, discutables dans une issue.

1. **Retour arrière exercé en conditions réelles.** Au moins 3 retours arrière automatiques sur un vrai hôte, couvrant un conteneur qui ne devient jamais sain, une route qui répond un statut inattendu, et un `docker compose up` qui échoue ; chacun journalisé `rollback ok`, avec l'ancienne image en service et sa route qui répond ensuite. Journaux publiés.
2. **Un deuxième hôte.** Au moins 4 semaines consécutives sur un second hôte indépendant (autre propriétaire, ou reverse proxy autre que Traefik) avec 20 conteneurs ou plus, présentées dans le même format que les chiffres du premier hôte.
3. **Un taux de faux négatifs mesuré.** Un échantillon étiqueté d'au moins 100 constats, avec les verdicts d'au moins 2 relecteurs, tiré après gel des rôles et des seuils (pas les 20 cas ayant servi au réglage). Publier combien de verdicts « agir » le score classe sous ACT, avec un intervalle de confiance. Cible : au plus 10 % des verdicts « agir » manqués. Si la cible n'est pas atteinte, le score change et la mesure est refaite avant la 1.0.

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
- L'essai à blanc doit montrer que seul le service à mettre à jour serait recréé.
- Un conteneur VPN, ou un service qui partage son réseau, est refusé.
- `rpl proposals --apply` prend les paramètres de la proposition enregistrée, rien de libre, et refuse une proposition vieille de plus de 36 heures, ou dont le fichier a été modifié après son calcul (contrôle SHA-256 : intégrité, pas authentification).
- `rpl patch` valide les noms de service, de base et d'image avant de lancer quoi que ce soit, et refuse un service que le fichier Compose ne définit pas. Un `docker compose up` ou un essai à blanc en échec compte comme une mise à jour échouée, pas comme un succès.

## Avec un agent IA

Si un agent pilote votre infrastructure, donnez-lui les étapes en lecture seule et gardez `--apply` derrière une approbation qu'il ne peut pas s'accorder lui-même. [agent-ops-guardrails](https://github.com/renocz/agent-ops-guardrails) est la tentative de l'auteur pour cette étape d'approbation ; ce projet fonctionne sans lui.

## Documentation

- [SECURITY.md](SECURITY.md) : signaler une faille, ce que l'outil fait et ne fait pas (en anglais)
- [CONTRIBUTING.md](CONTRIBUTING.md) : lancer les tests et les règles (bibliothèque standard seule, chiffres réels et limites écrites) (en anglais)
- [docs/design.md](docs/design.md) : la boucle, les décisions, les limites (en anglais)
- [docs/results.md](docs/results.md) : ce qui a été mesuré, ce qui ne l'a pas été, les défauts trouvés à l'usage (en anglais)

## Licence

MIT. Utilisez-le, copiez-le, dites-moi ce qui casse.
