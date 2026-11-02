# FAQ

[English](../faq.md) · **Français**

Les chiffres détaillés sont dans [results.md](../results.md) (en anglais).

- [Général](#général)
- [Le score et le scan](#le-score-et-le-scan)
- [La mise à jour et le retour arrière](#la-mise-à-jour-et-le-retour-arrière)
- [L'utiliser](#lutiliser)
- [Avec un agent IA](#avec-un-agent-ia)
- [Confiance et limites](#confiance-et-limites)

## Général

### C'est quoi, en une phrase ?
Un scanner me dit ce qui est vulnérable. rpl me dit lesquelles de ces failles comptent sur mon hôte, si une image plus récente les supprime vraiment, puis met à jour un service à la fois, avec un retour arrière si la vérification échoue, une fois que j'ai dit oui.

### Pourquoi je l'ai fait ?
Un scan de mes 65 conteneurs, une nuit, a rendu 2 297 lignes HIGH ou CRITICAL corrigeables. Je ne peux pas lire ça. Et « corrigeable » voulait dire « un tag existe », pas « une image plus récente supprime vraiment la faille ». Je voulais une courte liste sur laquelle agir, et des mises à jour qui ne me laissent pas un service cassé à minuit.

### Pour qui ?
Pour quelqu'un qui fait tourner Docker Compose derrière Traefik, chez lui ou dans une petite équipe, qui accepte de lire environ 1 300 lignes de Python, et qui veut rester celui qui décide. Il n'a qu'un utilisateur pour l'instant, moi, sur un seul hôte. Si vous avez déjà une équipe avec un processus de correctifs et une plateforme de vulnérabilités, ce n'est pas ce qu'il vous faut.

### En quoi c'est différent de Trivy seul ?
Trivy trouve les vulnérabilités, et rpl l'utilise pour ça. Ce que Trivy ne sait pas, c'est à quel point un conteneur est exposé sur mon hôte, si la faille est exploitée en ce moment, ou si l'image suivante la corrige vraiment. rpl ajoute ces trois choses et classe le résultat. Il ne remplace pas le scanner.

### En quoi c'est différent de Renovate, Dependabot ou Watchtower ?
Eux répondent à « y a-t-il une version plus récente ? ». rpl répond à « est-ce que ça compte, est-ce que l'image plus récente corrige vraiment, et puis-je l'appliquer sans risque ? ».
- **Watchtower** tire l'image et redémarre dès qu'une nouvelle sort. Pas de classement, pas de vérification que la faille a disparu, personne dans la boucle.
- **Renovate et Dependabot** ouvrent des pull requests pour les nouvelles versions. Ils ne regardent ni ce qui tourne sur mon hôte, ni son exposition.

Je pourrais les utiliser avec rpl. Je ne le fais pas, parce que mes fichiers compose sont sur le serveur, pas dans un dépôt avec un robot.

### Pourquoi ne pas tout mettre à jour automatiquement ?
Parce qu'une mise à jour qui passe le contrôle de santé peut quand même casser quelque chose, et je veux être celui qui l'accepte. rpl prépare des propositions chaque nuit et ne touche à aucun service en marche. Les appliquer est une commande à part, pour un service.

## Le score et le scan

### Sur quoi repose le score ?
Quatre choses :
- la sévérité de la faille ;
- sa présence dans la liste CISA KEV (exploitée dans la nature) ;
- l'accès du conteneur à la socket Docker et le rôle du service (un plan de contrôle, ou un service qui lit des données non fiables, pèsent plus) ;
- l'accessibilité du conteneur : sur Internet sans connexion, derrière une connexion, sur un port du réseau local, en localhost seulement, ou interne.

L'exposition vient des étiquettes Traefik et des ports publiés. Rien n'est deviné : sans la liste des noms d'hôtes publiés sur Internet, l'exposition Internet reste « inconnue ».

### Puis-je faire confiance au score ?
Comme classement, un peu. Comme verdict, non. Sur 20 vraies failles, il est d'accord avec mes verdicts 14 fois (répondre « différer » à chaque fois est d'accord 13 fois). Il trouve 5 de mes 7 cas « à traiter », avec 4 fausses alertes. Et j'ai choisi les rôles après avoir vu ces verdicts : ce tableau est un rejeu, pas une validation. Les chiffres et leurs limites sont dans [results.md](../results.md). Il n'y a pas encore de taux de faux négatifs mesuré, et c'est l'une des trois conditions de la 1.0.

### Que veut dire « un correctif est prouvé » ?
Pour chaque version candidate, rpl scanne l'image depuis le registre, sans la tirer dans Docker, et vérifie que les failles « à traiter » ont disparu. Sur 12 images avec des lignes « à traiter », 7 avaient une candidate qui les supprime toutes, 2 une candidate qui n'en supprime aucune, et 3 n'avaient aucune version plus récente. Changer le tag à l'aveugle n'aurait rien changé pour 5 des 12.

### Et si le mainteneur n'a pas publié d'image corrigée ?
Alors la réponse est « pas de correctif », et rpl le dit. La faille reste sur la liste. Un changement de tag qui ne change rien est pire que pas de proposition.

### Quels registres sont gérés ?
Docker Hub et ghcr.io. Pour tout autre registre, la réponse est INCONNU, jamais une supposition.

### Puis-je accepter une faille que j'ai examinée ?
Oui, dans `accepted.json` : `{"image|CVE-...": "raison"}`. Le texte ne sert que pour moi : l'outil compare la clé et ignore la valeur, donc j'écris une vraie raison, pour pouvoir la relire dans six mois.

## La mise à jour et le retour arrière

### Que fait `rpl patch` ?
Pour un service : il demande un instantané (vous donnez la commande), sauvegarde la base de données s'il y en a une, épingle la nouvelle image dans le fichier compose, fait un essai à blanc qui doit montrer exactement une recréation (celle du service lui-même), recrée, puis vérifie que le conteneur est sain, qu'il fait tourner la nouvelle image et qu'une route répond avec le statut attendu. Si quelque chose échoue, il restaure le fichier compose et remet l'ancienne image.

### Qu'est-ce qui peut le faire refuser de démarrer ?
- pas de commande d'instantané (sauf si je passe `--no-snapshot`), ou un instantané ou une sauvegarde en échec ;
- un service que le fichier compose ne définit pas, ou qui a `build:` à la place de `image:` ;
- un service sans conteneur actif, car on n'aurait aucune preuve de ce qu'était l'ancienne image ;
- un essai à blanc qui montre autre chose qu'une recréation de ce service ;
- un conteneur VPN (reconnu au nom « gluetun »), ou un service qui partage son réseau ;
- une proposition enregistrée de plus de 36 heures, ou dont le fichier a été modifié après son calcul.

### Le retour arrière a-t-il déjà sauvé un vrai service ?
Non. Chaque vraie mise à jour a passé sa vérification. J'ai fait jouer le retour arrière trois fois exprès, le 2 novembre 2026, sur un service jetable de mon vrai hôte Docker : une nouvelle image qui ne sert rien, une qui ne devient jamais saine, et un `docker compose up` qui échoue parce que le nouveau conteneur ne démarre pas. À chaque fois l'ancienne image est revenue avec le même identifiant, la route répondait de nouveau, le fichier compose était restauré et le journal disait `rollback ok`. C'est testé, pas prouvé. Je n'ai pas testé un vrai conflit de port, une vraie application, ni un retour arrière avec des données.

### Le retour arrière restaure-t-il mes données ?
Non, seulement l'image. Si la nouvelle version a lancé une migration de base de données, le retour arrière ne la défait pas. C'est à ça que servent l'instantané et la sauvegarde.

### Que veut dire le code de sortie 4 ?
`rollback FAILED: CHECK BY HAND`. L'outil n'a pas pu prouver que l'image d'origine tourne de nouveau, ou la mise à jour a été interrompue au mauvais moment. Regardez le service vous-même avant de faire autre chose. Le code 2 est un retour arrière vérifié. Je préfère un 4 bien bruyant à un « ok » discret que je ne peux pas justifier.

### Et si la vérification passe mais que l'application est cassée ?
Alors rpl ne le voit pas. La vérification prouve que le conteneur est sain, qu'il fait tourner la nouvelle image, et qu'une route répond. Elle ne prouve pas que l'application fonctionne. C'est pour ça que les propositions se font un service à la fois, avec un instantané, et que je regarde le service après.

## L'utiliser

### Qu'est-ce qu'il faut ?
Python 3.9 ou plus récent, rien à installer avec pip. Docker avec le plugin Compose. Trivy tourne dans un conteneur. Traefik devant les services. Les fichiers à écrire à la main sont dans [examples/](../../examples).

### A-t-il besoin d'une IA ?
Non. C'est du Python simple, avec la bibliothèque standard. Il n'y a aucun appel à un modèle nulle part.

### Qu'est-ce qui quitte ma machine ?
Trois sortes de requêtes, d'après le code (`grep -rn "https://" rpl/` les montre) :
- Trivy télécharge sa base de vulnérabilités ;
- la liste CISA KEV est téléchargée sur cisa.gov ;
- les versions candidates sont cherchées sur Docker Hub et ghcr.io, avec les demandes de jeton anonyme habituelles.

Rien sur mes conteneurs n'est envoyé ailleurs, et il n'y a pas de télémétrie. Vérifiez vous-même, c'est court.

### Combien de temps dure un scan, et combien ça coûte ?
Ça ne coûte que du disque et quelques minutes de processeur. Je lance les cinq premières étapes chaque nuit, depuis cron ou un timer systemd, et elles ne font que lire.

### Ça marche avec Podman, Kubernetes, Caddy, nginx ?
Non. Docker Compose et Traefik seulement. Un autre reverse proxy, ou des routes définies dans un fichier, sont lus comme « non routé », ce qui rend le score trop bas. Je n'ai pas essayé le reste.

### Ça marche sur Windows ou macOS ?
Je le fais tourner sous Linux. La CI tourne sous Linux avec Python 3.9 et 3.12. Je n'ai rien essayé d'autre.

## Avec un agent IA

### Est-il fait pour un agent IA ?
Il marche sans. Mais je laisse bien un agent IA gérer mon homelab, et c'est de là qu'est venue la question « qui dit oui à la mise à jour ». Les étapes en lecture seule se confient sans risque à un agent. `--apply` est celle qui change quelque chose.

### L'agent peut-il appliquer les mises à jour tout seul ?
Il le peut si on le laisse, et je ne le ferais pas. Gardez `--apply` derrière une approbation que l'agent ne peut pas se donner lui-même. [agent-ops-guardrails](https://github.com/renocz/agent-ops-guardrails) est ma tentative pour cette étape d'approbation, et rpl marche très bien sans. `proposals --apply` ne prend que les paramètres de la proposition enregistrée, rien de libre, ce qui le rend plus facile à encadrer.

## Confiance et limites

### Que manque-t-il avant de parler de 1.0 ?
Trois choses, chacune avec sa preuve dans `results.md` : au moins 3 retours arrière automatiques sur un vrai hôte ; 4 semaines sur un deuxième hôte indépendant avec 20 conteneurs ou plus ; et un taux de faux négatifs mesuré sur 100 failles étiquetées sur lesquelles je n'ai pas réglé l'outil. Aucune des trois n'est faite.

### Les images tirées sont-elles vérifiées ?
Non. L'outil fait confiance au tag et au registre. Il n'y a pas de vérification de signature, et pour un tag mobile seul l'empreinte que le registre annonce à ce moment-là est épinglée. Un registre ou un mainteneur compromis est hors de ce qu'il peut voir.

### Et si je trouve un bug ou un problème de sécurité ?
Pour un bug, ouvrez une issue. Pour une vulnérabilité, suivez [SECURITY.md](../../SECURITY.md). J'aimerais savoir ce qui casse chez vous, surtout si ce n'est pas un homelab Traefik.

### Où sont les chiffres derrière tout ça ?
[results.md](../results.md) : ce qui a été mesuré, ce qui ne l'a pas été, et les défauts que l'outil avait quand je l'ai utilisé sur un vrai hôte. [design.md](../design.md) explique pourquoi il marche comme ça.
