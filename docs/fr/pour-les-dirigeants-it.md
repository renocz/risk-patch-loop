# risk-patch-loop, pour les dirigeants IT

[English](../for-it-leaders.md) · **Français**

Une page courte pour quelqu'un qui dirige ou gère une infrastructure et veut savoir si ça mérite un coup d'œil. Cinq minutes, aucun code. Les détails sont dans [le README](../../README.fr.md), les questions des ingénieurs dans [la FAQ](faq.md), et les chiffres dans [results.md](../results.md) (en anglais).

## La version en 30 secondes

Un scanner de vulnérabilités donne une liste, et la liste est trop longue pour agir. Le scan d'une nuit sur mes 65 conteneurs a rendu 2 297 failles corrigeables. Personne ne lit ça.

risk-patch-loop est un petit outil que j'ai écrit pour transformer cette liste en quelques choses qui valent la peine d'être faites. Il classe les failles selon l'exposition réelle de chaque conteneur, vérifie qu'une image plus récente supprime vraiment la faille, et prépare des propositions. En appliquer une est une étape à part, qui touche un seul service, garde un instantané, et remet l'ancienne image si la vérification échoue. Rien n'est appliqué sans qu'une personne dise oui.

C'est une preuve de concept. Je l'ai construit et utilisé une semaine sur un seul hôte. Lisez les limites plus bas avant d'imaginer quelque chose de plus grand.

## Ce que ça change

- **Une liste plus courte, mieux ordonnée.** La sévérité seule met tout en haut. rpl ajoute trois choses que le scanner ignore : l'accessibilité du conteneur, si la faille est exploitée en ce moment (la liste CISA), et ce que fait le service.
- **Pas de mise à jour qui ne change rien.** Sur 12 images avec des failles à traiter, 5 auraient été « mises à jour » sans rien supprimer : aucune image corrigée n'avait été publiée. rpl dit « pas de correctif » au lieu de proposer un changement de version.
- **Un rayon d'action réduit.** Un service à la fois, un instantané avant, une vérification après, un chemin de retour. Sur mon hôte, les mises à jour qu'il a préparées ont coûté de 5 à 40 secondes d'indisponibilité chacune.
- **Une personne garde la main.** L'outil prépare, un humain valide. Ça permet aussi de le mettre facilement derrière une étape d'approbation si un agent IA fait le travail.

## Ce qu'il ne fait pas

- Il ne décide pas à votre place. Le score est un classement : sur 20 failles, il est d'accord avec mes verdicts 14 fois, et répondre « différer » à chaque fois l'aurait été 13 fois. J'ai choisi ses réglages après avoir vu ces verdicts, donc prenez-le comme un premier chiffre, pas comme un résultat.
- Il ne prouve pas qu'une application marche après une mise à jour. La vérification prouve que le conteneur est sain, qu'il fait tourner la nouvelle image, et qu'une route répond.
- Il ne restaure pas les données. Une migration de base lancée par la nouvelle version reste : c'est à ça que servent l'instantané et la sauvegarde.
- Il ne vérifie pas les signatures d'images. Il fait confiance au tag et au registre.
- Il ne couvre pas ce que je n'ai pas essayé : un hôte, Docker Compose, Traefik, Docker Hub et ghcr.io. Le reste est lu comme « inconnu », jamais comme une supposition.

## Quelle confiance lui accorder

| | |
|---|---|
| **Testé** | 203 tests automatiques contre un faux hôte Docker, lancés en CI sur deux versions de Python. Quelques comportements ont aussi été vérifiés à la main sur un vrai moteur Docker. |
| **Utilisé** | Une semaine sur un homelab : 65 conteneurs, un propriétaire. Cinq vraies mises à jour sont passées par lui et chacune a passé sa vérification. |
| **Le retour arrière** | Jamais nécessaire sur un vrai service. Je l'ai fait se déclencher trois fois exprès, sur un service jetable du vrai hôte (2 novembre 2026). L'ancienne image est revenue à chaque fois. C'est testé, pas prouvé. |
| **Trouvé en l'utilisant** | Trois vrais défauts la première semaine, puis onze autres en écrivant des tests et en relisant le code. Ils sont listés dans [results.md](../results.md), avec les tests qui les couvrent maintenant. |

J'ai écrit les chiffres tels qu'ils sont sortis, y compris ceux qui ne flattent pas l'outil.

## Ce qu'il faudrait pour l'utiliser en équipe

J'ai fixé trois conditions pour parler de 1.0. Aucune n'est remplie, et je voudrais les trois avant de le recommander à quelqu'un pour un vrai travail :

1. **Le retour arrière éprouvé en conditions réelles :** au moins 3 fois sur un vrai hôte, chacune journalisée et vérifiée.
2. **Un deuxième hôte :** 4 semaines sur un hôte indépendant (un autre propriétaire, ou un autre reverse proxy que Traefik) avec 20 conteneurs ou plus.
3. **Un taux d'oubli mesuré :** un échantillon de 100 failles étiquetées, jugées par deux personnes qui ne voient pas le score, pour compter combien de cas « à traiter » il classe trop bas. Mon objectif est 10 % au plus.

Si votre installation est un homelab Traefik et que vous êtes curieux, vous pouvez l'essayer dès aujourd'hui en lecture seule : les premières étapes ne changent rien. Si c'est un environnement de production, attendez ces conditions, ou aidez-moi à les remplir.

## Questions probables

**C'est un produit ?**
Non. C'est l'outil d'un ingénieur, en Python, sans dépendance. Pas de support, pas de promesse de feuille de route, pas de service derrière.

**Envoie-t-il mes données quelque part ?**
Pas que je sache, et le code est assez court pour le vérifier. Il télécharge la base du scanner et la liste CISA, et cherche les versions sur les registres. Pas de télémétrie, pas de service d'IA.

**A-t-il besoin d'un agent IA ?**
Non. Il marche en ligne de commande. Je laisse bien un agent IA piloter mon infrastructure, et pour ça je garde l'étape « appliquer » derrière une approbation que l'agent ne peut pas se donner (voir [agent-ops-guardrails](https://github.com/renocz/agent-ops-guardrails)). rpl marche sans.

**Pourquoi un responsable s'y intéresserait ?**
Parce que la réponse facile à une longue liste de vulnérabilités, c'est de l'ignorer ou de tout mettre à jour d'un coup, et les deux finissent mal et coûtent plus cher après. Une façon classée, vérifiée et réversible de le faire, c'est la pièce qui me manquait.

---

*Ce sont les notes de terrain d'un ingénieur sur un projet, pas un argumentaire de vente. Les chiffres derrière chaque affirmation sont dans [results.md](../results.md).*
