# ADR — Plan de contrôle Gluetun

**Statut** : accepté (phase 0)
**Date** : 2026-11-12
**Feature** : `016-gluetun-control-plane`
**Baseline** : `passteque/gluetun@8d925146ab36fdc538bcb35b3427518fd478e273`
(2026-11-11), fork `jul-ienfr/gluetun`, branche `016-control-plane`.

## Contexte

Le fork est identique à l'upstream. L'orchestrateur Python choisit les
candidats, les scores et applique les quotas ; le fork doit exécuter une cible,
prouver l'egress, basculer le DNS et le transport, et exposer un état fiable.
Toute la logique de score, de lease et de quota reste dans `registry.db`.

## Décisions

| ID | Décision |
|---|---|
| D1 | Le fork exécute une liste ordonnée de candidats et ne re-score jamais. |
| D2 | Un seul tunnel actif par conteneur ; le standby inter-stations est la feature 015. |
| D3 | Machine à états avec un seul job actif ; `409 active_job` sinon. |
| D4 | État persisté sans secret en clair ; secrets uniquement via `CONTROL_SECRET_KEY`. |
| D5 | Le DNS ladder bascule par requête, au-dessus du listener, sans redémarrer. |
| D6 | Consensus sur la valeur d'IP observée, pas sur la géolocalisation. |
| D7 | L'IP d'hôte est capturée au démarrage et refusée comme IP de sortie. |
| D8 | `exhausted` reste local et structuré ; aucune conclusion globale. |
| D9 | Idempotence par `Idempotency-Key` et bus d'événements avec `seq` monotone. |
| D10 | Scopes `reader`/`controller`/`admin`, secrets masqués sauf `reveal=true` admin. |
| D11 | Compatibilité additive : les routes et réponses upstream restent inchangées. |
| D12 | Migration strangler `legacy` → `shadow` → `active`, station par station. |
| D13 | Le ladder de transports `wireguard,openvpn-udp,openvpn-tcp` vit dans le fork, un seul tunnel, breaker et retour au premier transport. |

## Activation

| Variable | Défaut | Effet |
|---|---|---|
| `CONTROL_PLANE_ENABLED` | `true` | Monte les routes de contrôle. |
| `CONTROL_STATE_DIR` | `/gluetun/control` | Répertoire d'état persistant. |
| `CONTROL_STATE_MODE` | `state` | `state`, `env` ou `merge`. |
| `CONTROL_EGRESS_ENABLED` | `true` | Active la vérification d'egress. |
| `CONTROL_EGRESS_SOURCES` | `http:ipify,dns:whoami,publicip:internal` | Sources ordonnées. |
| `CONTROL_EGRESS_QUORUM` | `2` | k du k-of-n. |
| `CONTROL_EGRESS_MIN_SOURCES` | `3` | n minimal. |
| `DNS_LADDER` | `dot,plain` | Étages DNS ordonnés. |
| `DNS_FAIL_CLOSED` | `true` | Interdit les resolvers de l'hôte. |
| `DNS_REDUNDANCY_REQUIRED` | `false` | Refuse un ladder à un seul étage. |

`CONTROL_PLANE_ENABLED=false` restaure strictement le comportement upstream :
aucune route de contrôle n'est montée et les nouveaux réglages sont inertes.

## Conséquences

- Les modules 016 sont isolés dans `internal/control`, `internal/egress` et
  `internal/dns/ladder` pour faciliter les rebases trimestriels.
- Toute extension est créée dans le fork ; aucun commit local antérieur n'est à
  préserver.
- Les tests de contrat upstream doivent passer avant et après chaque rebase.
- En phase 0, les routes autres que `capabilities` répondent `501
  not_implemented` et `features` n'annonce que l'implémenté.

## Rebase

1. `git fetch upstream master`.
2. `git diff --exit-code upstream/master -- .` sur une branche propre.
3. Rebaser `016-control-plane` sur `upstream/master`.
4. Rejouer `go test ./internal/...` et les tests de contrat.
5. Mettre à jour le commit de baseline dans cet ADR.
