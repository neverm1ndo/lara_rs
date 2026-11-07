# Architecture Decision Records

В этом каталоге хранятся принятые архитектурные решения Lara.

Статусы документов:

- `Proposed` — решение обсуждается;
- `Accepted` — решение принято и должно учитываться в новой разработке;
- `Superseded` — решение заменено более новым ADR;
- `Deprecated` — решение больше не рекомендуется, но ещё может встречаться в коде.

Принятые решения не переписываются задним числом при существенном изменении
архитектуры. Вместо этого создаётся новый ADR со ссылкой на заменяемый документ.

## Индекс

- [ADR-0001: Control plane для нескольких игровых инстансов](0001-server-instance-control-plane.md)
- [ADR-0002: Release B — управление lifecycle и единый CLI](0002-release-b-lifecycle-and-cli.md)
- [ADR-0003: Release C — multi-instance configuration](0003-release-c-multi-instance-configuration.md)
- [ADR-0004: Release E — инциденты и восстановление наблюдения](0004-release-e-incidents-and-recovery.md) (`Proposed`)
- [ADR-0005: проект UDS-контракта готовности primary](0005-primary-uds-readiness-contract.md) (`Proposed`)
