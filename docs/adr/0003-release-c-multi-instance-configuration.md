# ADR-0003: Release C — multi-instance configuration

- Статус: `Accepted`
- Дата: 2026-11-05
- Владельцы: backend, frontend и infrastructure teams
- Связанный этап: Release C
- Развивает: [ADR-0001](0001-server-instance-control-plane.md) и
  [ADR-0002](0002-release-b-lifecycle-and-cli.md)

## Контекст

Release B прошёл smoke-тест на Linux-хосте: auxiliary-инстанс зарегистрирован,
его systemd unit наблюдается и управляется через Lara, а runtime state доступен
через HTTP. Это подтверждает границы registry, CLI, systemd D-Bus и
Developer-only lifecycle.

Некоторым auxiliary-инстансам кроме lifecycle необходима capability
`Configuration`: Developer должен просматривать файловое дерево, редактировать
текстовые конфигурации и безопасно обновлять заранее разрешённые файлы игрового
мода. Backup snapshots auxiliary-инстансам не требуются.

Существующий bounded context `configuration` исторически привязан к primary
storage root и маршрутам `/configuration/...`. Его presentation и файловые
правила уже отделены от HTTP, но production composition разрешает только одну
цель. Простое переключение глобального root по выбранному во frontend инстансу
неприемлемо: оно создаёт shared mutable state, риск межинстансной записи и
невозможность надёжно применить разные encoding, limits, ignored paths и backup
policy.

Release C должен сделать configuration действительно instance-aware, не
нарушая bounded-context границы и не превращая capability manifest в механизм
авторизации.

## Решение

### Граница Release C

Release C является вертикальным релизом файлового управления несколькими
инстансами. В него входят:

- канонический instance-scoped configuration API;
- разрешение configuration target через application port;
- повторная backend-авторизация capability и роли на каждый запрос;
- отдельная filesystem capability для каждого storage root;
- текстовое чтение и редактирование с encoding policy;
- безопасная загрузка бинарных артефактов только по allowlist;
- optimistic concurrency для изменяющих операций;
- аудит configuration mutations и долговечная realtime-доставка;
- отсутствие backup snapshots у auxiliary;
- сохранение backup policy primary;
- CLI, `doctor`, OpenAPI и Linux smoke-test для нового контура.

В Release C не входят:

- автоматические инциденты и journald replay;
- UDS handshake/readiness и lifecycle primary;
- backups или maps для auxiliary;
- произвольная загрузка executable, native plugins и environment files;
- удалённый agent и управление другими физическими хостами;
- RCON и игровые административные команды;
- автоматический restart после изменения файлов.

Инциденты, journald recovery и primary readiness образуют следующий отдельный
вертикальный релиз. Они не блокируют проверку безопасности файлового контура.

### Канонический HTTP-контракт

Канонические маршруты получают `instance_id` из path:

```text
GET    /server-instances/{instance_id}/configuration/tree
GET    /server-instances/{instance_id}/configuration/files?path=...
POST   /server-instances/{instance_id}/configuration/files?path=...
PUT    /server-instances/{instance_id}/configuration/files?path=...
DELETE /server-instances/{instance_id}/configuration/files?path=...
PATCH  /server-instances/{instance_id}/configuration/files/rename
HEAD   /server-instances/{instance_id}/configuration/artifacts?path=...
PUT    /server-instances/{instance_id}/configuration/artifacts?path=...
```

Точные DTO, заголовки, коды ошибок и поведение повторных запросов зафиксированы
в [контракте Release C](../api/release-c-configuration.md) и отдельной
[OpenAPI 3.1 спецификации](../api/release-c-configuration.openapi.json). Она
публикуется как контракт для разработки; runtime `/openapi.json` содержит
только уже смонтированные операции.

Если для минимально полезного файлового менеджера понадобятся директории,
добавляется отдельный ресурс `/directories`: создание, переименование и
удаление только пустой директории. Рекурсивное удаление в Release C не
поддерживается.

Исторические маршруты `/configuration/...` в Release C не монтируются и не
публикуются в OpenAPI. Клиент ещё не использует этот контракт, поэтому
переходный alias не нужен. Единственным публичным API является instance-scoped
пространство `/server-instances/{instance_id}/configuration/...`; обращение к
старому пути возвращает обычный `404`.

Binary artifact upload отделён от текстового `files` API. Текстовый endpoint
проверяет configured encoding и не транскодирует байты. Artifact endpoint
принимает opaque bytes, доступен только Developer и только для точного пути,
присутствующего в allowlist данного инстанса.
`HEAD /artifacts` возвращает размер и `ETag` существующего allowlisted файла,
чтобы клиент получил precondition для обновления без скачивания бинарных байтов.

### Порт разрешения configuration target

Application layer контекста `configuration` определяет порт
`ConfigurationTargetResolver`. Он не импортирует
`server_instances::infrastructure` и не знает TOML, systemd unit или внутреннюю
структуру registry.

Порт возвращает immutable request-scoped target:

```text
ConfigurationTarget
├── instance_id
├── storage capability
├── access scope
├── file policy
├── text encoding
├── upload/tree limits
├── artifact allowlist
└── mutation preservation policy
```

Bootstrap связывает resolver с доверенным `InstanceRegistry`, независимым
`ConfigurationTargetCatalog` и фабрикой filesystem capabilities. Каталог
принадлежит integration/composition layer: `server_instances` продолжает знать
только ID, storage root и наличие capability, но не импортирует file policy,
encoding или backup types из `configuration`. Клиент никогда не передаёт
storage root, systemd unit или абсолютный путь. Resolver отклоняет неизвестный
инстанс и инстанс без `Configuration` до файлового I/O.

Target не хранится в изменяемой глобальной переменной и не переключается между
запросами. Каждая операция получает собственный target, поэтому параллельные
запросы разных инстансов не могут изменить root друг друга.

### Авторизация

Backend применяет следующую матрицу независимо от manifest клиента:

| Пользователь | Primary | Auxiliary с `Configuration` |
| --- | --- | --- |
| Developer | Полная разрешённая file policy | Полная разрешённая file policy |
| Configurator | Только configurator subtree, text operations | Запрещено |
| Admin/Challenger | Запрещено | Запрещено |
| Mapper/Backuper | Только собственные primary features | Запрещено |

Developer определяется по `main_group` или явному permission. `Admin` не
наследует Developer-доступ. Наличие `lara.configuration.v1` в manifest лишь
строит UI; endpoint снова проверяет роль, capability инстанса и action.

Effective manifest объявляет только реально доступные действия, например
`browse`, `read_text`, `write_text` и `update_artifact`. Configurator никогда не
получает auxiliary instance или `update_artifact`.

### Файловая безопасность

Все операции используют `shared::file_storage`; собственный path resolver в
presentation или infrastructure не создаётся. Применяются следующие
инварианты:

- клиентские пути только относительные и нормализованные;
- canonical storage root создаётся один раз при bootstrap/target construction;
- symlink и reparse-point не пересекаются и не следуются;
- ignored subtree скрывается в tree и возвращает `404` при прямом обращении;
- лимиты глубины, числа entries, одного файла и upload body применяются до
  записи;
- запись выполняется во временный файл в том же filesystem, затем через
  atomic rename;
- executable bit и ownership не изменяются HTTP-запросом;
- `.env`, secrets, `omp-server`, native libraries и systemd files запрещены,
  если они не представлены отдельным явно разрешённым типом операции;
- artifact allowlist содержит точные относительные пути, а не glob от клиента;
- content hash вычисляется до публикации успешного события.

Allowlist артефактов конфигурируется на конкретном инстансе. Расширение файла
само по себе не является достаточным разрешением на запись. Обновление
исполняемого `omp-server` через HTTP в Release C запрещено.

### Конкурентность и целостность

Чтение файла возвращает `ETag`, построенный из `FileRevision`/content hash.
Overwrite, delete, rename и artifact update требуют `If-Match`. Несовпадение
возвращает `412 Precondition Failed`; занятое destination — `409 Conflict`.

Mutation coordinator повторно проверяет revision после подготовки side effects
и перед atomic replace. Это защищает от потери изменений между двумя вкладками,
ручного редактирования на хосте и одновременных запросов Lara.

Один HTTP-запрос изменяет один файл. Batch upload откладывается до отдельного
контракта с явно определённой атомарностью.

### Backup policy

Решение о snapshot принимает target policy, а не проверка `Primary` внутри
файлового сервиса:

- primary destructive text mutation использует `BackupRequirement::Required`;
- auxiliary использует `BackupRequirement::Disabled`;
- create не требует snapshot;
- rename primary использует явно зафиксированную policy и не маскирует ошибку
  обязательного preservation;
- artifact update auxiliary создаёт audit event и content hashes, но не backup.

Путь, записанный в backup/audit, всегда относится к полному storage root
инстанса. Request-scoped configurator path не должен приводить к двойному
префиксу или восстановлению в другой каталог.

### Долговечность mutation, аудит и realtime

Filesystem и MongoDB не образуют общую транзакцию. Поэтому Release C не
пытается обещать атомарность двух разных хранилищ. До файлового side effect Lara
создаёт долговечную `ConfigurationMutation` с idempotency key, expected
revision и hash желаемого содержимого:

```text
Requested -> Applying -> Succeeded | Failed | ReconciliationRequired
```

Повтор запроса с тем же ключом и fingerprint возвращает исходную mutation, а
другой payload с тем же ключом получает `409`. После рестарта reconciliation
сравнивает source/destination, expected revision и фактические hashes:

- уже применённый desired hash завершает mutation как `Succeeded` без повторной
  записи;
- неизменившаяся expected revision позволяет безопасно продолжить операцию;
- неоднозначное внешнее изменение переводит запись в
  `ReconciliationRequired` и не перезаписывается автоматически.

Для delete и rename сохраняется достаточно before/after evidence, чтобы
отличить уже завершённый side effect от стороннего изменения. HTTP сообщает
успех только после terminal `Succeeded`, но durable intent позволяет объяснить
и восстановить crash window между filesystem replace и MongoDB update.

Успешная mutation создаёт versioned `configuration.file-changed.v1` с:

- event ID/mutation ID;
- instance ID;
- actor user ID и session ID;
- видом операции;
- безопасными source/destination paths;
- previous/current revision и content hash;
- timestamp;
- признаком и receipt сохранённого primary backup, если он был нужен.

Событие и embedded outbox сохраняются в том же MongoDB-документе, что и
terminal transition mutation. Доставка имеет at-least-once семантику. HTTP
retry не повторяет уже зафиксированный или фактически применённый side effect.

Developer получает detailed events всех доступных инстансов. Configurator
получает только primary events внутри разрешённой проекции. Автор получает
state/event update, а подавление toast о собственном действии выполняется по
`actorUserId`, а не исключением socket connection.

### Конфигурация и CLI

Deployment configuration хранит декларативную configuration policy рядом с
описанием инстанса, но loader раскладывает её в отдельный
`ConfigurationTargetCatalog`, а не переносит в доменную модель registry. Пути
остаются server-side configuration. Предлагаемая форма:

```toml
[[game_server.instances]]
id = "test"
capabilities = ["overview", "lifecycle", "configuration", "incidents"]
storage_root = "/home/svr_sa_test"

[game_server.instances.configuration]
fallback_encoding = "windows-1251"
ignored_paths = ["logs", "scriptfiles/cache"]
artifact_paths = ["gamemodes/test.amx"]
max_file_size_bytes = 10485760
```

Общие безопасные defaults могут наследоваться, но effective policy полностью
валидируется при startup. Capability `Configuration` без policy или доступного
storage root является ошибкой конфигурации, а не молчаливым отключением.

CLI расширяется без неявных host mutations:

```text
lara instance add ... --capability configuration
lara instance edit <id> ...
lara instance verify <id>
lara doctor [--instance <id>]
```

Сложные списки policy редактируются в TOML или отдельными точными CLI options;
CLI не предлагает небезопасный универсальный `--allow-path '*'`. `doctor`
проверяет traversal/write access пользователя `lara`, ignored/artifact policy,
filesystem границы и отсутствие symlink, но не изменяет игровой файл.

## План реализации

### 1. Зафиксировать контракты и миграцию

- принять этот ADR после review backend/frontend/infrastructure;
- зафиксировать canonical routes, error codes, ETag/If-Match и event envelope;
- убрать legacy `/configuration/...` из production router и OpenAPI;
- добавить API contract tests до production wiring.

Результат: согласованный OpenAPI 3.1 контракт без изменений host state.

### 2. Расширить registry и startup validation

- добавить per-instance configuration policy;
- валидировать capability/policy, relative paths, limits, encoding и artifact
  allowlist;
- запретить пересечения ignored и writable artifact paths;
- сохранить чтение прежней primary configuration как compatibility input.

Результат: invalid policy останавливает startup с точной диагностикой.

### 3. Ввести application port разрешения target

- определить `ConfigurationTargetResolver` в application layer;
- реализовать adapter над registry и отдельным target catalog на composition
  boundary;
- создавать изолированный `LocalFileStorage` для каждого target;
- покрыть параллельное разрешение нескольких инстансов и попытки cross-root
  доступа тестами.

Результат: configuration не зависит от `server_instances::infrastructure`.

### 4. Перевести text service на instance-scoped use cases

- перенести tree/read/create/overwrite/delete/rename на target;
- сохранить primary backup behavior;
- отключить snapshots для auxiliary;
- добавить ETag/If-Match и atomic replace;
- придерживаться зафиксированного canonical route contract при миграции
  файлового сервиса.

Результат: один сервис безопасно работает с primary и несколькими auxiliary.

### 5. Реализовать artifact update

- отделить opaque artifact payload от text encoding pipeline;
- проверять Developer, exact allowlist path, размер и ожидаемую revision;
- записывать временный файл, считать hash и атомарно заменять destination;
- запретить executable/system/native/environment targets;
- определить поведение при запущенном сервере без автоматического restart.

Результат: мод обновляется без выдачи произвольного доступа к host filesystem.

### 6. Добавить canonical HTTP/OpenAPI и manifest actions

- смонтировать instance-scoped routes;
- повторно проверять role/capability/action в extractors/use cases;
- документировать DTO, headers и stable errors через `utoipa`;
- добавить effective actions в `lara.configuration.v1`;
- обновить frontend contract/navigation fixtures.

Результат: клиент выбирает инстанс из manifest и не строит пути самостоятельно.

### 7. Сделать mutation и audit долговечными

- реализовать `ConfigurationMutation`, MongoDB repository и indexes;
- сохранять intent до filesystem side effect и реализовать reconciliation
  crash window;
- подключить `ConfigurationEventPublisher` к durable outbox;
- добавить idempotency и восстановление недоставленных событий;
- реализовать role-aware Socket.IO projection;
- добавить HTTP audit/history query для Developer, если frontend требует
  recovery после reconnect уже в Release C.

Результат: успешное изменение нельзя потерять между HTTP и realtime.

### 8. Расширить CLI и диагностику

- научить `instance add/edit` безопасно формировать configuration policy;
- расширить `instance verify` и `doctor` read-only проверками;
- обновить config examples и deployment documentation;
- не выполнять chown, restart или создание игровых файлов неявно.

Результат: deployment остаётся воспроизводимым и диагностируемым.

### 9. Провести тестирование и пилот

- unit tests domain policy, resolver, authorization и revisions;
- HTTP/OpenAPI tests canonical routes и отсутствия legacy routes;
- filesystem integration tests symlink, traversal, races и atomic replace;
- MongoDB/outbox recovery tests;
- Linux package smoke-test без изменения production primary;
- пилот на одном auxiliary с `Configuration`, затем на втором инстансе для
  проверки изоляции;
- rollback test, подтверждающий сохранность игровых файлов и Release B
  lifecycle.

Результат: evidence для перевода ADR в `Accepted` и выпуска Release C.

## Оценка трудозатрат

Оценка для одного backend-инженера при готовом frontend-контракте:

| Блок | Инженерные дни |
| --- | ---: |
| Контракты, registry и миграция | 3–4 |
| Target resolver и filesystem isolation | 3–5 |
| Text CRUD, revisions и удаление legacy routes | 4–6 |
| Artifact update и security hardening | 4–6 |
| Audit, outbox и realtime | 4–6 |
| CLI, doctor и документация | 2–4 |
| Integration/package/smoke/rollback tests | 4–6 |
| **Итого** | **24–37** |

Frontend integration, UX файлового менеджера и внешнее security review в эту
оценку не входят. При параллельной работе backend и frontend календарный срок
может быть меньше, но filesystem security и Linux smoke-test не сокращаются.

## Критерии приёмки

Release C считается завершённым, когда:

- Developer видит configuration actions только у инстансов с capability;
- Configurator работает только с primary subtree;
- Admin, Challenger, Mapper и Backuper не получают auxiliary configuration;
- два параллельных запроса к разным инстансам физически остаются в своих roots;
- traversal, absolute path, symlink и ignored path не дают прочитать или
  изменить файл;
- stale `If-Match` не перезаписывает ручное или параллельное изменение;
- binary artifact можно обновить только по exact allowlist и только Developer;
- auxiliary mutation не создаёт backup snapshot;
- destructive primary mutation без успешного обязательного backup не
  выполняется;
- mutation и audit event содержат правильный instance ID и полный server path;
- рестарт Lara в любой точке mutation не теряет intent, не повторяет уже
  применённый side effect и явно отмечает неоднозначное внешнее изменение;
- canonical routes полностью представлены в общей OpenAPI 3.1 схеме;
- legacy `/configuration/...` отсутствует в router и OpenAPI;
- `lara doctor --instance <id>` обнаруживает недоступный root, неверные права и
  небезопасную policy;
- Debian smoke-test и пилот auxiliary проходят без регрессии lifecycle Release
  B;
- rollback Lara не удаляет и не рекурсивно изменяет игровые файлы.

## Последствия

Положительные:

- capability `Configuration` становится реальной per-instance возможностью;
- frontend получает единый контракт для выбора и управления инстансом;
- auxiliary не наследует стоимость и сложность backup snapshots;
- primary сохраняет действующую защиту изменений;
- filesystem boundaries проверяются централизованно и тестируемо;
- audit не зависит от Socket.IO-соединения.

Отрицательные и эксплуатационные затраты:

- registry и CLI получают более сложную per-instance policy;
- optimistic concurrency требует поддержки ETag клиентом;
- artifact update увеличивает security surface и требует Linux integration
  tests;
- durable audit добавляет MongoDB indexes, outbox и maintenance concerns.

## Рассмотренные альтернативы

### Один глобальный mutable storage root

Отклонено: параллельные запросы могут попасть в чужой root, а policy невозможно
надёжно связать с авторизованным инстансом.

### Передавать абсолютный путь из клиента

Отклонено: UI metadata не является доверенной, а allowlist инстансов должен
оставаться полностью server-side.

### Копировать configuration bounded context внутрь `server_instances`

Отклонено: lifecycle registry не должен владеть файловой моделью, encoding,
backup orchestration и редактором. Связь реализуется application port.

### Включить backups для каждого auxiliary

Отклонено требованиями и стоимостью хранения. Auxiliary получает audit и
content hashes; snapshots остаются capability primary.

### Разрешить любые бинарные файлы по расширению

Отклонено: расширение контролируется именем файла и не защищает executable,
plugin или secret paths. Требуется exact server-side allowlist.

### Автоматически перезапускать сервер после upload

Отклонено: file mutation и lifecycle operation имеют разные риски, аудит и
идемпотентность. Клиент может явно запросить restart после успешного update.

### Одновременно реализовать incidents, journald и UDS

Отклонено для Release C: это независимый reliability-контур с другими
источниками истины и критериями восстановления. Он оформляется следующим ADR.

## Последующие решения

Отдельного ADR требуют автоматические incidents, journald replay/checkpoints,
UDS handshake/readiness и согласованная миграция primary на systemd.
