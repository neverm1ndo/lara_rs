# ADR-0001: Control plane для нескольких игровых инстансов

- Статус: `Accepted`
- Дата: 2026-10-18
- Владельцы: backend и infrastructure teams
- Связанный этап: Release A

## Контекст

Lara исторически обслуживает один основной open.mp/SAMP-сервер. Прототип на
Express запускал `omp-server` как дочерний процесс Node.js, находил его через
`pidof`, перезапускал через сигналы и одновременно использовал Socket.IO для
команд, состояния и уведомлений.

Такая модель не обеспечивает надёжного управления несколькими одноимёнными
процессами и теряет сведения о жизненном цикле после перезапуска backend. В ней
также нельзя достоверно отличить плановую операцию от падения, определить
готовность приложения и восстановить произошедший ночью инцидент.

На одном хосте уже существует несколько игровых серверов с разными модами и
конфигурациями. Основной сервер использует полный набор Lara-функций. Остальным
нужно как минимум управление жизненным циклом, а некоторым — файловый менеджер,
редактор конфигурации и загрузка игрового мода. Исторические backup snapshots
для auxiliary-инстансов не требуются.

Клиент должен получать доступный текущему пользователю каталог инстансов и
строить навигацию из объявленных сервером возможностей. Состав инстансов и
возможностей не должен быть захардкожен во frontend.

## Решение

Lara становится control plane зарегистрированных игровых инстансов. Новый
bounded context `server_instances` владеет:

- реестром инстансов и их идентичностью;
- capability-моделью и пользовательским manifest;
- состоянием процесса и readiness;
- lifecycle-операциями;
- наблюдением за systemd;
- журналом и корреляцией инцидентов;
- политикой realtime-уведомлений об операциях и инцидентах.

Контексты `configuration`, `maps` и `backups` сохраняют собственные доменные
модели. Они получают сведения об инстансе через application-порты или другие
явные контракты и не обращаются к `server_instances::infrastructure`.

## Идентичность и классификация инстансов

Каждый инстанс имеет стабильный типизированный `ServerInstanceId`, отображаемое
имя, вид, окружение и набор capabilities.

Виды инстансов:

- `Primary` — основной игровой сервер;
- `Auxiliary` — дополнительный сервер разработки, тестирования или отдельного
  игрового режима.

В системе существует ровно один `Primary`. Вид инстанса не заменяет capability:
возможности объявляются явно.

Начальный набор capabilities:

- `Overview`;
- `Lifecycle`;
- `Configuration`;
- `Maps`;
- `Backups`;
- `Incidents`.

Приняты следующие инварианты:

- каждый управляемый инстанс имеет `Lifecycle`;
- primary имеет полный поддерживаемый набор возможностей;
- auxiliary может опционально иметь `Configuration`;
- auxiliary не имеет `Backups`;
- `Maps` на первом этапе доступна только primary;
- systemd unit и storage root не могут принадлежать двум инстансам;
- абсолютные пути и имена systemd units никогда не принимаются от клиента.

## Управление процессами

Lara не порождает `omp-server` напрямую и не хранит `Child`/PID как источник
истины. Каждый игровой сервер запускается отдельным systemd unit и работает как
foreground-процесс. Systemd владеет процессом, cgroup, сигналами, restart policy
и start limits.

Целевая топология:

```text
lara.service
└── lara-rs

lara-game@main.service
└── omp-server

lara-game@dev-dm.service
└── omp-server
```

Lara вызывает `StartUnit`, `StopUnit` и `RestartUnit` через systemd D-Bus.
Успешное принятие systemd job не считается готовностью игрового сервера.
Завершение операции определяется по наблюдаемому состоянию unit и настроенной
readiness-проверке.

Прямой запуск `systemctl` допустим только как временный адаптер миграции. Даже в
этом случае Lara порождает клиент `systemctl`, а не игровой процесс. Целевой
production-адаптер использует D-Bus.

Процесс Lara работает без root-прав. Приложение использует внутренний allowlist
units, а операционная система ограничивает сервисную учётную запись Lara только
разрешёнными игровыми units.

## Наблюдение и readiness

Systemd является источником истины о процессе. Read-only adapter использует
system bus напрямую через `zbus` и не вызывает `systemctl`. Наблюдатель
использует как минимум следующие свойства:

- `ActiveState` и `SubState`;
- `Result`;
- `MainPID`;
- `ExecMainCode` и `ExecMainStatus`;
- `NRestarts`;
- `InvocationID`.

UDS не используется как замена process supervision. Для primary он показывает
готовность игрового приложения и передаёт heartbeat. Handshake связывается с
конкретным systemd invocation через `InvocationID`. Потеря UDS сама по себе не
считается падением и коррелируется с состоянием unit.

Auxiliary без application-level probe первоначально считается готовым после
перехода unit в `active`. Позднее ему может быть назначен отдельный readiness
adapter без изменения доменной модели.

Read-only state API возвращает нормализованные process и readiness состояния
раздельно. До первого успешного snapshot наблюдателя состояние имеет значение
`not_observed` с `process: unknown` и не интерпретируется как `offline` или
инцидент. Developer-проекция также может содержать безопасные operational
evidence: main PID, restart counter, invocation ID и нормализованную причину
последнего завершения. Имена systemd units в HTTP-контракт не попадают.

В Release A наблюдение включается явным `systemd_observation = true` только для
одного auxiliary-инстанса. После подключения adapter делает initial snapshot,
подписывается на `PropertiesChanged` и каждые 30 секунд выполняет reconciliation.
При потере D-Bus сохраняется последнее evidence, но snapshot помечается как
`stale`; до первого успешного чтения состояние остаётся `not_observed`.

Journald используется для восстановления событий, произошедших во время
остановки Lara. Для production требуется persistent journal. Периодический
reconciliation страхует потерю live D-Bus-событий, но не является основным
механизмом наблюдения. Replay journald остаётся за границами Release A.

## Команды и realtime

HTTP является command/query transport:

```text
GET  /server-instances
GET  /server-instances/{instance_id}/state
POST /server-instances/{instance_id}/operations
GET  /server-instances/{instance_id}/operations
GET  /server-instances/{instance_id}/operations/{operation_id}
```

Изменяющая команда создаёт долговечную `LifecycleOperation` до обращения к
systemd. Для защиты от повторного restart клиент передаёт `Idempotency-Key`.
Если операция не может быть надёжно записана, Lara не выполняет ручное действие.

Socket.IO используется только для server-to-client realtime-доставки состояния
и уведомлений. Потеря Socket.IO-соединения не должна приводить к потере истории:
клиент восстанавливает события через HTTP cursor/sequence.

## Capability manifest

`GET /server-instances` возвращает не внутреннюю конфигурацию, а эффективный
manifest текущего пользователя. Он содержит:

- `schemaVersion` и `revision`;
- `defaultInstanceId`;
- доступные инстансы;
- versioned feature IDs;
- допустимые пользователю действия внутри feature;
- безопасные observability metadata.

Стабильные feature IDs имеют вид:

```text
lara.overview.v1
lara.lifecycle.v1
lara.configuration.v1
lara.maps.v1
lara.backups.v1
lara.incidents.v1
```

Неизвестные feature IDs игнорируются клиентом. Несовместимое изменение создаёт
новую major-версию capability. Экспериментальные возможности объявляются в
`unstableFeatures` и могут сопровождаться внутренними Lara Improvement
Proposals, но их наличие не ослабляет серверную авторизацию.

Manifest не раскрывает storage roots, пути UDS, systemd unit names и секреты.
Технические metadata описываются семантически, например `readiness: "uds"` или
`readiness: "process"`.

Manifest персонализируется как пересечение объявленных capabilities и прав
пользователя. Он помогает frontend строить навигацию, но не является средством
защиты endpoint: каждый запрос авторизуется повторно на сервере.

Capability может предоставлять разные действия в разных релизах. В Release A
`lara.lifecycle.v1` объявляет только read-only состояние; действия `start`,
`stop` и `restart` появляются в effective permissions лишь после реализации
аудируемых операций в следующем релизе. Клиент не должен считать наличие feature
разрешением на все потенциальные действия этой feature.

## Авторизация

Lifecycle-операции любого инстанса доступны только пользователю с ролью
`Developer`. Роль считается присутствующей, если она является `main_group` или
содержится в `permissions`. Числовые идентификаторы ролей не образуют иерархию:
`Admin` не наследует Developer-доступ.

Начальная матрица доступа:

| Роль | Primary | Auxiliary |
| --- | --- | --- |
| Developer | Все объявленные capabilities | Все объявленные capabilities |
| Configurator | Ограниченная `Configuration` | Нет доступа |
| Mapper | `Maps` | Нет доступа |
| Backuper | `Backups` | Нет доступа |
| Challenger/Admin | Без lifecycle и файлового доступа; публичный статус/уведомления primary | Инстанс не раскрывается |

Если пользователь одновременно имеет Developer и другую роль, для управления и
уведомлений применяется Developer-политика.

## Multi-instance configuration

Канонический configuration API содержит `instance_id`:

```text
/server-instances/{instance_id}/configuration/...
```

Существующий `/configuration/...` временно остаётся совместимым alias primary.
Каждый configuration service разрешается из доверенного реестра и получает
собственные storage root, encoding, limits, ignored paths и file policy.

Текстовое редактирование и загрузка бинарного игрового мода являются разными
внутренними операциями. Бинарные артефакты разрешаются только по allowlist путей
и расширений, записываются через временный файл и атомарную замену и получают
content hash. Произвольная замена `omp-server`, `.env`, native plugins и других
служебных файлов через configuration API запрещена.

Изменение файла auxiliary создаёт configuration event и аудит, но не backup
snapshot. Primary сохраняет принятую backup policy. Решение о backup принимается
по capability, а не через проверку вида инстанса внутри `configuration`.

## Долговечность событий и инциденты

MongoDB хранит lifecycle operations, incidents, outbox и checkpoints
наблюдателя. Сначала фиксируется бизнес-событие, затем оно публикуется в
Socket.IO. Transactional outbox используется там, где topology MongoDB
поддерживает необходимые транзакционные гарантии; в остальных случаях outbox
восстанавливается идемпотентно из канонической записи операции или инцидента.

Плановая lifecycle-операция и инцидент являются разными сущностями. Неуспешная
плановая операция может породить инцидент. Неожиданное изменение systemd без
активной операции классифицируется как внешнее действие или отказ на основании
доступных свидетельств.

Инцидент различает operational state (`Open`, `Recovering`, `Resolved`) и review
state (`Unreviewed`, `Acknowledged`, `Investigated`). Автоматическое
восстановление закрывает outage, но не помечает его расследованным.

## Политика уведомлений

Developer получает подробные state events обо всех доступных инстансах и toast
о действиях других Developer. Автор операции продолжает получать state events,
но клиент подавляет дополнительный toast по `actorUserId`.

Challenger и Admin получают отдельную урезанную проекцию только после успешного
restart primary. Она не содержит auxiliary metadata, причины, внутренних ID,
systemd evidence или иных Developer-only сведений.

Пользовательское уведомление, синхронизация состояния и долговечное доменное
событие являются разными представлениями. Исключение одного socket-соединения
через `socket.broadcast` не используется как бизнес-правило "не уведомлять
автора", поскольку у пользователя может быть несколько вкладок или устройств.

## Границы Release A

Release A создаёт фундамент без изменяющих production-команд:

1. Этот ADR и реестр архитектурных решений.
2. Domain-модель идентичности, вида и capabilities инстанса.
3. Конфигурационный реестр с startup-валидацией.
4. Персонализированный read-only capability manifest.
5. Read-only runtime state contract.
6. Один auxiliary-инстанс, переведённый администраторами на отдельный systemd
   unit.
7. Systemd adapter в read-only/shadow режиме для пилотного инстанса.
8. Unit-, HTTP- и Linux integration tests для границ Release A.

В Release A не входят:

- start/stop/restart из Lara;
- Socket.IO lifecycle notifications;
- incident persistence;
- journald replay;
- multi-instance configuration mutations;
- UDS protocol changes;
- автоматический rollout на primary.

Эти возможности добавляются последующими вертикальными релизами после проверки
реестра, manifest и read-only наблюдения на auxiliary.

## Последствия

Положительные:

- перезапуск Lara не останавливает игровые серверы;
- все инстансы получают одинаковую process supervision модель;
- новый инстанс в основном добавляется конфигурацией и systemd unit;
- frontend не зависит от фиксированного списка серверов и разделов;
- lifecycle, readiness и incident evidence больше не смешиваются;
- auxiliary может получить configuration без включения backups;
- границы файловых хранилищ и системных units проверяются централизованно.

Отрицательные и эксплуатационные затраты:

- все управляемые серверы необходимо перевести на systemd;
- потребуется Linux integration environment; read-only наблюдение не требует
  выдавать Lara право управлять units, а policy для будущих команд проектируется
  отдельно;
- MongoDB topology влияет на реализацию transactional outbox;
- readiness основного сервера требует развития UDS-протокола;
- capability manifest и versioned events становятся публичными контрактами;
- multi-instance configuration требует миграции существующих unscoped routes.

## Рассмотренные альтернативы

### Прямой `spawn(omp-server)` из Lara

Отклонено: превращает backend в process supervisor и требует самостоятельно
решать восстановление после рестарта Lara, cgroups, orphan cleanup, backoff,
логи, сигналы и запуск после reboot хоста.

### Управление через PID, `pidof` и `kill`

Отклонено: не различает одноимённые процессы, подвержено повторному использованию
PID и не предоставляет надёжный источник exit evidence.

### Только Socket.IO для команд и событий

Отклонено: требует собственного RPC, idempotency и recovery-протокола. HTTP
используется для команд, Socket.IO — для доставки событий.

### RCON как supervisor или health check

Отклонено: недоступно при падении процесса, не предоставляет надёжной истории и
не заменяет systemd. RCON может быть добавлен только как необязательный adapter
для graceful shutdown или игровых административных команд.

### Отдельный backend на каждый инстанс

Отклонено для текущего масштаба: дублирует auth, API и эксплуатацию. Один control
plane управляет реестром локальных инстансов; удалённый агент может быть добавлен
позднее реализацией runtime-порта.

## Нерешённые детали реализации

Следующие решения принимаются отдельными ADR или implementation notes после
коротких технических исследований:

- точная polkit/D-Bus policy production-хоста;
- MongoDB transaction/outbox strategy для фактической topology;
- формат UDS handshake и heartbeat;
- readiness probes auxiliary-инстансов;
- eventual remote-agent transport для нескольких физических хостов.
