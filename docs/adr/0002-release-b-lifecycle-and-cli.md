# ADR-0002: Release B — управление lifecycle и единый CLI

- Статус: `Accepted`
- Дата: 2026-10-27
- Владельцы: backend и infrastructure teams
- Связанный этап: Release B
- Развивает: [ADR-0001](0001-server-instance-control-plane.md)

## Контекст

Release A создал read-only фундамент control plane: реестр игровых инстансов,
capability manifest, runtime state contract и shadow-наблюдение одного
auxiliary-инстанса через systemd D-Bus. Изменяющие lifecycle-команды намеренно
не реализовывались.

Пилотный deployment выявил, что ручная установка требует слишком большого
числа связанных действий: копирования примеров, редактирования TOML, создания
systemd drop-in, настройки Unix-пользователей и прав, проверки D-Bus и запуска
диагностических команд. Такая процедура подходит для разработки решения, но не
является приемлемым постоянным интерфейсом администратора.

Основной игровой сервер пока работает под прежним supervisor и не может быть
переведён на отдельный systemd unit без согласованного окна. При этом он должен
оставаться primary в каталоге Lara и использовать существующие configuration,
maps и backups. Следовательно, регистрация инстанса и управление его процессом
должны быть явно разделены.

Release B должен дать Developer безопасные `start`, `stop` и `restart` для
auxiliary-инстансов, сохранить аудит независимо от realtime-соединения и
сократить обычное развёртывание до нескольких проверяемых CLI-команд.

## Решение

### Граница Release B

Release B является вертикальным релизом управления lifecycle
auxiliary-инстансов. В него входят:

- единый CLI `lara` для daemon-режима, настройки и диагностики;
- явные режимы управления инстансом `external` и `systemd`;
- наблюдение нескольких systemd-managed auxiliary-инстансов;
- `start`, `stop` и `restart` через systemd D-Bus;
- долговечные lifecycle operations и идемпотентный HTTP API;
- Developer-only авторизация команд;
- realtime-события состояния и операций с возможностью восстановления через
  HTTP;
- минимально необходимая polkit policy и Linux integration tests;
- упрощённая и исправленная раскладка Debian-пакета.

В Release B не входят:

- автоматическая миграция или lifecycle-управление primary;
- UDS handshake и readiness primary;
- журнал автоматических инцидентов и journald replay;
- multi-instance configuration routes и mutations;
- RCON;
- удалённый agent для других физических хостов;
- автоматическая остановка прежних Node/bash supervisors.

### Регистрация и режим управления

У инстанса появляется обязательный режим управления:

- `external` — Lara регистрирует инстанс и предоставляет разрешённые файловые
  capabilities, но не наблюдает и не изменяет его процесс;
- `systemd` — Lara наблюдает и может изменять состояние заранее настроенного
  systemd unit.

Пример:

```toml
[[game_server.instances]]
id = "main"
display_name = "Main server"
kind = "primary"
management = "external"
storage_root = "/home/svr_main"

[[game_server.instances]]
id = "test"
display_name = "Test server"
kind = "auxiliary"
management = "systemd"
systemd_unit = "lara-game@test.service"
storage_root = "/home/svr_test"
```

`systemd_unit` обязателен только для режима `systemd`. Наличие capability
`Lifecycle` продолжает описывать предметную возможность, но effective
permissions `start`, `stop` и `restart` выдаются только для управляемого
systemd-инстанса и только Developer.

Флаг `systemd_observation` становится устаревшим. На один переходный релиз он
читается для совместимости и преобразуется в соответствующий режим с явным
предупреждением. Новая конфигурация не должна требовать этот флаг: systemd mode
автоматически включает наблюдение.

Release B разрешает несколько systemd-managed auxiliary-инстансов. Primary
официально поддерживается в режиме `external`; его миграция и изменяющие
команды остаются отдельным этапом.

### Единый CLI

Debian-пакет устанавливает канонический executable `/usr/bin/lara`. Тот же
бинарник используется как daemon и административная утилита:

```text
lara serve
lara doctor [--instance <id>]
lara config init
lara config validate
lara config paths
lara instance list
lara instance add
lara instance edit
lara instance remove
lara instance verify <id>
lara instance render-systemd <id>
lara completions <shell>
```

Packaged unit запускает `lara serve` от непривилегированного пользователя
`lara`. Команды, изменяющие `/etc/lara` или systemd drop-ins, проверяют наличие
необходимых прав и обычно вызываются через `sudo`. Read-only диагностика может
работать без root и явно отмечает пропущенные privileged checks.

Запуск `lara` без подкоманды показывает справку и не запускает daemon. Для
переходного периода пакет предоставляет `/usr/bin/lara-rs` как совместимый
alias; новый systemd unit использует только `/usr/bin/lara serve`.

CLI является presentation/bootstrap-слоем. Он переиспользует application
services и доменную валидацию, а не реализует отдельные правила для ID,
capabilities, storage roots или systemd units.

### Безопасное изменение host-конфигурации

`lara config init` создаёт production overlay и environment-файл, но:

- не записывает секреты в аргументы процесса или логи;
- не перезаписывает существующий файл без явного подтверждения;
- выставляет владельца `root:lara` и режим `0640`;
- поддерживает `--dry-run`, `--yes` и машиночитаемый `--output json`;
- не запускает сервис автоматически.

`lara instance add` принимает стабильный ID, root, executable, Unix user и
capabilities, затем:

1. валидирует модель инстанса и отсутствие пересечений;
2. показывает план изменений;
3. атомарно обновляет только явный production overlay;
4. создаёт instance-specific systemd drop-in;
5. учитывает расположение под `/home` через `ProtectHome` и `ReadWritePaths`;
6. проверяет unit через `systemd-analyze verify`;
7. выполняет `daemon-reload` после успешной записи;
8. сообщает необходимые изменения ACL отдельным планом.

CLI использует file lock, временный файл, `fsync` и atomic rename. Перед
изменением существующего файла создаётся резервная копия. Удаление регистрации
или drop-in никогда не удаляет storage root и файлы игрового сервера.
Рекурсивный `chown`, остановка прежнего supervisor, enable или start unit не
выполняются неявно.

### Диагностика

`lara doctor` возвращает отдельный результат каждой проверки и ненулевой exit
code при блокирующей проблеме. Проверяются как минимум:

- синтаксис и startup-инварианты конфигурации;
- доступность MySQL и MongoDB;
- существование и права storage roots;
- доступ пользователя `lara` к заявленным файловым capabilities;
- executable, WorkingDirectory и effective systemd unit;
- D-Bus и read-only snapshot;
- polkit-разрешения без выполнения изменяющей команды;
- наличие процесса того же сервера вне ожидаемого cgroup;
- расхождение production overlay и systemd drop-in.

Human-readable вывод используется по умолчанию; `--output json` предоставляет
стабильный контракт для автоматизации.

### Lifecycle operation

Изменяющий HTTP-запрос создаёт в MongoDB `LifecycleOperation` до обращения к
systemd. Минимальная state machine:

```text
Requested
  -> Dispatching
  -> WaitingForState
  -> Succeeded | Failed | TimedOut
```

Операция содержит:

- уникальный operation ID;
- instance ID и действие;
- actor user ID и безопасное отображаемое имя;
- idempotency key и fingerprint запроса;
- timestamps и deadline;
- ожидаемое конечное состояние;
- systemd job reference;
- нормализованные начальное и конечное evidence;
- безопасный error code.

Если каноническая запись операции не сохранена, systemd-команда не
выполняется. Повтор того же запроса с тем же `Idempotency-Key` возвращает
исходную операцию. Использование ключа с другим payload возвращает `409`.
Несовместимые активные операции над одним инстансом сериализуются.

### Runtime port и systemd D-Bus

Application layer определяет runtime port для `start`, `stop` и `restart`.
Infrastructure adapter вызывает `StartUnit`, `StopUnit` и `RestartUnit` через
async D-Bus; `systemctl` и прямой spawn игрового процесса не используются.

Защита состоит из двух независимых слоёв:

1. application allowlist разрешает только unit, полученный из доверенного
   instance registry;
2. polkit разрешает Unix-пользователю `lara` управление только шаблоном
   `lara-game@*.service` и только необходимыми systemd verbs.

Имена units, пути executable и storage roots никогда не принимаются из
lifecycle HTTP payload.

Принятие systemd job не завершает операцию. Observer сопоставляет job и
последующие snapshots с ожидаемым состоянием. `stop` успешен после
подтверждённого `inactive`; `start` и `restart` — после `active` и настроенной
readiness-проверки. Для Release B auxiliary использует process readiness.

### HTTP и OpenAPI

Release B реализует контракты из ADR-0001:

```text
POST /server-instances/{instance_id}/operations
GET  /server-instances/{instance_id}/operations
GET  /server-instances/{instance_id}/operations/{operation_id}
```

`POST` требует заголовок `Idempotency-Key` и payload:

```json
{
  "action": "restart"
}
```

Каждый endpoint повторно проверяет роль Developer и доступ к инстансу.
Capability manifest получает permissions `start`, `stop` и `restart` только
после готовности command path. Все DTO документируются через `utoipa`.

### Realtime и долговечность

После долговечного изменения публикуются versioned события:

```text
server_instance.operation.updated
server_instance.state.changed
```

Developer получает подробные события всех доступных инстансов. Событие
содержит `actorUserId`: клиент обновляет состояние во всех сессиях, но не
показывает автору дополнительный toast о собственном действии.

Socket.IO не является источником истории. После reconnect клиент получает
операции через HTTP. Доставка является at-least-once; события имеют стабильные
ID и sequence для дедупликации. Если MongoDB topology не позволяет атомарную
multi-document transaction, outbox идемпотентно восстанавливается из
канонической записи операции.

### Debian-пакет

Operational examples перемещаются из `/usr/share/doc` в
`/usr/share/lara-rs/examples`, поскольку документация может исключаться
локальной dpkg policy. Пакет также:

- устанавливает `lara`, совместимый alias `lara-rs`, systemd units и polkit
  policy;
- не перезаписывает `/etc/lara` при upgrade;
- не запускает сервис до явной настройки;
- устраняет предупреждения создания service users;
- предлагает после установки выполнить `sudo lara config init` и
  `sudo lara doctor`.

## Совместимость и миграция

Release B читает Release A configuration и сообщает точную миграцию к
`management`. Существующий `lara-rs.service` обновляется пакетом одновременно с
бинарником, поэтому начинает использовать `lara serve`. Пользовательские
production overlays и игровые данные не изменяются postinst-скриптом.

Изменение конфигурации CLI выполняется только после её полного чтения и
валидации новой моделью. При ошибке исходный файл и effective systemd config
остаются без изменений.

## Критерии приёмки

Release B считается завершённым, когда:

- primary работает в `external` без фиктивного systemd unit;
- как минимум два auxiliary одновременно наблюдаются через D-Bus;
- Developer может идемпотентно выполнить start, stop и restart;
- Admin, Challenger и специализированные роли получают `403`;
- рестарт Lara во время операции не теряет её и приводит к reconciliation;
- повторный HTTP-запрос не создаёт повторную systemd-команду;
- Socket.IO reconnect восстанавливается через HTTP history;
- polkit не позволяет Lara управлять посторонним unit;
- `lara instance add --dry-run` не изменяет host;
- `lara doctor` обнаруживает неверные права, D-Bus/polkit denial и процесс вне
  ожидаемого cgroup;
- установка `.deb` на чистый Debian оставляет систему в безопасном
  ненастроенном состоянии и предоставляет все operational examples;
- rollback одного auxiliary не затрагивает Lara, primary и другие инстансы.

## Последствия

Положительные:

- primary больше не обязан притворяться systemd-managed;
- обычное добавление auxiliary становится воспроизводимой CLI-операцией;
- daemon и CLI используют одну версию доменных правил;
- ручные команды получают аудит, idempotency и наблюдаемое завершение;
- потеря realtime-соединения не теряет историю действий;
- приложение и ОС независимо ограничивают область systemd-команд.

Отрицательные и эксплуатационные затраты:

- CLI должен безопасно редактировать TOML и host-конфигурацию;
- polkit и настоящий systemd требуют Linux integration environment;
- операции становятся асинхронными и требуют recovery после рестарта;
- переходный compatibility layer временно усложняет registry;
- incident journal и primary readiness остаются нерешёнными после Release B.

## Рассмотренные альтернативы

### Отдельный `lara-admin`

Отклонено: отдельный executable создаёт дополнительную версию публичного
интерфейса и риск рассинхронизации с daemon. Один `lara` разделяет режимы через
subcommands, сохраняя внутренние bounded contexts.

### Автоматический start после `instance add`

Отклонено: CLI не может безопасно предположить, что старый supervisor остановлен
и порт свободен. Cutover остаётся отдельным подтверждаемым действием.

### Lifecycle-команды через Socket.IO

Отклонено по ADR-0001: HTTP предоставляет idempotency и recovery-контракт;
Socket.IO используется только для server-to-client событий.

### Запуск `systemctl` из Lara

Отклонено: production adapter использует типизированный D-Bus API без shell и
не наследует особенности CLI-вывода или окружения.

### Разрешить управление primary в Release B

Отклонено: существующий primary ещё связан с прежним supervisor, а его
readiness через UDS не реализован. Auxiliary даёт безопасную границу для
проверки command path.

## Последующие решения

Отдельные ADR или implementation notes должны уточнить:

- точное содержание polkit rule и способ его проверки без мутации unit;
- формат MongoDB indexes, operation lease и outbox recovery;
- CLI schema для стабильного JSON output;
- стратегию редактирования TOML с сохранением комментариев;
- границы следующего релиза: incidents, journald replay, UDS readiness и
  migration primary.
