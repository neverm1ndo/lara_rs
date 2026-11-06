# Release E: контракт инцидентов (проект)

Статус: `Proposed`. Этот документ фиксирует первый шаг
[ADR-0004](../adr/0004-release-e-incidents-and-recovery.md). Маршруты и события
ниже ещё не смонтированы; runtime `/openapi.json` пока их не содержит.

## Инвентаризация действующего кода

| Компонент | Уже есть | Для Release E требуется |
| --- | --- | --- |
| `systemd_observer` | D-Bus `PropertiesChanged`, initial snapshot, 30-секундный reconciliation, `ActiveState`, `SubState`, `Result`, `MainPID`, `NRestarts`, `InvocationID`, `ExecMainCode`, `ExecMainStatus` | Передать нормализованное evidence в классификатор; snapshot не является историей и не доказывает причину перехода |
| `runtime_state` | process/readiness/observation, `last_termination`, invocation ID; `not_observed` и `stale` различаются | Не трактовать эти состояния как отказ и не открывать инцидент от одного initial snapshot |
| `lifecycle_operations` и reconciliation | Долговечные команды, actor, expected/final evidence, активная операция, outbox | Корреляция с процессом только по подтверждённым фактам; команда не скрывает независимое падение |
| Socket.IO `/` | Developer room, state и operation events | Долговечные incident events и HTTP recovery; auxiliary не передаётся Admin/Challenger |
| Manifest | Registry содержит `incidents` и `incident_tracking` | До готовности API effective `lara.incidents.v1` и `incidentTracking` скрыты; при подключении API включаются вместе |
| Journald | Адаптера и checkpoint нет | Persistent journal, replay, обнаружение пробелов и дедупликация |

Текущий observer не хранит boot ID или journald cursor. Для доказуемого replay
их нужно читать из journal, а не выводить из `InvocationID` или текущего PID.

## Условия доступности

Автоматические инциденты создаются только для зарегистрированного инстанса с
`management = "systemd"`, capability `incidents` и `incident_tracking = true`.
Primary с `management = "external"` остаётся без инцидентов до появления
достоверного источника process evidence. UDS для этого контракта не требуется.

Developer определяется по `main_group` или явной роли в `permissions`.
Только он видит подробности и меняет review state любого доступного инстанса.
Admin и Challenger не получают инциденты auxiliary ни через HTTP, ни через
Socket.IO. Backend повторяет проверку на каждом запросе; manifest служит
только для навигации.

## Модель записи

```text
incidentId               стабильный непрозрачный ID
instanceId               ID из доверенного registry
kind                     outage | unexpected_restart | unplanned_stop
operationalState         open | recovering | resolved
reviewState              unreviewed | acknowledged | investigated
openedAt                 UTC; время факта или первого подтверждения
recoveredAt              UTC или null
updatedAt                UTC
version                  монотонная версия записи
cause                    exit_code | signal | core_dump | timeout |
                         watchdog | resource_failure | start_limit | unknown
confidence               confirmed | inferred | unknown
evidence                 нормализованные systemd/journal факты
relatedOperationIds      подтверждённые корреляции, может быть []
review                   actorUserId, at, note, история переходов
```

Служебные имена unit, сырые строки журнала и абсолютные пути не входят в
клиентский DTO. Внутренняя запись хранит provenance факта: источник,
boot ID и journald cursor для journal; для live D-Bus — сравнение с ранее
сохранённым состоянием и invocation/restart evidence. PID не используется как
идентичность инцидента. Повтор чтения того же journal entry имеет один ключ
`instanceId + bootId + cursor`; live-переход фиксируется один раз относительно
долговечной предыдущей границы. Записи из live и replay должны сходиться в
один инцидент по доказанной идентичности запуска и интервалу, а не только по
похожим временным меткам.

Отдельный `observation gap` хранит начало/конец неизвестного интервала,
причину (`journal_unavailable`, `cursor_expired`, `permission_denied` и т.п.)
и время обнаружения. Gap не является инцидентом игрового процесса.

На шаге 3 созданы MongoDB collections `server_instance_incidents` и
`server_instance_incident_checkpoints`. Уникальный multikey index по ключам
фактов не позволяет поместить один факт в разные инциденты; отдельный индекс
ограничивает число активных инцидентов одним на instance. Версия агрегата
обновляется через compare-and-swap. Outbox хранится внутри записи инцидента
и пополняется тем же атомарным update; после истечения аренды событие можно
выдать повторно с прежним `eventId`. Checkpoint обновляется отдельным CAS и
должен продвигаться только после долговечной обработки journal entry.

## Переходы и классификация

Operational state: `open -> recovering -> resolved`; при кратком отказе
допустим `open -> resolved`, если промежуточное восстановление не наблюдалось.
Разрешённый инцидент не открывается повторно: новое независимое событие
получает новый ID. Review state: `unreviewed -> acknowledged -> investigated`;
автоматическое разрешение outage не меняет review state. Исправление ошибочной
классификации требует отдельной аудируемой операции, а не удаления истории.

| Сценарий | Решение | Evidence и предел уверенности |
| --- | --- | --- |
| Первый snapshot показывает `active` | Baseline без инцидента | Прошлое неизвестно, пока не выполнен replay |
| Первый snapshot показывает `inactive`/`failed` | Replay или проверка journal перед классификацией | Если журнал недоступен, текущее подтверждённое `failed` может открыть outage с `openedAt` времени наблюдения и `unknown` причиной; прошлое остаётся gap |
| `not_observed`, `stale`, разрыв D-Bus | Инцидент не открывается | Состояние наблюдателя не равно состоянию процесса |
| Подтверждённый плановый stop/restart Lara | Не считать неожиданным отказом | Требуется совпадение operation, unit/job, invocation и времени; одно намерение недостаточно |
| Неплановый exit/failure | Открыть `outage` | Нормализованная причина из systemd, иначе `unknown` |
| Automatic restart после отказа | Перевести тот же outage в `resolved` после подтверждения `active` | `NRestarts`/новый invocation и journal дают связь; review остаётся `unreviewed` |
| Неплановый restart без доказанного outage | `unexpected_restart`, сразу `resolved` после active | Не приписывать причину или actor без evidence |
| Внешний stop | `unplanned_stop`, пока процесс не восстановлен | Не называть crash без exit/failure evidence |
| Неуспешная операция Lara без фактической потери процесса | Нет incident, операция остаётся failed | Командная ошибка сама по себе не outage |
| Неполный journal | Observation gap | Не реконструировать неизвестные переходы по предположению |

`recovering` означает наблюдаемую попытку возврата процесса (например,
`activating`) после зафиксированного отказа. Для process-readiness
`resolved` наступает после подтверждённого `active`; это не утверждение о
готовности игрового приложения. Если в ходе планового restart обнаружен
самостоятельный отказ, он классифицируется отдельно с явной ссылкой на
операцию и уровнем уверенности.

## Предлагаемый HTTP API

Все пути находятся под `/server-instances/{instance_id}/incidents`.

| Метод и путь | Назначение |
| --- | --- |
| `GET /server-instances/{instance_id}/incidents` | Список по `operationalState`, `reviewState`, времени и opaque cursor; стабильный порядок `(openedAt DESC, incidentId DESC)` |
| `GET /server-instances/{instance_id}/incidents/{incident_id}` | Детали и история review |
| `PATCH /server-instances/{instance_id}/incidents/{incident_id}/review` | Переход в `acknowledged` или `investigated`, `note` и `Idempotency-Key`; `If-Match` по версии записи |

У списка ограниченный `limit` и `nextCursor`; cursor связывает порядок и
фильтры, поэтому его нельзя применять с другим набором фильтров. `ETag`
детальной записи отражает `version`. Изменение review требует strong
`If-Match`, чтобы две вкладки не перезаписали решение друг друга. Повтор
запроса с тем же actor, ключом и телом возвращает прежний результат; тот же
ключ с другим содержимым даёт конфликт. Ответы содержат `Cache-Control:
no-store`.

| HTTP | Код | Случай |
| ---: | --- | --- |
| 400 | `BAD_REQUEST` | Неверный фильтр, cursor, review transition или ключ |
| 401 | `UNAUTHENTICATED` | Нет действующей сессии |
| 403 | `FORBIDDEN` | Видимый primary, но роль не разрешена |
| 404 | `NOT_FOUND` | Неизвестный или скрытый инстанс, отсутствующий инцидент |
| 409 | `CONFLICT` | Повтор ключа с другим запросом или недопустимый переход |
| 412 | `PRECONDITION_FAILED` | Устаревший `If-Match` |
| 428 | `PRECONDITION_REQUIRED` | Нет `If-Match` для review |
| 503 | `SERVICE_UNAVAILABLE` | Нельзя надёжно записать инцидент/review |

## Realtime и восстановление

Предлагаемое событие Socket.IO `/`: `server_instance.incident.updated.v1`.
Конверт содержит `schemaVersion`, `eventId`, `incidentId`, `instanceId`,
`version`, `occurredAt`, `kind`, `operationalState`, `reviewState`,
`openedAt`, `recoveredAt` и `actorUserId` для ручного review. Event ID
стабилен для пары `(incidentId, version)`. Outbox допускает повторную доставку;
клиент дедуплицирует по `eventId`. После переподключения клиент запрашивает
историю по HTTP; отсутствие socket-соединения не меняет запись инцидента.

События адресуются только Developer. Инициатор review получает обновление
состояния во всех своих вкладках; клиент подавляет собственный toast по
`actorUserId`. У автоматического инцидента actor отсутствует.

## Открытые решения перед шагом 2

- Проверить на Debian host, какие journald fields и курсоры доступны для
  `lara-game@...` при реальных restart/crash и какие права нужны `lara`.
- Зафиксировать фактический MongoDB transaction режим production topology:
  embedded outbox или транзакция, с сохранением идемпотентного replay.
- Подтвердить, нужен ли отдельный HTTP endpoint для observation gaps или
  достаточно `doctor` и операционного журнала. Gap не смешивать с incident.
