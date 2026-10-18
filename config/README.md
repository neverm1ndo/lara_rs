# Конфигурация сервера

Сервер использует гибридную конфигурацию: обычные параметры можно хранить в
TOML, а секреты и точечные переопределения передавать через окружение.

## Приоритет источников

Значение из источника ниже в списке заменяет значение из источника выше:

1. минимальные встроенные значения загрузчика;
2. безопасный `config/default.toml`, встроенный в бинарник при сборке;
3. дополнительный TOML-файл из `LARA_CONFIG_FILE`;
4. устаревшие переменные окружения;
5. переменные окружения `LARA_*`.

Таким образом, production-файл может задавать общие параметры окружения, а
секреты из secret manager или контейнера всегда имеют последний приоритет.
Запуск установленного бинарника не зависит от текущей директории или наличия
исходного дерева. Копия defaults в `/usr/share/lara-rs/config/default.toml`
устанавливается только как справочный файл; runtime использует встроенную копию.

## Имена переменных окружения

Путь внутри TOML преобразуется в переменную с префиксом `LARA_`; уровни
разделяются двумя подчёркиваниями:

| TOML | Переменная окружения |
| --- | --- |
| `server.bind_address` | `LARA_SERVER__BIND_ADDRESS` |
| `jwt.secret` | `LARA_JWT__SECRET` |
| `jwt.issuer` | `LARA_JWT__ISSUER` |
| `jwt.audience` | `LARA_JWT__AUDIENCE` |
| `jwt.ttl_seconds` | `LARA_JWT__TTL_SECONDS` |
| `mfa.encryption_key` | `LARA_MFA__ENCRYPTION_KEY` |
| `mfa.issuer` | `LARA_MFA__ISSUER` |
| `mfa.challenge_ttl_seconds` | `LARA_MFA__CHALLENGE_TTL_SECONDS` |
| `mfa.enrollment_ttl_seconds` | `LARA_MFA__ENROLLMENT_TTL_SECONDS` |
| `mfa.max_verification_attempts` | `LARA_MFA__MAX_VERIFICATION_ATTEMPTS` |
| `mfa.totp_period_seconds` | `LARA_MFA__TOTP_PERIOD_SECONDS` |
| `mfa.totp_digits` | `LARA_MFA__TOTP_DIGITS` |
| `mfa.allowed_clock_skew_steps` | `LARA_MFA__ALLOWED_CLOCK_SKEW_STEPS` |
| `mysql.url` | `LARA_MYSQL__URL` |
| `mongodb.uri` | `LARA_MONGODB__URI` |
| `mongodb.database` | `LARA_MONGODB__DATABASE` |
| `game_server.primary_instance` | `LARA_GAME_SERVER__PRIMARY_INSTANCE` |
| `game_server.storage.root` | `LARA_GAME_SERVER__STORAGE__ROOT` |
| `game_server.storage.max_tree_depth` | `LARA_GAME_SERVER__STORAGE__MAX_TREE_DEPTH` |
| `game_server.storage.max_tree_entries` | `LARA_GAME_SERVER__STORAGE__MAX_TREE_ENTRIES` |
| `game_server.storage.max_stream_size_bytes` | `LARA_GAME_SERVER__STORAGE__MAX_STREAM_SIZE_BYTES` |
| `configuration.files.configurator_directory` | `LARA_CONFIGURATION__FILES__CONFIGURATOR_DIRECTORY` |
| `configuration.files.binary_extensions` | `LARA_CONFIGURATION__FILES__BINARY_EXTENSIONS` |
| `configuration.files.binary_file_names` | `LARA_CONFIGURATION__FILES__BINARY_FILE_NAMES` |
| `configuration.files.ignored_paths` | `LARA_CONFIGURATION__FILES__IGNORED_PATHS` |
| `configuration.files.fallback_encoding` | `LARA_CONFIGURATION__FILES__FALLBACK_ENCODING` |
| `maps.files.directory` | `LARA_MAPS__FILES__DIRECTORY` |
| `maps.upload.max_files_per_request` | `LARA_MAPS__UPLOAD__MAX_FILES_PER_REQUEST` |
| `maps.upload.max_file_size_bytes` | `LARA_MAPS__UPLOAD__MAX_FILE_SIZE_BYTES` |
| `maps.upload.max_total_size_bytes` | `LARA_MAPS__UPLOAD__MAX_TOTAL_SIZE_BYTES` |
| `backups.storage.directory` | `LARA_BACKUPS__STORAGE__DIRECTORY` |
| `backups.storage.compression` | `LARA_BACKUPS__STORAGE__COMPRESSION` |
| `backups.storage.compression_level` | `LARA_BACKUPS__STORAGE__COMPRESSION_LEVEL` |
| `backups.storage.compression_threshold_bytes` | `LARA_BACKUPS__STORAGE__COMPRESSION_THRESHOLD_BYTES` |
| `backups.retention.lifetime_seconds` | `LARA_BACKUPS__RETENTION__LIFETIME_SECONDS` |
| `backups.retention.cleanup_interval_seconds` | `LARA_BACKUPS__RETENTION__CLEANUP_INTERVAL_SECONDS` |
| `backups.retention.cleanup_batch_size` | `LARA_BACKUPS__RETENTION__CLEANUP_BATCH_SIZE` |
| `backups.retention.max_concurrent_deletions` | `LARA_BACKUPS__RETENTION__MAX_CONCURRENT_DELETIONS` |
| `backups.retention.operation_lease_seconds` | `LARA_BACKUPS__RETENTION__OPERATION_LEASE_SECONDS` |
| `backups.retention.stale_preparation_seconds` | `LARA_BACKUPS__RETENTION__STALE_PREPARATION_SECONDS` |
| `backups.diff.enabled` | `LARA_BACKUPS__DIFF__ENABLED` |
| `backups.diff.max_input_size_bytes` | `LARA_BACKUPS__DIFF__MAX_INPUT_SIZE_BYTES` |
| `backups.diff.generation_timeout_ms` | `LARA_BACKUPS__DIFF__GENERATION_TIMEOUT_MS` |

Списки в переменных окружения задаются через запятую. Например,
`LARA_CONFIGURATION__FILES__BINARY_EXTENSIONS=amx,dff,so,txd` и
`LARA_CONFIGURATION__FILES__IGNORED_PATHS=logs,scriptfiles/cache`.

Для локальной разработки скопируйте `.env.example` в `.env` и замените
тестовые реквизиты. `.env` исключён из Git.

## Дополнительный TOML-файл

Путь задаётся отдельно:

```text
LARA_CONFIG_FILE=/etc/lara/production.toml
```

Пример файла без секретов:

```toml
[server]
bind_address = "0.0.0.0:8080"

[jwt]
issuer = "lara-production"
audience = "lara-api"
ttl_seconds = 1800

[mfa]
issuer = "Lara"
challenge_ttl_seconds = 300
enrollment_ttl_seconds = 600
max_verification_attempts = 5
totp_period_seconds = 30
totp_digits = 6
allowed_clock_skew_steps = 1

[mongodb]
database = "lara"

[game_server]
primary_instance = "main"

# The array in an overlay replaces the default array, so repeat the primary
# entry whenever auxiliary instances are declared.
[[game_server.instances]]
id = "main"
display_name = "Main server"
kind = "primary"
environment = "production"
sort_order = 10
systemd_unit = "lara-game@main.service"
capabilities = [
    "overview",
    "lifecycle",
    "configuration",
    "maps",
    "backups",
    "incidents",
]
readiness = "uds"
incident_tracking = true
systemd_observation = false

[[game_server.instances]]
id = "dev-dm"
display_name = "Developer DM"
kind = "auxiliary"
environment = "development"
sort_order = 20
systemd_unit = "lara-game@dev-dm.service"
storage_root = "/srv/openmp/dev-dm"
capabilities = [
    "overview",
    "lifecycle",
    "configuration",
    "incidents",
]
readiness = "process"
incident_tracking = true
systemd_observation = true

[game_server.storage]
root = "/srv/openmp/main"
max_tree_depth = 32
max_tree_entries = 10000
max_stream_size_bytes = 10485760

[configuration.files]
configurator_directory = "scriptfiles/config"
binary_extensions = ["amx", "dff", "dll", "exe", "so", "txd"]
binary_file_names = ["omp-server", "samp03svr"]
ignored_paths = ["logs", "scriptfiles/cache"]
fallback_encoding = "windows-1251"

[maps.files]
directory = "scriptfiles/maps"

[maps.upload]
max_files_per_request = 50
max_file_size_bytes = 10485760
max_total_size_bytes = 52428800

[backups.storage]
directory = "/srv/lara/backups"
compression = "gzip"
compression_level = 1
compression_threshold_bytes = 1048576

[backups.retention]
lifetime_seconds = 1209600
cleanup_interval_seconds = 3600
cleanup_batch_size = 50
max_concurrent_deletions = 8
operation_lease_seconds = 300
stale_preparation_seconds = 1800

[backups.diff]
enabled = true
max_input_size_bytes = 10485760
generation_timeout_ms = 5000
```

`jwt.secret`, `mfa.encryption_key`, `mysql.url` и `mongodb.uri` рекомендуется
передавать только через окружение или secret manager. Не добавляйте
production-секреты в TOML или `.env.example`. Ключ MFA — это ровно 32 случайных
байта, записанных 64 шестнадцатеричными символами.

## Проверка при запуске

До подключения к базам данных сервер проверяет обязательные строки, диапазон
JWT TTL (60–86400 секунд), минимальную длину HS256-секрета (32 байта), формат
ключа шифрования MFA, параметры TOTP и MFA challenge, лимиты файлового
хранилища, относительные пути, расширения и имена бинарных файлов, исключённые
ветки дерева и fallback-кодировку. Секреты скрываются в `Debug`-выводе.

## Опциональная MFA

MFA остаётся добровольной для всех ролей. Настройки `mfa` определяют только
параметры TOTP и короткоживущих login/enrollment challenge; они не включают MFA
глобально и не делают её обязательной для отдельных групп.

`challenge_ttl_seconds` допускает 60–900 секунд, `enrollment_ttl_seconds` —
60–3600 секунд, `max_verification_attempts` — 1–10. Период TOTP ограничен
15–300 секундами, число цифр может быть 6 или 8, а допустимое расхождение часов
— от 0 до 2 временных интервалов. Для совместимости рекомендуются значения
30 секунд, 6 цифр и окно ±1 интервал из `default.toml`.

Каталог `maps.files.directory` задаётся относительно
`game_server.storage.root`. Лимит одного файла карты не может превышать
`game_server.storage.max_stream_size_bytes`, а суммарный лимит одной
мультизагрузки должен быть не меньше лимита отдельного файла. Допустимо от 1 до
1000 файлов в одном запросе; максимальный суммарный размер ограничен 1 ГиБ.

Все файлы, не совпавшие с `binary_extensions` или `binary_file_names`,
считаются потенциально текстовыми. Пути из `ignored_paths` вместе со всем их
содержимым не включаются в дерево и недоступны через configuration API.
Символические ссылки, Windows junction и другие reparse points всегда
игнорируются и не имеют отключаемой настройки.

## Хранилище бэкапов

`backups.storage.directory` разрешается относительно рабочей директории
процесса и обязан находиться вне `game_server.storage.root`. При инициализации
backups-модуля эта граница дополнительно проверяется после canonicalization,
чтобы исключить обход через символические ссылки и Windows reparse points.

`compression` принимает `gzip` или `none`. Для `gzip` допустим уровень 0–9;
для `none` уровень должен быть равен 0. Полный snapshot всегда сохраняется как
неизменённая последовательность байтов. Сжатие и DiffMatchPatch являются
отдельными представлениями и не меняют содержимое при download или restore.

`lifetime_seconds` определяет срок хранения. Cleanup запускается через
`cleanup_interval_seconds`, обрабатывает не более `cleanup_batch_size` записей
за проход и ограничивает параллелизм через `max_concurrent_deletions`.
`operation_lease_seconds` защищает активные download/restore от cleanup, а
`stale_preparation_seconds` используется reconciler для зависших операций.

Diff ограничивается `max_input_size_bytes` и
`generation_timeout_ms`. Бинарные файлы всё равно архивируются целиком, но для
них diff получает статус `not_applicable`; ошибка или отключение diff не
отменяет создание полного snapshot.

## Кодировка файлов configuration API

Файлы конфигурации SAMP/open.mp хранятся в кодировке из
`configuration.files.fallback_encoding` (`windows-1251` по умолчанию). API не
перекодирует содержимое и передаёт байты без изменений:

- `GET /configuration/files` возвращает поток с заголовком
  `Content-Type: text/plain; charset=windows-1251`;
- `POST /configuration/files` и `PUT /configuration/files` принимают
  `multipart/form-data` с единственной бинарной частью `file`, а путь — в
  query-параметре `path`.

Перед записью сервер проверяет, что байты допустимы для настроенной кодировки,
но сохраняет их без декодирования и повторного кодирования. Клиент может
передать уже подготовленный blob напрямую; имя файла внутри multipart не
используется как путь и не считается доверенным вводом.

Для однобайтовой Windows-1251 структурная проверка отбрасывает неназначенный
байт `0x98`. Она не может достоверно отличить случайно присланный UTF-8 без BOM:
последовательности байтов однобайтовых кодировок по своей природе неоднозначны.

## Реестр игровых инстансов

`game_server.primary_instance` ссылается на единственную запись `kind =
"primary"`. Primary использует `game_server.storage.root`, если `storage_root`
не указан непосредственно в его записи. Для auxiliary `storage_root`
обязателен.

Идентификатор содержит только строчные ASCII-буквы, цифры и внутренние дефисы.
Имена systemd units должны оканчиваться на `.service`. При запуске приложение
отклоняет дубли идентификаторов и units, несколько primary, перекрывающиеся
storage roots, отсутствие `lifecycle`, а также `maps` или `backups` у auxiliary.

Массив `game_server.instances` является атомарным значением TOML overlay: если
production-файл объявляет auxiliary, в нём следует повторить и primary. Списки
инстансов рекомендуется задавать в TOML через `LARA_CONFIG_FILE`, а не через
переменные окружения.

`systemd_observation = true` включает read-only D-Bus observer. В Release A
разрешён ровно один такой пилотный auxiliary-инстанс; primary наблюдателем не
затрагивается. По умолчанию флаг выключен, поэтому обновление Lara само по себе
не начинает обращаться к systemd.

Для совместимости конфигурация без `game_server.instances` создаёт implicit
primary с ID из `game_server.primary_instance` (`main` по умолчанию), unit
`lara-game@<id>.service`, полным набором capabilities и UDS readiness. Этот
режим предназначен для миграции и не позволяет объявлять auxiliary.

Шаблон systemd unit, read-only проверка пилота, порядок cutover и rollback
находятся в [`deploy/systemd`](../deploy/systemd/README.md). Старый Node/bash
supervisor необходимо отключить для выбранного инстанса до запуска нового unit,
иначе на одном порту могут одновременно стартовать два процесса.

Значение `game_server.storage.root` по умолчанию равно `./game-server` и
разрешается относительно рабочей директории процесса. В production следует
задавать абсолютный путь. Проверка существования и canonicalization корня
выполняется при инициализации файлового хранилища.

Старые переменные (`LSRV_SECRET`, `MYSQL_DATABASE_URL`, `MONGODB_URI` и
остальные) временно поддерживаются. При их использовании сервер пишет
предупреждение с новым именем переменной; значения в лог не попадают.
