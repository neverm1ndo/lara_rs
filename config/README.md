# Конфигурация сервера

Сервер использует гибридную конфигурацию: обычные параметры можно хранить в
TOML, а секреты и точечные переопределения передавать через окружение.

## Приоритет источников

Значение из источника ниже в списке заменяет значение из источника выше:

1. встроенные безопасные значения;
2. `config/default.toml`;
3. дополнительный TOML-файл из `LARA_CONFIG_FILE`;
4. устаревшие переменные окружения;
5. переменные окружения `LARA_*`.

Таким образом, production-файл может задавать общие параметры окружения, а
секреты из secret manager или контейнера всегда имеют последний приоритет.

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
| `mysql.url` | `LARA_MYSQL__URL` |
| `mongodb.uri` | `LARA_MONGODB__URI` |
| `mongodb.database` | `LARA_MONGODB__DATABASE` |
| `game_server.storage.root` | `LARA_GAME_SERVER__STORAGE__ROOT` |
| `game_server.storage.max_tree_depth` | `LARA_GAME_SERVER__STORAGE__MAX_TREE_DEPTH` |
| `game_server.storage.max_tree_entries` | `LARA_GAME_SERVER__STORAGE__MAX_TREE_ENTRIES` |
| `game_server.storage.max_stream_size_bytes` | `LARA_GAME_SERVER__STORAGE__MAX_STREAM_SIZE_BYTES` |
| `configuration.files.configurator_directory` | `LARA_CONFIGURATION__FILES__CONFIGURATOR_DIRECTORY` |
| `configuration.files.binary_extensions` | `LARA_CONFIGURATION__FILES__BINARY_EXTENSIONS` |
| `configuration.files.binary_file_names` | `LARA_CONFIGURATION__FILES__BINARY_FILE_NAMES` |
| `configuration.files.ignored_paths` | `LARA_CONFIGURATION__FILES__IGNORED_PATHS` |
| `configuration.files.fallback_encoding` | `LARA_CONFIGURATION__FILES__FALLBACK_ENCODING` |

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

[mongodb]
database = "lara"

[game_server.storage]
root = "/srv/openmp"
max_tree_depth = 32
max_tree_entries = 10000
max_stream_size_bytes = 10485760

[configuration.files]
configurator_directory = "scriptfiles/config"
binary_extensions = ["amx", "dff", "dll", "exe", "so", "txd"]
binary_file_names = ["omp-server", "samp03svr"]
ignored_paths = ["logs", "scriptfiles/cache"]
fallback_encoding = "windows-1251"
```

`jwt.secret`, `mysql.url` и `mongodb.uri` рекомендуется передавать только
через окружение или secret manager. Не добавляйте production-секреты в TOML
или `.env.example`.

## Проверка при запуске

До подключения к базам данных сервер проверяет обязательные строки, диапазон
JWT TTL (60–86400 секунд), минимальную длину HS256-секрета (32 байта), лимиты
файлового хранилища, относительные пути, расширения и имена бинарных файлов,
исключённые ветки дерева и fallback-кодировку. Секреты скрываются в
`Debug`-выводе.

Все файлы, не совпавшие с `binary_extensions` или `binary_file_names`,
считаются потенциально текстовыми. Пути из `ignored_paths` вместе со всем их
содержимым не включаются в дерево и недоступны через configuration API.
Символические ссылки, Windows junction и другие reparse points всегда
игнорируются и не имеют отключаемой настройки.

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

Значение `game_server.storage.root` по умолчанию равно `./game-server` и
разрешается относительно рабочей директории процесса. В production следует
задавать абсолютный путь. Проверка существования и canonicalization корня
выполняется при инициализации файлового хранилища.

Старые переменные (`LSRV_SECRET`, `MYSQL_DATABASE_URL`, `MONGODB_URI` и
остальные) временно поддерживаются. При их использовании сервер пишет
предупреждение с новым именем переменной; значения в лог не попадают.
