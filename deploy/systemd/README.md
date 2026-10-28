# Пилотный игровой инстанс под systemd

Этот пакет закрывает инфраструктурную часть шага 6 Release A. Он предназначен
для одного auxiliary-инстанса. Primary на этом этапе автоматически не
мигрируется, а Lara не получает права `StartUnit`, `StopUnit` или `RestartUnit`.

## Установка Debian-пакета Lara

Release artifact рассчитан на Debian 12 (`amd64`). Пакет устанавливает бинарник,
`lara-rs.service`, шаблон `lara-game@.service`, примеры конфигурации и утилиту
`/usr/lib/lara-rs/verify-pilot`. Сервис намеренно не запускается и не включается
автоматически: сначала администратор должен добавить production-конфигурацию и
секреты.

Канонический executable — `/usr/bin/lara`; systemd запускает `lara serve`.
`/usr/bin/lara-rs` временно сохраняется как совместимый alias. Запуск `lara`
без подкоманды показывает справку и не запускает daemon.

```sh
sudo apt install ./lara-rs_0.2.2-1_amd64.deb

sudo lara config init --dry-run
sudo lara config init
```

Команда использует встроенные в тот же бинарник шаблоны, поэтому не зависит от
наличия `/usr/share/doc`. Она не запускает сервис и не заменяет существующие
файлы без явного `--yes`; перед разрешённой заменой создаются timestamped
backup-файлы. Для автоматизации доступен `--output json`.

В `/etc/lara/lara.env` необходимо заменить placeholder-секреты. Путь overlay
уже указан как:

```text
LARA_CONFIG_FILE=/etc/lara/production.toml
```

После проверки путей, реквизитов баз данных и списка инстансов:

```sh
sudo lara config validate
lara config paths
sudo systemd-analyze verify /lib/systemd/system/lara-rs.service
sudo systemctl enable --now lara-rs.service
sudo systemctl --no-pager --full status lara-rs.service
sudo journalctl -u lara-rs.service -n 100 --no-pager
```

Package upgrade сохраняет `/etc/lara` и `/var/lib/lara` и не удаляет системных
пользователей. Package removal также не удаляет пользовательские данные.

## Принятая раскладка

Для инстанса `dev-dm` шаблон ожидает:

```text
/srv/openmp/dev-dm/
├── omp-server
├── config.json или server.cfg
├── gamemodes/
├── plugins/
└── scriptfiles/
```

Процесс запускается пользователем `lara-game`, остаётся foreground-процессом и
не daemonize/fork. Все его дочерние процессы принадлежат cgroup
`lara-game@dev-dm.service`.

Если существующий сервер пока нельзя перенести в `/srv/openmp/<instance-id>`,
используйте instance-specific drop-in из `override.conf.example`. Не меняйте
общий шаблон ради одного нестандартного инстанса.

## Предварительные условия

1. Выберите некритичный auxiliary-инстанс и согласуйте окно обслуживания.
2. Зафиксируйте текущую команду запуска, рабочий каталог, пользователя,
   переменные окружения, лимиты и открытые порты.
3. Убедитесь, что бинарник работает в foreground без `screen`, `tmux`, `nohup`,
   завершающего `&` и бесконечного restart-loop в shell-скрипте.
4. Отключите для пилота старый Node/bash supervisor. Он не должен иметь
   возможности запустить второй процесс после перехода на systemd.
5. Убедитесь, что `storage_root` пилота не пересекается с primary и другими
   инстансами.

Не используйте `pidof omp-server` или массовый `pkill`: на хосте могут работать
несколько одноимённых процессов.

## Установка

Команды выполняются администратором на Linux-хосте. Значения пользователя,
группы и путей сначала следует проверить для конкретного сервера.

```sh
getent group lara-game >/dev/null || sudo groupadd --system lara-game
sudo install -d -o root -g root -m 0755 /var/lib/lara-game
id -u lara-game >/dev/null 2>&1 || \
  sudo useradd --system --gid lara-game --home-dir /var/lib/lara-game \
    --shell /usr/sbin/nologin lara-game
sudo chown lara-game:lara-game /var/lib/lara-game
sudo chmod 0750 /var/lib/lara-game

# Debian-пакет уже устанавливает шаблон. При развёртывании напрямую из
# исходников используйте вместо него:
# sudo install -o root -g root -m 0644 \
#   deploy/systemd/lara-game@.service \
#   /etc/systemd/system/lara-game@.service
sudo install -d -o root -g lara-game -m 0750 /etc/lara/game-instances
sudo chown -R lara-game:lara-game /srv/openmp/dev-dm
sudo chmod -R g+rwX,o-rwx /srv/openmp/dev-dm
sudo chmod 0750 /srv/openmp/dev-dm/omp-server

sudo systemd-analyze verify /lib/systemd/system/lara-game@.service
sudo systemctl daemon-reload
```

Debian-пакет создаёт обе сервисные учётные записи; команды выше оставлены для
развёртывания unit напрямую из исходников. Администратор должен проверить
существующие UID/GID. Рекурсивный `chown` допустим только после проверки точного
абсолютного пути пилотного инстанса.

Пользователь `lara` запускается с supplementary group `lara-game`. Поэтому все
storage roots, доступные через configuration/file manager, должны разрешать
группе `lara-game` чтение и запись. Unit использует `UMask=0007`, чтобы новые
файлы игрового процесса сохраняли это свойство. Не добавляйте игровые процессы
в группу `lara`: она предназначена для чтения секретов самой Lara.

Если серверу нужны переменные окружения, создайте отдельный файл из
`instance.env.example`. Секреты Lara в него не помещаются.

## Cutover без двойного процесса

Сначала остановите пилот штатным способом старого supervisor и запретите ему
автоматический повторный запуск. Затем убедитесь, что порт свободен и процесс
этого конкретного инстанса отсутствует. Только после этого выполните:

```sh
sudo systemctl enable --now lara-game@dev-dm.service
sudo systemctl --no-pager --full status lara-game@dev-dm.service
sudo journalctl -u lara-game@dev-dm.service -n 100 --no-pager
sudo /usr/lib/lara-rs/verify-pilot dev-dm
```

Проверка по одному имени процесса недостаточна. Сопоставляйте PID, listening
port, рабочий каталог и cgroup выбранного unit.

## Регистрация в Lara

Реестр теперь безопасно редактируется тем же бинарником. Первый `instance add`
автоматически материализует external primary из действующей конфигурации,
сохраняет остальные TOML-комментарии и добавляет только auxiliary:

```sh
sudo lara instance add dev-dm \
  --display-name "Developer DM" \
  --environment development \
  --storage-root /home/svr_dm \
  --capability overview \
  --capability lifecycle \
  --capability configuration \
  --capability incidents \
  --sort-order 20 \
  --dry-run

# Повторить без --dry-run после проверки плана.
sudo lara instance add dev-dm \
  --display-name "Developer DM" \
  --environment development \
  --storage-root /home/svr_dm \
  --capability overview \
  --capability lifecycle \
  --capability configuration \
  --capability incidents \
  --sort-order 20

sudo lara instance list
```

`instance edit` заменяет только явно переданные поля. Если указан хотя бы один
`--capability`, переданный набор заменяет прежний целиком. `instance remove`
требует `--yes`; он удаляет только регистрацию и никогда не удаляет storage
root, его содержимое, drop-in или запущенный процесс. Каждая запись overlay
проверяется полным startup-валидатором, выполняется под file lock, создаёт
timestamped backup и устанавливается atomic rename.

После регистрации drop-in можно сначала проверить, а затем установить отдельной
командой:

```sh
sudo lara instance render-systemd dev-dm --dry-run
sudo lara instance render-systemd dev-dm
```

Команда проверяет, что storage root существует, не является symlink, а
`omp-server` — обычный исполняемый файл внутри этого root. Для нестандартного
имени используются `--executable`, `--user` и `--group`. Путь под `/home`
автоматически получает `ProtectHome=no`; для остальных путей сохраняется
`ProtectHome=yes`. В обоих случаях `ReadWritePaths` ограничен единственным
storage root.

Drop-in устанавливается с режимом `0644`. При замене требуется `--yes` и
создаётся backup. После изменения Lara вызывает manager `Reload` через systemd
D-Bus; для подготовки offline image предусмотрен `--no-reload`. Команда не
вызывает `enable`, `start`, `stop`, не создаёт environment-файл и не меняет
владельцев игровых ресурсов. Ожидаемый необязательный environment-файл и план
ACL возвращаются в human/JSON output.

Эквивалентная ручная форма production overlay содержит как primary, так и
auxiliary: массив `game_server.instances` заменяется целиком.

```toml
[game_server]
primary_instance = "main"

[[game_server.instances]]
id = "main"
display_name = "Main server"
kind = "primary"
environment = "production"
sort_order = 10
management = "external"
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

[[game_server.instances]]
id = "dev-dm"
display_name = "Developer DM"
kind = "auxiliary"
environment = "development"
sort_order = 20
management = "systemd"
systemd_unit = "lara-game@dev-dm.service"
storage_root = "/srv/openmp/dev-dm"
capabilities = ["overview", "lifecycle", "configuration", "incidents"]
readiness = "process"
incident_tracking = true
```

После изменения overlay перезапустите Lara и проверьте Developer manifest.
До первого успешного D-Bus snapshot runtime endpoint возвращает
`observation.status = "not_observed"`; при потере связи после snapshot —
`observation.status = "stale"`.

## Acceptance checklist

- unit проходит `systemd-analyze verify`;
- unit имеет состояния `active/running` и ненулевой `MainPID`;
- `InvocationID` заполнен, `NRestarts` читается;
- процесс находится в cgroup своего unit, а не `lara.service` или `lars.service`;
- после перезапуска Lara игровой процесс продолжает работать;
- штатный `systemctl stop` не приводит к автоматическому restart;
- аварийное завершение восстанавливается согласно `Restart=on-failure`;
- после пяти быстрых падений срабатывает start limit;
- stdout/stderr доступны через `journalctl -u lara-game@dev-dm.service`;
- старый Node/bash supervisor не может создать второй экземпляр;
- Developer manifest показывает `dev-dm`, другие роли его не видят.

Проверки аварийного завершения и start limit выполняются только в отдельное
согласованное окно. Для них не следует использовать primary.

## Откат

1. Остановите только пилотный unit:
   `sudo systemctl disable --now lara-game@dev-dm.service`.
2. Проверьте освобождение его порта и отсутствие процессов в cgroup unit.
3. Верните прежний способ запуска только для этого инстанса.
4. Удалите `dev-dm` из production overlay Lara и перезапустите Lara.
5. Сохраните journal и вывод `systemctl show` для разбора причины отката.

Не удаляйте каталог сервера и не меняйте его данные во время отката.
