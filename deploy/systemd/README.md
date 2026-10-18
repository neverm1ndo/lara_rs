# Пилотный игровой инстанс под systemd

Этот пакет закрывает инфраструктурную часть шага 6 Release A. Он предназначен
для одного auxiliary-инстанса. Primary на этом этапе автоматически не
мигрируется, а Lara не получает права `StartUnit`, `StopUnit` или `RestartUnit`.

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
sudo groupadd --system lara-game
sudo useradd --system --gid lara-game --home-dir /nonexistent \
  --shell /usr/sbin/nologin lara-game

sudo install -o root -g root -m 0644 \
  deploy/systemd/lara-game@.service \
  /etc/systemd/system/lara-game@.service
sudo install -d -o root -g lara-game -m 0750 /etc/lara/game-instances
sudo chown -R lara-game:lara-game /srv/openmp/dev-dm
sudo chmod 0750 /srv/openmp/dev-dm/omp-server

sudo systemd-analyze verify /etc/systemd/system/lara-game@.service
sudo systemctl daemon-reload
```

`groupadd` и `useradd` вернут ошибку, если учётная запись уже существует; в
таком случае администратор должен проверить существующие UID/GID, а не создавать
дубликат. Рекурсивный `chown` допустим только после проверки точного абсолютного
пути пилотного инстанса.

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
bash deploy/systemd/verify-pilot.sh dev-dm
```

Проверка по одному имени процесса недостаточна. Сопоставляйте PID, listening
port, рабочий каталог и cgroup выбранного unit.

## Регистрация в Lara

Production overlay должен содержать как primary, так и auxiliary: массив
`game_server.instances` заменяется целиком.

```toml
[game_server]
primary_instance = "main"

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
capabilities = ["overview", "lifecycle", "configuration", "incidents"]
readiness = "process"
incident_tracking = true
systemd_observation = true
```

После изменения overlay перезапустите Lara и проверьте Developer manifest.
До реализации шага 7 runtime endpoint будет честно возвращать
`observation.status = "not_observed"`.

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
