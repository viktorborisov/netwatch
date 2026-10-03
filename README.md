# netwatch — eBPF live-монитор активности системы

Смотрит в реальном времени, что делает система: сетевые соединения,
запуск процессов и открытие файлов. Работает через **eBPF** (ядро
Linux сообщает о событиях, без патчей и перезагрузок).

## Архитектура

    [host]  bpftrace (all.bt)  --пишет-->  logs/events.jsonl
                                              |
                                              | (общий volume, ro)
                                              v
    [docker] Flask (app.py)  --читает-->  ring-buffer --> веб-дашборд (SSE)

Почему так:
- **bpftrace на хосте, а не в контейнере** — контейнер не privileged,
  не нужно монтировать /sys/kernel внутрь, легче и безопаснее.
- **один bpftrace, а не три** — каждый инстанс держит ~112MB RSS
  (libbpf/LLVM). Три инстанса = OOM на этом 868MB VPS. Один = ~40-60MB.
- **Flask в контейнере** — изоляция, лимит памяти 128M, рестарт-политика.

## Файлы

- `bt/all.bt`      — bpftrace-программа: 3 tracepointа (net/proc/file)
- `tracer.sh`      — запускает all.bt, превращает строки в JSONL
- `app.py`         — Flask: tail JSONL, ring-buffer, SSE-стрим, дашборд
- `Dockerfile`     — образ Flask-сервиса
- `docker-compose.yml` — запуск контейнера, volume logs->/data:ro
- `/etc/systemd/system/netwatch-tracer.service` — автозапуск tracerа

## Формат события

Строка в `logs/events.jsonl`:

    {"ts":123456,"type":"net","pid":42,"comm":"curl",
     "data":{"daddr":"1.1.1.1","dport":80}}

- `ts` — это **nsecs ядра** (время с загрузки), а не Unix-время!
  Flask переводит в реальное: `boot_time + ts/1000` (см. `enrich()`).
- `type`: `net` (TCP connect) | `proc` (exec) | `file` (openat)

## Управление

    systemctl status netwatch-tracer     # host-трейсер
    systemctl restart netwatch-tracer
    docker compose -f /opt/netwatch/docker-compose.yml logs -f
    docker compose -f /opt/netwatch/docker-compose.yml restart

## Доступ к дашборду (безопасно, без открытия портов)

Flask слушает ТОЛЬКО 127.0.0.1:8000. Смотри через SSH-туннель:
с локальной машины:

    ssh -L 8000:127.0.0.1:8000 -i ~/.ssh/vps_ed25519 root@194.87.239.102

затем открыть http://localhost:8000

## Известные ограничения

- bpftrace показывает `pid=0 / swapper` для сетевых connect: событие
  происходит в контексте softirq, а не процесса. Это норма eBPF.
- Часть `file`-событий — относительные пути (openat с dirfd), напр.
  `etc`, `run`. Фильтр по префиксу их не отсекает.
- Убраны шумные пути: /proc,/sys,/dev,/run,/lib,/usr/lib,locale,hyperv.

## Что можно добавить

- Алерт в Telegram на коннект к «интересному» IP/порту (probe + pipe).
- FIFO вместо JSONL (append дешевле, tail проще).
- Ротация events.jsonl (logrotate) при долгой работе.

## CI/CD (GitHub Actions)

Workflow: `.github/workflows/deploy.yml`

- **pull_request** → только CI (проверка кода, сборка образа).
- **push в main** → CI + деплой на VPS по rsync, затем рестарт
  контейнера и host-трейсера. На сервере git-репозиторий НЕ нужен.

### Настройка (один раз)

1. Создай репозиторий на GitHub и запушь:

       cd netwatch
       git remote add origin git@github.com:<user>/netwatch.git
       git push -u origin main

2. Добавь секреты: GitHub repo → Settings → Secrets and variables →
   Actions → New repository secret:

   | Секрет       | Значение                                             |
   |--------------|------------------------------------------------------|
   | `VM_HOST`   | `194.87.239.102`                                     |
   | `VM_USER`   | `root`                                               |
   | `VM_SSH_KEY`| приватный ключ `~/.ssh/gh_deploy` (целиком, с строками) |

3. Публичная часть ключа уже в `~/.ssh/authorized_keys` на VPS
   (запись `github-actions-deploy`). Если нет — добавь:

       ssh-copy-id -i ~/.ssh/gh_deploy.pub root@194.87.239.102

4. Проверка: сделай push в main → во вкладке Actions увидишь
   jobs `ci` и `deploy`.

### Как это работает

    push main --> [ci: py_compile, bash -n, docker build]
                          |
                          v (needs: ci)
                 [deploy: rsync код -> VPS, docker compose build/up,
                          systemctl restart netwatch-tracer]

`--delete` в rsync убирает удалённые локально файлы, но исключает
`.git`, `logs`, `__pycache__` — логи на сервере не трогаются.
