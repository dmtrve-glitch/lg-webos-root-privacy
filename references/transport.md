# Локальный доступ

Используй рабочий доступ, а не меняй его без причины. Команды ниже — шаблоны с явными параметрами, не готовые адреса чужого ТВ. `SESSION` — отдельный каталог сеанса с private-подкаталогом; он не находится внутри переносимого скилла. На Windows проверь ACL private-каталога: `chmod(0600)` в Python не заменяет ACL.

## SSAP и временный bridge

`scripts/tv_bridge.py` — Python 3 на ноутбуке, только stdlib. Он не содержит exploit. Параметры:

```text
python SKILL/scripts/tv_bridge.py --tv TV_IP --module SESSION/upstream-slopbro/slopbro.py --manifest SESSION/reviewed-sources.json --key-file SESSION/private/tv.key --action pair
python SKILL/scripts/tv_bridge.py --tv TV_IP --module SESSION/upstream-slopbro/slopbro.py --manifest SESSION/reviewed-sources.json --key-file SESSION/private/tv.key --action info --output SESSION/identity.json
python SKILL/scripts/tv_bridge.py --tv TV_IP --module SESSION/upstream-slopbro/slopbro.py --manifest SESSION/reviewed-sources.json --key-file SESSION/private/tv.key --action exec --local-ip LAPTOP_IP --app-id VERIFIED_WAM_APP --command-file SESSION/command.sh --output SESSION/result.json --asset-dir SESSION/transfer
```

У `reviewed-sources.json` форма `{"files":[{"path":"slopbro.py","sha256":"реальный hash проверенного модуля"}, ...]}`. Пример полной исторической записи лежит рядом в `slopbro-source-manifest.json`. Хэш проверяется **до** import. Обновление manifest допустимо после проверки новой версии, а не для обхода ошибки целостности. Bridge требует совместимых `SSAPClient`, `WebSocket`, `DEFAULT_MANIFEST`; при изменении upstream адаптируй интерфейс после чтения кода.

На pair нужен физический ответ «Разрешить». `info` не даёт root, а доступность update-info зависит от прав. Не считать отсутствие firmware в ответе признаком совместимости: запросить его с экрана.

Exec требует **уже установленного и разрешённого** root-сервиса `org.webosbrew.hbchannel.service/exec` и подходящего WAM context. Для webOS 6 в нашем кейсе это был `com.webos.app.adoverlayex`; на другом build сверяй upstream routing и реальные разрешения. `returnValue` уровня Luna не заменяет проверку результата shell-команды. В `command.sh` используй `set -e`, выводи проверяемое конечное состояние, читай сохранённый полный JSON.

Временный HTTP-сервер привязывается к указанному LAN-интерфейсу и принимает запросы только от TV IP по случайному URL. Это доверенный локальный канал HTTP, а не шифрование или криптографическое подтверждение источника; на недоверенной/общей сети используй другой разрешённый транспорт. Не отключай глобальный firewall: сначала проверь IP, маршрут, guest Wi-Fi, client isolation и узкое временное правило, если оно действительно требуется. У исходников SSAP-клиента проверь обработку самоподписанного сертификата ТВ; pairing key не отправляй внешним узлам.

`--asset-dir` публикует только файлы верхнего уровня этого каталога, не симлинки. Помести туда только нужные публичные скрипты/данные передачи, никогда ключи и backup пользовательских данных. В команде `ASSET_BASE_URL` подменяется временным URL; после скачивания проверь заранее известный SHA-256. Не выполнять непроверенный поток `curl | sh`.

## Передача аудита и политики

Скопируй `tv_audit.py` и `tv_policy.py` в transfer-каталог, вычисли их hashes на ноутбуке. Для команды загрузки на ТВ используй curl или имеющийся клиент, затем сравни hash. Пример структуры shell-команды (подставить реальный digest до запуска):

```sh
set -e
curl -fsS --connect-timeout 4 --max-time 8 'ASSET_BASE_URL/tv_audit.py' -o /tmp/lg-tv-audit.py
printf '%s  %s\n' 'REVIEWED_SHA256' '/tmp/lg-tv-audit.py' | sha256sum -c -
python /tmp/lg-tv-audit.py
```

Встроенный timeout bridge по умолчанию `BusyBox -t 20`; `--timeout-style gnu` для проверенного GNU варианта. Длительные задачи надо разбить; максимальное время команды 45 секунд. Сервер завершается после результата или таймаута. Если результат потерян, сначала прочитай состояние: команда могла исполниться. Не повторяй trial/install вслепую.

Страница пытается закрыться через `window.close()`. Если осталась — удержать «Назад» 2–3 секунды, восстановить обычный UI, затем проводить визуальную проверку. Не считать страницу/синий фон автоматически поломкой. Не утверждать, что код закрыл страницу только на основании успешного POST. Если WAM page уничтожена при запуске другого приложения, запланируй короткую задачу с отложенным запуском и отдельным логом/результатом, а не жди невозможный ответ старой страницы.
