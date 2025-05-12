# Dev

Debug mattermost плагинов требует пропатченной версии сервера [см. документацию](https://developers.mattermost.com/integrate/plugins/developer-workflow/#configure-mattermost-server-for-debugging-plugins)

Для упрощения процесса представлен docker образ с уже [пропатченным](./patch_go_plugin.sh) и собранным из исходников сервером.

## Запуск 

Команда запускает сервер mattermost. Для использования образа из docker registry необходимо задать переменную окружения `DOCKER_REGISTRY` в [.env](.env)


В случае запуска на удаленном хосте, требуется указать корректный SiteUrl в System Console -> Web Server, иначе сообщения от плагина могут не приходить
```shell
docker compose up
```

## Debug
1. Задеплоить плагин. Предварительно задать переменные окружения [.env](.env)
    ```shell
    cd .. && MM_DEBUG=1 make deploy
    ```
2. Запустить дебаггер. Команду выполнять на хосте, где запущен mattermost
    ```shell
    docker exec patched-mm sh -c 'dlv attach $(pgrep -f "plugins/forgejo/*") --continue --listen :2346 --headless=true --api-version=2 --accept-multiclient'
    ```
3. Подключиться к дебаггеру через порт из предыдущей команды
