# CI и доставка

**Русский** · [English](README.en.md)

Границы проверок и наблюдавшиеся результаты описаны в [README](../README.ru.md#cicd).

GitLab выполняет portable/configuration tests, компиляцию BPF и упаковку. bpf-build имеет dependencies: []; delivery получает только BPF artifacts через needs. FF_USE_DIRECT_DOWNLOAD=false отключает прямой путь скачивания, на котором наблюдался CDN 403.

GitHub Actions использует hosted runner, Debian containers и read-only permissions. Выполняются переносимые и конфигурационные проверки, затем сборка и загрузка BPF package. Результат новой редакции проверяется в её workflow; прежний успех GitLab не доказывает успех GitHub.

ci/package.sh принимает CI_COMMIT_SHA; GitHub передаёт github.sha. Проверяются контрольные суммы object, упаковываются object/build metadata. SHA-256 не является подписью или независимым доказательством происхождения.

Развёртывание GitLab требует OPLA_DEPLOY_ENABLED=1, protected default branch, manual job и отдельный runner с tag opla-deploy. Protected File variables: OPLA_DEPLOY_INVENTORY, OPLA_DEPLOY_VARS, OPLA_SSH_PRIVATE_KEY, OPLA_SSH_KNOWN_HOSTS. Перед настройкой изучите deploy.sh; проверка host keys включена. Реальное серверное развёртывание ещё не прошло приёмку.

Исходная история уже присоединена к публичному репозиторию; атрибуция затем исправлена. Не повторяйте старый импорт и не сливайте приватную ветку целиком. См. [историю Git](../docs/git-history.md).
