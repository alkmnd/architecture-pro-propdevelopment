# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

### 1. Доступ к секретам
- **Кто:** `minikube-user`, от имени system:serviceaccount:secure-ops:monitoring (флаг `kubectl --as`).
- **Где:** list secrets в namespace kube-system.
- **Исход:** 403 Forbidden — у ServiceAccount monitoring нет прав на чтение секретов kube-system.
- **Почему подозрительно:** юзер пытается послать запрос от имени ServiceAccount. это может расцениваться как разведка привилегий и попытка доступа от имени менее привилегированной учётки. kubectl auth can-i … --as=…:monitoring похоже на исследование прав перед атакой.

### 2. Привилегированные поды
- **Кто:** `minikube-user`.
- **Что:** создал под privileged-pod в namespace secure-ops. Создан успешно.
- **Комментарий:** privileged: true даёт контейнеру доступ к устройствам хоста и эквивалент root-доступа к узлу - это вектор эскалации от пода к ноде (container escape). В кластере отсутствует Pod Security Admission, поэтому под допущен без ограничений.

### 3. Использование kubectl exec в чужом поде
- **Кто:** `minikube-user`.
- **Что делал:** exec (subresource exec, verb=get) в системный под в kube-system командой `cat /etc/resolv.conf` исследовал сеть/DNS.
- **Исход:** код 101 Switching Protocols, т. е. exec авторизован и выполнен (команда запущена, но упала тк distroless-образ coredns без `cat`).
- **Почему подозрительно:** исполнение команд в системном поде - lateral movement. Сам факт exec от высокопривилегированного пользователя в чужой под требует отдельного контроля.

### 4. Создание RoleBinding с правами cluster-admin
- **Кто:** `minikube-user`.
- **Что:** создал RoleBinding escalate-binding в namespace secure-ops, привязавший ServiceAccount monitoring к ClusterRole cluster-admin. Код 201 - создан.
- **К чему привело:** ServiceAccount monitoring получил полные права cluster-admin во всём кластере, это постоянная backdoor-эскалация: любой, кто завладеет токеном monitoring, получает god-mode.

### 5. Удаление audit-policy.yaml
- **Кто:** `minikube-user`.
- **Возможные последствия:** успешное удаление/подмена audit-policy.yaml отключило бы аудит.

## Вывод

Анализ свежего среза audit.log выявил цепочку атаки со стороны `minikube-user`: разведка прав, затем попытка кражи секретов, запуск привилегированного пода, exec в системный под, закладка постоянного доступа через выдачу cluster-admin ServiceAccount monitoring и попытка удалить audit-policy.yaml.

Кластер считается скомпрометированным: привилегированный под создан, ServiceAccount monitoring наделён cluster-admin, секреты прочитаны, exec в системный под авторизован. Корневые проблемы — избыточные привилегии (`minikube-user` в system:masters), отсутствие Pod Security Admission и доступность лога/policy изнутри кластера.

Для устранения: убрать учетку minikube-user из system:masters, пересмотреть роли (не выдавать cluster-admin и secret-reader без необходимости), включить PSA restricted (поды и контейнеры должны быть настроены так, чтобы не запускаться с правами суперпользователя), вынести аудит-лог во внешнее хранилище (чтобы не было ситуации, когда привилегированный пользователь смог удалить/подменить логи), добавить контроль целостности audit-policy.yaml.


