# Задание 7 — Аудит и обеспечение соответствия политике безопасности контейнеров (PSP / PodSecurity / OPA Gatekeeper)

## Структура файлов

```
Task7/
├── 01-create-namespace.yaml          # namespace audit-zone с PSA restricted
├── insecure-manifests/               # поды, которые должны быть отклонены
│   ├── 01-privileged-pod.yaml        # privileged: true
│   ├── 02-hostpath-pod.yaml          # монтирует hostPath
│   └── 03-root-user-pod.yaml         # runAsUser: 0 (root)
├── secure-manifests/                 # исправленные, безопасные поды
│   ├── 01-secure.yaml
│   ├── 02-secure.yaml
│   └── 03-secure.yaml
├── gatekeeper/
│   ├── constraint-templates/        
│   │   ├── privileged.yaml
│   │   ├── hostpath.yaml
│   │   └── runasnonroot.yaml        
│   └── constraints/               
│       ├── privileged.yaml
│       ├── hostpath.yaml
│       └── runasnonroot.yaml
├── verify/
│   ├── verify-admission.sh           # проверка PSA: insecure отклоняются, secure принимаются
│   └── validate-security.sh          # проверка Gatekeeper: установлен и применяет ограничения
├── audit-policy.yaml                 # политика аудита 
└── README_FOR_REVIEWER.md
```


## Порядок выполнения

### 1. Установить OPA Gatekeeper

```bash
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update
helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system --create-namespace
```

Дождаться готовности:

```bash
kubectl -n gatekeeper-system wait deploy/gatekeeper-controller-manager \
  --for=condition=Available --timeout=180s
```

### 2. Применить namespace и политики Gatekeeper

```bash
kubectl apply -f 01-create-namespace.yaml
kubectl apply -f gatekeeper/constraint-templates/
kubectl apply -f gatekeeper/constraints/
```

> После применения шаблонов подождите нужро подождать несколько секугд, пока Gatekeeper
> зарегистрирует новые констреинты, затем нужно выполнить `kubectl apply -f gatekeeper/constraints/`,
> если первый раз появилась ошибка `no matches for kind`.

### 3. Проверить

```bash
# PodSecurity Admission: небезопасные отклоняются, безопасные принимаются
bash verify/verify-admission.sh

# Gatekeeper установлен, constraints применяются
bash verify/validate-security.sh
```