# Cómo preparar tu flujo de GitHub Actions para el CI/CD con ServerPilot

> **Audiencia:** agentes y equipos que configuran el pipeline de deploy.  
> **Objetivo:** preparar tu aplicación y tu workflow para que ServerPilot pueda ejecutar el release automático en el servidor.  
> **Regla de oro:** ServerPilot **no recibe código fuente**. Solo recibe **imágenes Docker** vía registry + ejecución de `release.sh` por SSH.

---

## 0. Decisión obligatoria — ¿qué camino usar?

```
SI el proyecto en producción es:
  - UN solo proceso
  - UN solo Dockerfile
  - SIN dependencias locales en el mismo host (db/redis externos o embebidos en la misma imagen)
ENTONCES → CAMINO 1 (Docker simple)

SI el proyecto en producción es:
  - Varios servicios en docker-compose.yml (app + db, app + redis, etc.)
  - Dependencias que deben correr en el mismo host que la app
ENTONCES → CAMINO 2 (Docker Compose)
```

| Señal en el repo | Camino |
|------------------|--------|
| Solo `Dockerfile`, deploy = un container | **1** |
| `docker-compose.yml` con app + db/redis/worker | **2** |
| Dockerfile + compose para dev local, prod con stack en servidor | **2** |

**No mezclar caminos en producción.** Elegí uno y seguí solo ese procedimiento.

---

## 1. Invariantes (válidos para ambos caminos)

```
INVARIANTE_1: El CI construye y pushea la imagen al registry (GHCR u otro).
INVARIANTE_2: El servidor NUNCA ejecuta git clone, npm install, go build, etc.
INVARIANTE_3: El deploy en prod ocurre EN EL SERVIDOR vía SSH + release.sh.
INVARIANTE_4: Tags de imagen inmutables: v1.2.3 o sha-abc1234. PROHIBIDO :latest en prod.
INVARIANTE_5: Secretos de runtime (DB, API keys) → prod.env en servidor. NO en GitHub.
INVARIANTE_6: Secretos de conexión (SSH) → GitHub Secrets. NO en prod.env.
INVARIANTE_7: Registry login en servidor es TEMPORAL dentro de release.sh. NO persistir tokens.
INVARIANTE_8: Publicar containers en 127.0.0.1. Nginx (ServerPilot) expone el dominio.
```

---

## 2. Variables globales que el agente debe definir primero

El agente **elige** `APP_NAME` y lo usa **idéntico** en todos lados:

```
APP_NAME        := "<minúsculas, sin espacios>"     # ej. payments-api
REGISTRY        := "ghcr.io"
ORG             := "<org o usuario github>"
IMAGE_NAME      := REGISTRY + "/" + ORG + "/" + APP_NAME
RELEASE_SCRIPT  := "/opt/" + APP_NAME + "/deploy/release.sh"
COMPOSE_DIR     := "/opt/" + APP_NAME              # solo camino 2
```

**Validación del nombre:**

```
ASSERT APP_NAME matches regex: ^[a-z][a-z0-9-]*$
ASSERT APP_NAME is stable (no fechas, no nombres de persona)
```

**Cuando el agente terminó de configurar GitHub + workflow:**

```
NOTIFY ServerPilot team:
  "Deploy listo para provisionar. APP_NAME=<APP_NAME>, CAMINO=<1|2>"
WAIT until ServerPilot confirms:
  - /opt/<APP_NAME>/ exists
  - release.sh installed
  - (camino 2) bootstrap done, prod.env ready
THEN enable workflow (push tag v*)
```

---

## 3. Matriz de configuración — GitHub vs servidor

### 3.1 GitHub — Environments

```
CREATE environment: production
OPTIONAL CREATE environment: staging

BIND secrets SSH only to the environment used by deploy job
JOB must declare: environment: production
```

### 3.2 GitHub — Secrets (obligatorios)

| Secret | Valor | Quién lo provee |
|--------|-------|-----------------|
| `SSH_HOST` | hostname o IP del servidor | ServerPilot |
| `SSH_USER` | usuario deploy | ServerPilot |
| `SSH_PRIVATE_KEY` | clave privada Ed25519 completa | ServerPilot |

### 3.3 GitHub — Variables (por camino)

**Camino 1:**

| Variable | Ejemplo | Cuándo se conoce |
|----------|---------|------------------|
| `IMAGE_NAME` | `ghcr.io/org/payments-api` | Al definir APP_NAME |
| `CONTAINER_PORT` | `8080` | Al leer Dockerfile EXPOSE/listen |
| `DEPLOY_PORT` | `3042` | **Después** del primer deploy exitoso (`sp port`) |
| `RELEASE_SCRIPT` | `/opt/payments-api/deploy/release.sh` | Al definir APP_NAME |

**Camino 2:**

| Variable | Ejemplo | Cuándo se conoce |
|----------|---------|------------------|
| `IMAGE_NAME` | `ghcr.io/org/payments-api` | Al definir APP_NAME |
| `COMPOSE_DIR` | `/opt/payments-api` | Al definir APP_NAME |
| `RELEASE_SERVICE` | `app` | Nombre del servicio que TU imagen reemplaza |
| `RELEASE_SCRIPT` | `/opt/payments-api/deploy/release.sh` | Al definir APP_NAME |

### 3.4 Servidor — `prod.env` (runtime, NO GitHub)

```
# Camino 1: opcional si pasás env al docker run (habitualmente pocos)
# Camino 2: OBLIGATORIO para app + db

DATABASE_URL=...
API_KEY=...
# todo lo que la app necesita para arrancar
```

### 3.5 Registry — token en CI (no guardar en servidor)

```
GitHub Actions:
  PUSH  → secrets.GITHUB_TOKEN (permissions: packages: write)
  PULL en servidor → pasar mismo token como REGISTRY_TOKEN al SSH step (efímero)

REGISTRY_USER := github.actor
REGISTRY_TOKEN := secrets.GITHUB_TOKEN
```

---

## 4. Procedimiento común del pipeline (ambos caminos)

```
PROCEDIMIENTO release_pipeline:

  TRIGGER: push tag matching v*  (ej. v1.2.3)

  STEP 1 — checkout
    git checkout ref del tag

  STEP 2 — test
    ejecutar tests del proyecto (stack-agnóstico)
    SI falla → ABORT pipeline

  STEP 3 — build image
    docker build -t IMAGE_NAME:TAG .
    TAG := github.ref_name  (ej. v1.2.3)

  STEP 4 — push image
    docker login ghcr.io
    docker push IMAGE_NAME:TAG
    SI falla → ABORT pipeline

  STEP 5 — deploy via SSH
    CONECTAR: SSH_USER@SSH_HOST con SSH_PRIVATE_KEY
    EXPORTAR env vars (ver sección del camino elegido)
    EJECUTAR: bash RELEASE_SCRIPT
    SI exit code != 0 → ABORT pipeline, alertar

  POSTCONDICIÓN:
    container(s) corriendo en servidor con imagen TAG
    (camino 2) solo servicio RELEASE_SERVICE recreado
```

**El runner de GitHub NO ejecuta `docker run` ni `compose up` en producción.** Solo en el servidor.

---

# CAMINO 1 — Docker simple (solo Dockerfile)

## C1. Cuándo aplica

```
APLICA SI:
  - Un Dockerfile en la raíz (o ruta fija en el workflow)
  - Un solo container en producción
  - Puerto interno conocido (EXPOSE o documentado)

NO APLICA SI:
  - Necesitás postgres/redis como containers separados en el mismo host
  → usar CAMINO 2
```

## C1. Arquitectura

```
[GitHub Actions] --build push--> [GHCR]
[GitHub Actions] --SSH--------> [Servidor]
                                  release.sh:
                                    sp port (si DEPLOY_PORT vacío)
                                    docker pull IMAGE_REF
                                    docker run -p 127.0.0.1:DEPLOY_PORT:CONTAINER_PORT
[ServerPilot/Nginx] -----------> dominio público → 127.0.0.1:DEPLOY_PORT
```

## C1. Archivos que el agente crea en el repo

```
REPO/
  Dockerfile              # OBLIGATORIO
  .dockerignore           # OBLIGATORIO
  .github/workflows/release.yml
```

**Dockerfile — requisitos mínimos:**

```
MUST expose exactly one application port (ej. EXPOSE 8080)
MUST define CMD o ENTRYPOINT que escuche en ese puerto
MUST NOT bake secrets en la imagen
```

## C1. `release.sh` en el servidor (ServerPilot lo instala)

Ruta fija: `/opt/<APP_NAME>/deploy/release.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${IMAGE_REF:?IMAGE_REF is required}"
CONTAINER_NAME="${CONTAINER_NAME:?CONTAINER_NAME is required}"
CONTAINER_PORT="${CONTAINER_PORT:?CONTAINER_PORT is required}"
DEPLOY_PORT="${DEPLOY_PORT:-$(sp port)}"

if [ -n "${REGISTRY_TOKEN:-}" ] && [ -n "${REGISTRY_USER:-}" ]; then
  CFG="$(mktemp -d)"
  TOK="$(mktemp)"
  chmod 600 "$TOK"
  printf '%s' "$REGISTRY_TOKEN" > "$TOK"
  export DOCKER_CONFIG="$CFG"
  docker login ghcr.io -u "$REGISTRY_USER" --password-stdin < "$TOK"
  trap 'rm -f "$TOK"; docker logout ghcr.io 2>/dev/null; rm -rf "$CFG"' EXIT
fi

docker pull "$IMAGE_REF"
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "127.0.0.1:${DEPLOY_PORT}:${CONTAINER_PORT}" \
  "$IMAGE_REF"
```

## C1. Variables que el SSH step DEBE exportar

```
IMAGE_REF       = IMAGE_NAME + ":" + TAG
CONTAINER_NAME  = APP_NAME
CONTAINER_PORT  = <puerto interno, ej. "8080">
DEPLOY_PORT     = vars.DEPLOY_PORT  (vacío solo en primer deploy)
REGISTRY_USER   = github.actor
REGISTRY_TOKEN  = secrets.GITHUB_TOKEN
```

## C1. Workflow GitHub Actions — plantilla completa

Reemplazá `TU_ORG` y `NOMBRE_APP` por valores reales.

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: read
  packages: write

env:
  IMAGE_NAME: ghcr.io/TU_ORG/NOMBRE_APP
  CONTAINER_NAME: NOMBRE_APP
  CONTAINER_PORT: "8080"
  RELEASE_SCRIPT: /opt/NOMBRE_APP/deploy/release.sh

jobs:
  release:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Test
        run: |
          # AGENT: reemplazar con comando real de tests
          echo "run tests"

      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: ${{ env.IMAGE_NAME }}:${{ github.ref_name }}

      - uses: appleboy/ssh-action@v1.2.0
        env:
          IMAGE_REF: ${{ env.IMAGE_NAME }}:${{ github.ref_name }}
          CONTAINER_NAME: ${{ env.CONTAINER_NAME }}
          CONTAINER_PORT: ${{ env.CONTAINER_PORT }}
          DEPLOY_PORT: ${{ vars.DEPLOY_PORT }}
          REGISTRY_USER: ${{ github.actor }}
          REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          host: ${{ secrets.SSH_HOST }}
          username: ${{ secrets.SSH_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          envs: IMAGE_REF,CONTAINER_NAME,CONTAINER_PORT,DEPLOY_PORT,REGISTRY_USER,REGISTRY_TOKEN
          script: bash ${{ env.RELEASE_SCRIPT }}
```

## C1. Secuencia post-primer-deploy

```
PRIMER deploy exitoso:
  1. release.sh llamó sp port → obtuvo DEPLOY_PORT (ej. 3042)
  2. AGENT: guardar DEPLOY_PORT=3042 en GitHub Variables (environment production)
  3. ServerPilot: Associate Site en dashboard → dominio → SSL (una vez)

DEPLOYS siguientes:
  ASSERT vars.DEPLOY_PORT está definido
  ASSERT release.sh NO llama sp port de nuevo
  ASSERT mismo puerto → Nginx sigue funcionando
```

## C1. Validación final (camino 1)

```
CHECK docker ps --filter name=APP_NAME → Status Up
CHECK curl -sf http://127.0.0.1:DEPLOY_PORT/health → HTTP 200
CHECK imagen en uso == IMAGE_NAME:TAG esperado
```

---

# CAMINO 2 — Docker Compose (stack en servidor)

## C2. Cuándo aplica

```
APLICA SI:
  - Producción requiere app + dependencias (db, redis, etc.) en el mismo host
  - Solo la imagen de TU servicio cambia en cada release
  - Dependencias usan imágenes públicas fijas (postgres:16-alpine, redis:7, etc.)

NO APLICA SI:
  - Un solo container alcanza
  → usar CAMINO 1
```

## C2. Arquitectura

```
BOOTSTRAP (una vez, ServerPilot):
  crear /opt/APP_NAME/docker-compose.yml  (sin build:)
  crear /opt/APP_NAME/prod.env
  sp compose deploy → levanta app + db, asigna SP_COMPOSE_PORT

CADA RELEASE (tu CI):
  build push imagen solo de TU servicio
  SSH → release.sh:
    export IMAGE_REF=...
    docker compose pull RELEASE_SERVICE
    docker compose up -d --no-deps --no-build RELEASE_SERVICE

  db/redis: NO se tocan
```

## C2. División de responsabilidades

| Componente | Quién lo construye en CI | Quién lo actualiza en release |
|------------|--------------------------|-------------------------------|
| Tu app (`app`, `web`) | SÍ — `docker build` | SÍ — `pull` + `up --no-deps` |
| Postgres, Redis, etc. | NO — imagen pública fija | NO — quedan corriendo |
| docker-compose.yml en servidor | NO | NO — estable |
| prod.env | NO | NO — solo cambios manuales controlados |

## C2. Manifiesto en servidor (`/opt/<APP_NAME>/docker-compose.yml`)

ServerPilot lo crea en bootstrap. **El agente NO lo sube desde el repo.**

```yaml
services:
  app:
    image: ${IMAGE_REF:?IMAGE_REF is required}
    env_file:
      - /opt/NOMBRE_APP/prod.env
    ports:
      - "${SP_COMPOSE_PORT}:8080"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3

  db:
    image: postgres:16-alpine
    expose:
      - "5432"
    env_file:
      - /opt/NOMBRE_APP/prod.env
    volumes:
      - db_data:/var/lib/postgresql/data

volumes:
  db_data:
```

**Reglas del manifiesto:**

```
PROHIBIDO build: en servicios de producción
IMAGE_REF solo en el servicio que TU CI construye
ports: + ${SP_COMPOSE_PORT} → servicio público (Nginx)
expose: → interno, sin dominio
```

## C2. `release.sh` en el servidor

```bash
#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${IMAGE_REF:?IMAGE_REF is required}"
COMPOSE_DIR="${COMPOSE_DIR:?COMPOSE_DIR is required}"
SERVICE="${RELEASE_SERVICE:-app}"
TAG_NAME="${TAG_NAME:-}"
HOST_PORT="${HOST_PORT:-8080}"

if [ -n "${REGISTRY_TOKEN:-}" ] && [ -n "${REGISTRY_USER:-}" ]; then
  CFG="$(mktemp -d)"
  TOK="$(mktemp)"
  chmod 600 "$TOK"
  printf '%s' "$REGISTRY_TOKEN" > "$TOK"
  export DOCKER_CONFIG="$CFG"
  docker login ghcr.io -u "$REGISTRY_USER" --password-stdin < "$TOK"
  trap 'rm -f "$TOK"; docker logout ghcr.io 2>/dev/null; rm -rf "$CFG"' EXIT
fi

export IMAGE_REF
cd "$COMPOSE_DIR"
docker compose pull "$SERVICE"
docker compose up -d --no-deps --no-build "$SERVICE"

if [ -n "$TAG_NAME" ]; then
  for _ in $(seq 1 15); do
    if curl -fsS "http://127.0.0.1:${HOST_PORT}/health" | grep -Fq "$TAG_NAME"; then
      echo "Deploy OK: $TAG_NAME"
      exit 0
    fi
    sleep 2
  done
  echo "Health check failed for $TAG_NAME" >&2
  exit 1
fi
```

**Por qué `compose pull`:**

```
La imagen nueva existe en GHCR después del push.
El compose en disco es solo receta; NO trae la imagen hasta pull.
SIN pull → up reutiliza capas viejas → deploy silenciosamente fallido.
```

## C2. Variables que el SSH step DEBE exportar

```
IMAGE_REF        = IMAGE_NAME + ":" + TAG
COMPOSE_DIR      = "/opt/" + APP_NAME
RELEASE_SERVICE  = "app"   # o web, api — el que TU build reemplaza
TAG_NAME         = TAG     # opcional, para health check
HOST_PORT        = "8080"  # puerto interno para curl /health
REGISTRY_USER    = github.actor
REGISTRY_TOKEN   = secrets.GITHUB_TOKEN
```

## C2. Workflow GitHub Actions — plantilla completa

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: read
  packages: write

env:
  IMAGE_NAME: ghcr.io/TU_ORG/NOMBRE_APP
  COMPOSE_DIR: /opt/NOMBRE_APP
  RELEASE_SERVICE: app
  RELEASE_SCRIPT: /opt/NOMBRE_APP/deploy/release.sh

jobs:
  release:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Test
        run: |
          # AGENT: reemplazar con comando real de tests
          echo "run tests"

      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: ${{ env.IMAGE_NAME }}:${{ github.ref_name }}

      - uses: appleboy/ssh-action@v1.2.0
        env:
          IMAGE_REF: ${{ env.IMAGE_NAME }}:${{ github.ref_name }}
          TAG_NAME: ${{ github.ref_name }}
          COMPOSE_DIR: ${{ env.COMPOSE_DIR }}
          RELEASE_SERVICE: ${{ env.RELEASE_SERVICE }}
          HOST_PORT: "8080"
          REGISTRY_USER: ${{ github.actor }}
          REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          host: ${{ secrets.SSH_HOST }}
          username: ${{ secrets.SSH_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          envs: IMAGE_REF,TAG_NAME,COMPOSE_DIR,RELEASE_SERVICE,HOST_PORT,REGISTRY_USER,REGISTRY_TOKEN
          script: bash ${{ env.RELEASE_SCRIPT }}
```

## C2. Validación final (camino 2)

```
CHECK docker compose ps → servicio RELEASE_SERVICE Up
CHECK servicio db → siguió Up (no recreado)
CHECK curl http://127.0.0.1:HOST_PORT/health → 200
CHECK (opcional) body contiene TAG_NAME
```

---

## 5. Orden de ejecución para el agente (checklist maestro)

```
FASE A — Definición
  [ ] Elegir CAMINO (1 o 2) según árbol de decisión §0
  [ ] Definir APP_NAME (regex válido)
  [ ] Derivar IMAGE_NAME, RELEASE_SCRIPT, COMPOSE_DIR

FASE B — Repo
  [ ] Crear/validar Dockerfile
  [ ] Crear .dockerignore
  [ ] Implementar GET /health → 200
  [ ] Crear .github/workflows/release.yml (plantilla §C1 o §C2)

FASE C — GitHub
  [ ] Crear environment production
  [ ] Configurar secrets: SSH_HOST, SSH_USER, SSH_PRIVATE_KEY
  [ ] Configurar variables según camino (§3.3)
  [ ] Workflow permissions: packages: write

FASE D — Coordinación ServerPilot
  [ ] NOTIFY: APP_NAME + camino
  [ ] WAIT confirmación: /opt/APP_NAME/, release.sh, (C2) bootstrap + prod.env

FASE E — Primer release
  [ ] git tag v0.1.0 && git push origin v0.1.0
  [ ] Verificar pipeline verde
  [ ] (C1) Guardar DEPLOY_PORT en GitHub Variables
  [ ] Associate Site + SSL en dashboard

FASE F — Releases siguientes
  [ ] Solo push tag v* → pipeline automático
  [ ] Verificar /health
```

---

## 6. Anti-patrones (el agente NO debe hacer esto)

```
❌ git pull / rsync del repo al servidor en cada release
❌ docker build en el servidor
❌ build: en compose de producción
❌ compose up sin --no-deps (recrea db)
❌ :latest en producción
❌ secretos de app en GitHub Secrets
❌ PAT de registry guardado en ~/.docker del servidor
❌ publicar en 0.0.0.0
❌ ejecutar deploy antes de que ServerPilot confirme /opt/APP_NAME/
❌ imprimir REGISTRY_TOKEN en logs (no set -x con secrets)
```

---

## 7. Troubleshooting

| Síntoma | Diagnóstico | Acción |
|---------|-------------|--------|
| Misma versión después del deploy | Falta pull | Verificar release.sh hace pull |
| `pull access denied` | Registry privado sin login | Pasar REGISTRY_TOKEN al SSH step |
| db reiniciada | up sin --no-deps | Corregir release.sh camino 2 |
| Puerto Nginx roto (C1) | sp port cada vez | Fijar DEPLOY_PORT en vars |
| `release.sh: not found` | ServerPilot no provisionó | Esperar confirmación equipo SP |
| Health check falla | HOST_PORT o TAG_NAME mal | Alinear con puerto interno real |

---

## 8. Referencia one-liner

```bash
# Camino 1 — debug manual en servidor
export IMAGE_REF=ghcr.io/org/app:v1.0.0 CONTAINER_NAME=app CONTAINER_PORT=8080 DEPLOY_PORT=3042
bash /opt/app/deploy/release.sh

# Camino 2 — debug manual en servidor
export IMAGE_REF=ghcr.io/org/app:v1.0.0 COMPOSE_DIR=/opt/app RELEASE_SERVICE=app TAG_NAME=v1.0.0
bash /opt/app/deploy/release.sh
```
