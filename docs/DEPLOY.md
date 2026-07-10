# Cómo preparar tu flujo de GitHub Actions para el CI/CD con ServerPilot

> **Audiencia:** agentes y equipos que configuran el pipeline de deploy.  
> **Objetivo:** preparar tu aplicación y tu workflow para que ServerPilot pueda ejecutar el release automático en el servidor.  
> **Regla de oro:** ServerPilot **no recibe código fuente** en cada release. El CI construye y pushea **imágenes Docker** al registry, copia `deploy/release.sh` **desde el repo de la app** al servidor y lo ejecuta por SSH.

---

## División bootstrap vs cada release

```
BOOTSTRAP (una vez, antes del primer tag):
  ServerPilot / operador:
    - /opt/<APP_NAME>/ existe
    - prod.env en servidor (secretos runtime)
    - (camino 2) docker-compose.yml en servidor + primer compose up
    - usuario SSH deploy + claves
  Equipo app (repo):
    - deploy/release.sh versionado en el repo
    - workflow GitHub Actions

CADA RELEASE (automático, cada tag v*):
  CI en GitHub Actions:
    - build + push imagen
    - scp deploy/release.sh → /opt/<APP_NAME>/deploy/release.sh
    - SSH: export vars + bash release.sh
```

**`release.sh` vive en el repo de la aplicación.** ServerPilot **no** lo instala ni lo mantiene. El CI lo sube en cada deploy para que cambios al script se desplieguen solos.

### Quién levanta qué (regla fija)

| Acción | Camino 1 (Docker simple) | Camino 2 (Compose) |
|--------|--------------------------|---------------------|
| **Levantamiento inicial** (primera vez que algo corre en prod) | **CI + `release.sh`** — `docker pull` + `docker run` en el primer tag | **ServerPilot** — bootstrap: `docker-compose.yml`, `prod.env`, `sp compose deploy` levanta **todo el stack** (app + db + redis, etc.) |
| **Cada release siguiente** | **CI + `release.sh`** — recrea solo el container de la app | **CI + `release.sh`** — `pull` + `up --no-deps` **solo el servicio de la app** |
| **db / redis / workers** | No aplica (un solo container) | **ServerPilot en bootstrap** los levanta; **`release.sh` NUNCA los levanta ni los recrea** |
| **Puertos host compose** | — | **ServerPilot en bootstrap** (`sp compose deploy`); **`release.sh` NO reasigna** |
| **Nginx / dominio / SSL** | **ServerPilot** (panel) | **ServerPilot** (panel) |
| **`prod.env`** | **ServerPilot** (o operador) lo crea antes del primer deploy | **ServerPilot** (o operador) lo crea **antes del bootstrap** |

```
REGLA CAMINO 2:
  ServerPilot levanta el stack completo UNA VEZ (bootstrap) y asigna SP_COMPOSE_PORT_*.
  release.sh del repo SOLO actualiza el servicio de aplicación.
  Si db/redis no están Up, NO es trabajo de release.sh — falta bootstrap ServerPilot.
```

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
INVARIANTE_3: El deploy en prod ocurre EN EL SERVIDOR vía SSH + release.sh (copiado desde el repo en cada release).
INVARIANTE_4: Tags de imagen inmutables: v1.2.3 o sha-abc1234. PROHIBIDO :latest en prod.
INVARIANTE_5: Secretos de runtime (DB, API keys) → prod.env en servidor. NO en GitHub.
INVARIANTE_6: Secretos de conexión (SSH) → GitHub Secrets. NO en prod.env.
INVARIANTE_7: Registry login en servidor es TEMPORAL dentro de release.sh. NO persistir tokens.
INVARIANTE_8: Publicar containers en 127.0.0.1. Nginx (ServerPilot) expone el dominio.
INVARIANTE_9: (camino 2) Puertos host en compose usan ${SP_COMPOSE_PORT...}; ServerPilot asigna valores en bootstrap (sp compose deploy). release.sh NO reasigna puertos.
```

---

## 2. Variables globales que el agente debe definir primero

El agente **elige** `APP_NAME` y lo usa **idéntico** en todos lados:

```
APP_NAME            := "<minúsculas, sin espacios>"     # ej. payments-api
REGISTRY            := "ghcr.io"
ORG                 := "<org o usuario github>"
IMAGE_NAME          := REGISTRY + "/" + ORG + "/" + APP_NAME
RELEASE_SCRIPT_REPO := "deploy/release.sh"              # en el repo — fuente de verdad
RELEASE_SCRIPT_SRV  := "/opt/" + APP_NAME + "/deploy/release.sh"  # destino en servidor (CI lo copia)
COMPOSE_DIR         := "/opt/" + APP_NAME              # solo camino 2
```

**Validación del nombre:**

```
ASSERT APP_NAME matches regex: ^[a-z][a-z0-9-]*$
ASSERT APP_NAME is stable (no fechas, no nombres de persona)
```

**Cuando el agente terminó de configurar GitHub + workflow:**

```
ASSERT deploy/release.sh existe en el repo y está commiteado
NOTIFY ServerPilot team:
  "Deploy listo para provisionar. APP_NAME=<APP_NAME>, CAMINO=<1|2>"
WAIT until ServerPilot confirms:
  - /opt/<APP_NAME>/ exists
  - prod.env listo
  - (camino 2) docker-compose.yml en servidor
  - (camino 2) bootstrap con sp compose deploy hecho (stack Up)
  - (camino 2) mapa de puertos asignados (SP_COMPOSE_PORT_* → host port) documentado
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
| `RELEASE_SCRIPT_REPO` | `deploy/release.sh` | Archivo en el repo |
| `RELEASE_SCRIPT_SRV` | `/opt/payments-api/deploy/release.sh` | Destino que el CI copia por SCP |

**Camino 2:**

| Variable | Ejemplo | Cuándo se conoce |
|----------|---------|------------------|
| `IMAGE_NAME` | `ghcr.io/org/payments-api` | Al definir APP_NAME |
| `COMPOSE_DIR` | `/opt/payments-api` | Al definir APP_NAME |
| `RELEASE_SERVICE` | `app` | Nombre del servicio que TU imagen reemplaza |
| `RELEASE_SCRIPT_REPO` | `deploy/release.sh` | Archivo en el repo |
| `RELEASE_SCRIPT_SRV` | `/opt/payments-api/deploy/release.sh` | Destino que el CI copia por SCP |

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

  STEP 5 — copiar release.sh al servidor
    ASSERT archivo existe en repo: deploy/release.sh
    SCP: RELEASE_SCRIPT_REPO → RELEASE_SCRIPT_SRV en el servidor
    chmod 700 RELEASE_SCRIPT_SRV

  STEP 6 — deploy via SSH
    CONECTAR: SSH_USER@SSH_HOST con SSH_PRIVATE_KEY
    EXPORTAR env vars (ver sección del camino elegido)
    EJECUTAR: bash RELEASE_SCRIPT_SRV
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
BOOTSTRAP (una vez — ServerPilot prepara el servidor):
  ServerPilot: /opt/APP_NAME/, usuario SSH, (opcional) prod.env
  Equipo app: deploy/release.sh en el repo

PRIMER RELEASE (CI + release.sh levanta el container):
  release.sh: sp port (si hace falta) + docker pull + docker run

CADA RELEASE SIGUIENTE (CI + release.sh):
  docker pull + docker run (mismo DEPLOY_PORT fijo en GitHub Variables)

[ServerPilot/Nginx] -----------> dominio público → 127.0.0.1:DEPLOY_PORT
```

## C1. Archivos que el agente crea en el repo

```
REPO/
  Dockerfile              # OBLIGATORIO
  .dockerignore           # OBLIGATORIO
  deploy/release.sh       # OBLIGATORIO — script de deploy en el servidor
  .github/workflows/release.yml
```

**Dockerfile — requisitos mínimos:**

```
MUST expose exactly one application port (ej. EXPOSE 8080)
MUST define CMD o ENTRYPOINT que escuche en ese puerto
MUST NOT bake secrets en la imagen
```

## C1. `deploy/release.sh` en el repo (la app lo versiona)

El CI copia este archivo a `/opt/<APP_NAME>/deploy/release.sh` en cada release.

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
  RELEASE_SCRIPT_SRV: /opt/NOMBRE_APP/deploy/release.sh

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

      - name: Upload release script
        uses: appleboy/scp-action@v1.0.0
        with:
          host: ${{ secrets.SSH_HOST }}
          username: ${{ secrets.SSH_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          source: deploy/release.sh
          target: ${{ env.RELEASE_SCRIPT_SRV }}

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
          script: |
            chmod 700 ${{ env.RELEASE_SCRIPT_SRV }}
            bash ${{ env.RELEASE_SCRIPT_SRV }}
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
BOOTSTRAP (una vez — ServerPilot levanta TODO el stack):
  ServerPilot / operador:
    crear /opt/APP_NAME/docker-compose.yml  (sin build:)
    crear /opt/APP_NAME/prod.env
    sp compose deploy (panel o API) → reserva puertos, escribe SP_COMPOSE_PORT_*,
      genera override 127.0.0.1, compose up de TODOS los servicios
    entregar mapa: servicio → env var → host port (ej. app → SP_COMPOSE_PORT → 3042)
  Equipo app:
    deploy/release.sh en el repo (aún no se ejecuta en bootstrap)

CADA RELEASE (CI + release.sh — SOLO el servicio de la app):
  build push imagen solo de TU servicio
  scp deploy/release.sh → servidor
  SSH → release.sh (del repo):
    export IMAGE_REF=...
    docker compose pull RELEASE_SERVICE
    docker compose up -d --no-deps --no-build RELEASE_SERVICE

  db/redis/workers: YA estaban Up desde bootstrap — release.sh NO los toca
```

## C2. División de responsabilidades

| Componente | Quién lo levanta (primera vez) | Quién lo actualiza (cada release) |
|------------|--------------------------------|-------------------------------------|
| Tu app (`app`, `web`) | **ServerPilot** (bootstrap compose up) | **CI + `release.sh`** — `pull` + `up --no-deps` |
| Postgres, Redis, workers, etc. | **ServerPilot** (bootstrap compose up) | **Nadie** — siguen corriendo; no se recrean |
| docker-compose.yml en servidor | **ServerPilot** | **Nadie** — estable |
| deploy/release.sh | **Equipo app** (en el repo) | **CI** lo copia y ejecuta |
| prod.env | **ServerPilot** / operador | **Nadie** en CI — solo cambios manuales |
| Nginx / dominio / SSL | **ServerPilot** | **Nadie** en CI |

| Componente | Quién lo construye en CI (imagen) |
|------------|-----------------------------------|
| Tu app | SÍ — `docker build` |
| Postgres, Redis, etc. | NO — imagen pública fija en el manifiesto del servidor |

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
PROHIBIDO puertos host fijos (ej. "3042:8080") — solo ${SP_COMPOSE_PORT...}
IMAGE_REF solo en el servicio que TU CI construye
ports: + ${SP_COMPOSE_PORT...} → servicio público (Nginx)
expose: → interno, sin dominio
Bootstrap SIEMPRE con sp compose deploy — NO docker compose up manual sin ServerPilot
```

## C2.1 Puertos Compose — uno o varios servicios públicos

ServerPilot asigna **un puerto host distinto** por cada endpoint publicado (máx. **16** por proyecto).

### Convención de variables

| Caso | Variable en el manifiesto | Ejemplo valor tras bootstrap |
|------|---------------------------|------------------------------|
| **1 solo** servicio público | `SP_COMPOSE_PORT` | `SP_COMPOSE_PORT=3042` |
| **Varios** servicios públicos | `SP_COMPOSE_PORT_<SERVICIO>_<PUERTO_CONTAINER>` | `SP_COMPOSE_PORT_APP_8080=3042`, `SP_COMPOSE_PORT_ADMIN_3000=3043` |

Reglas de naming (ServerPilot las aplica al analizar el compose):

```
SERVICIO en mayúsculas, guiones → guión bajo (app-api → APP_API)
PUERTO = puerto interno del container (8080, 3000, etc.)
```

### Qué hace ServerPilot en bootstrap (`sp compose deploy`)

```
1. Analiza cada ports: con ${SP_COMPOSE_PORT...}
2. Reserva un puerto en 3000–3999 por endpoint (portalloc)
3. Escribe serverpilot.env con todas las SP_COMPOSE_PORT_*=####
4. Genera override con 127.0.0.1:${VAR}:puerto_container
5. Persiste el mapa en el registry compose (servicio, env_var, host_port)
6. Ejecuta compose up de todo el stack
```

**`release.sh` NO toca puertos.** Solo actualiza la imagen del servicio CI. Los `SP_COMPOSE_PORT_*` quedan fijos desde el bootstrap.

### Manifiesto — varios servicios públicos (ejemplo)

```yaml
services:
  app:
    image: ${IMAGE_REF:?IMAGE_REF is required}
    env_file:
      - /opt/NOMBRE_APP/prod.env
    ports:
      - "${SP_COMPOSE_PORT_APP_8080}:8080"

  admin:
    image: ghcr.io/org/admin-panel:1.0.0   # imagen fija si no la construye este CI
    env_file:
      - /opt/NOMBRE_APP/prod.env
    ports:
      - "${SP_COMPOSE_PORT_ADMIN_3000}:3000"

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

Si solo hay **un** endpoint público, podés usar la forma corta `${SP_COMPOSE_PORT}:8080` (ServerPilot normaliza a `SP_COMPOSE_PORT`).

### Nginx — un dominio por servicio público

```
Por cada servicio con puerto host asignado:
  Associate Site en dashboard → 127.0.0.1:<host_port del registry>
  (ej. app → 3042, admin → 3043 en dominios distintos)
```

Consultar mapa asignado: panel Compose / `GET /api/compose/projects` → `endpoints[]` con `service`, `env_var`, `host_port`.

### Checklist bootstrap puertos (camino 2)

```
[ ] Manifiesto usa ${SP_COMPOSE_PORT...} en cada ports: público
[ ] sp compose deploy completado (no compose up manual)
[ ] docker compose ps → app + db (+ admin si aplica) Up
[ ] Mapa documentado: servicio / env_var / host_port
[ ] Associate Site hecho por cada endpoint que necesita dominio
[ ] Recién entonces habilitar workflow de release
```

---

## C2.2 `deploy/release.sh` en el repo (la app lo versiona)

**Importante:** este script **no hace bootstrap**. Asume que ServerPilot **ya levantó** el stack completo (app + dependencias). Solo actualiza el servicio `RELEASE_SERVICE`.

El CI copia este archivo a `/opt/<APP_NAME>/deploy/release.sh` en cada release.

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
  RELEASE_SCRIPT_SRV: /opt/NOMBRE_APP/deploy/release.sh

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

      - name: Upload release script
        uses: appleboy/scp-action@v1.0.0
        with:
          host: ${{ secrets.SSH_HOST }}
          username: ${{ secrets.SSH_USER }}
          key: ${{ secrets.SSH_PRIVATE_KEY }}
          source: deploy/release.sh
          target: ${{ env.RELEASE_SCRIPT_SRV }}

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
          script: |
            chmod 700 ${{ env.RELEASE_SCRIPT_SRV }}
            bash ${{ env.RELEASE_SCRIPT_SRV }}
```

## C2. Validación final (camino 2)

```
CHECK docker compose ps → servicio RELEASE_SERVICE Up
CHECK servicio db → siguió Up (no recreado)
CHECK curl http://127.0.0.1:HOST_PORT/health → 200
CHECK (opcional) body contiene TAG_NAME
CHECK mapa puertos sin cambios (mismos SP_COMPOSE_PORT_* que en bootstrap)
CHECK (multi-puerto) cada servicio público responde en su host_port del registry
```

---

## 5. Orden de ejecución para el agente (checklist maestro)

```
FASE A — Definición
  [ ] Elegir CAMINO (1 o 2) según árbol de decisión §0
  [ ] Definir APP_NAME (regex válido)
  [ ] Derivar IMAGE_NAME, RELEASE_SCRIPT_REPO, RELEASE_SCRIPT_SRV, COMPOSE_DIR

FASE B — Repo
  [ ] Crear/validar Dockerfile
  [ ] Crear .dockerignore
  [ ] Crear deploy/release.sh (plantilla §C1 o §C2)
  [ ] Implementar GET /health → 200
  [ ] Crear .github/workflows/release.yml (plantilla §C1 o §C2)

FASE C — GitHub
  [ ] Crear environment production
  [ ] Configurar secrets: SSH_HOST, SSH_USER, SSH_PRIVATE_KEY
  [ ] Configurar variables según camino (§3.3)
  [ ] Workflow permissions: packages: write

FASE D — Coordinación ServerPilot
  [ ] NOTIFY: APP_NAME + camino + (C2) cantidad de servicios públicos
  [ ] WAIT confirmación: /opt/APP_NAME/, prod.env, (C2) compose + sp compose deploy
  [ ] (C2) Recibir mapa puertos (servicio → host_port) antes del primer tag

FASE E — Primer release
  [ ] git tag v0.1.0 && git push origin v0.1.0
  [ ] Verificar pipeline verde
  [ ] (C1) Guardar DEPLOY_PORT en GitHub Variables
  [ ] Associate Site + SSL en dashboard (C2: uno por cada servicio público)

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
❌ ejecutar deploy antes de que ServerPilot confirme /opt/APP_NAME/ y prod.env
❌ release.sh solo en el servidor sin versionarlo en el repo
❌ docker compose up manual en bootstrap sin sp compose deploy (puertos no quedan registrados)
❌ puertos host fijos en docker-compose.yml de producción
❌ imprimir REGISTRY_TOKEN en logs (no set -x con secrets)
```

---

## 7. Troubleshooting

| Síntoma | Diagnóstico | Acción |
|---------|-------------|--------|
| Misma versión después del deploy | Falta pull | Verificar release.sh hace pull |
| `pull access denied` | Registry privado sin login | Pasar REGISTRY_TOKEN al SSH step |
| db reiniciada | up sin --no-deps en release.sh | Corregir release.sh; el levantamiento de db es bootstrap ServerPilot, no CI |
| Stack no corre antes del primer tag (C2) | Bootstrap ServerPilot pendiente | Completar sp compose deploy antes de habilitar workflow |
| Puertos compose mal / Nginx 502 (C2) | Bootstrap sin sp compose deploy o puerto fijo | Usar ${SP_COMPOSE_PORT...} + sp compose deploy; ver mapa en registry |
| Dos servicios, dominio equivocado (C2) | Falta Associate por servicio | Un site Nginx por host_port público del registry |
| Puerto Nginx roto (C1) | sp port cada vez | Fijar DEPLOY_PORT en vars |
| `release.sh: not found` | Falta en repo o falló el SCP | Verificar `deploy/release.sh` y step Upload release script |
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

# Copiar release.sh del repo al servidor (mismo paso que hace el CI)
scp deploy/release.sh deploy@servidor:/opt/app/deploy/release.sh
```

---

## 9. Prompt para apps legacy — crear `deploy/release.sh` (Camino 2 Compose)

Copiá este bloque y dáselo al agente o al equipo que migra una app vieja:

```text
Tarea: crear deploy/release.sh en ESTE repositorio para el flujo CI/CD ServerPilot (Camino 2 — Docker Compose).

=== QUIÉN LEVANTA QUÉ (NO NEGOCIABLE) ===

ServerPilot (bootstrap, UNA VEZ, antes del primer tag):
  - Crea /opt/<APP_NAME>/docker-compose.yml y prod.env
  - Ejecuta sp compose deploy → levanta TODO el stack, asigna SP_COMPOSE_PORT_* por endpoint
  - Entrega mapa servicio → env_var → host_port (registry compose)
  - Configura Nginx/SSL (un site por servicio público)

CI + deploy/release.sh (CADA tag v*):
  - Build + push de la imagen de TU servicio
  - Copia release.sh al servidor y lo ejecuta
  - SOLO hace: compose pull + up --no-deps --no-build del servicio RELEASE_SERVICE

release.sh NO hace bootstrap. NO levanta db, redis ni workers.
Si esas dependencias no están Up, el problema es bootstrap ServerPilot — no arreglar con compose up sin --no-deps.

=== CONTEXTO ===

- ServerPilot NO recibe código fuente en cada release.
- GitHub Actions: build → push imagen a GHCR → scp deploy/release.sh al servidor → SSH ejecuta el script.
- En el servidor DEBE existir ya (bootstrap ServerPilot completado):
  - /opt/<APP_NAME>/docker-compose.yml  (manifiesto estable, sin build:)
  - /opt/<APP_NAME>/prod.env            (secretos runtime, NO en GitHub)
  - stack completo corriendo (docker compose ps → app + db/etc. Up)
  - SP_COMPOSE_PORT_* ya asignados (release.sh NO los cambia)
- Cada release SOLO actualiza el servicio de la aplicación; db/redis/workers NO se recrean.

Datos de esta app (completar antes de ejecutar):
  APP_NAME=________________
  RELEASE_SERVICE=________________     # servicio en docker-compose que usa IMAGE_REF (ej. app, web, api)
  COMPOSE_DIR=/opt/<APP_NAME>
  HOST_PORT=________________         # puerto interno para health check (ej. 8080)
  HEALTH_PATH=/health                # o la ruta real
  REGISTRY=ghcr.io/<org>/<APP_NAME>

El script deploy/release.sh DEBE:
1. Usar set -euo pipefail
2. Exigir IMAGE_REF y COMPOSE_DIR por env
3. Aceptar RELEASE_SERVICE (default: app)
4. Login registry EFÍMERO si vienen REGISTRY_USER + REGISTRY_TOKEN (mktemp, trap cleanup, docker logout)
5. export IMAGE_REF
6. cd "$COMPOSE_DIR"
7. docker compose pull "$RELEASE_SERVICE"
8. docker compose up -d --no-deps --no-build "$RELEASE_SERVICE"
9. Opcional: si TAG_NAME está definido, curl a http://127.0.0.1:${HOST_PORT}${HEALTH_PATH} hasta 15 intentos

PROHIBIDO en release.sh:
- git pull, rsync, npm install, docker build en el servidor
- compose up SIN --no-deps (recrearía db — eso es bootstrap, no release)
- compose up de servicios que no sean RELEASE_SERVICE
- levantar el stack por primera vez (bootstrap) — eso es ServerPilot
- guardar tokens en ~/.docker del servidor
- usar :latest

Entregables:
1. Archivo deploy/release.sh ejecutable (chmod +x en repo)
2. Lista de variables que el workflow debe exportar en el step SSH
3. Si falta GET /health, indicar qué endpoint usar o proponer uno mínimo

Plantilla base (adaptar, no copiar ciego):

#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${IMAGE_REF:?IMAGE_REF is required}"
COMPOSE_DIR="${COMPOSE_DIR:?COMPOSE_DIR is required}"
SERVICE="${RELEASE_SERVICE:-app}"
TAG_NAME="${TAG_NAME:-}"
HOST_PORT="${HOST_PORT:-8080}"
HEALTH_PATH="${HEALTH_PATH:-/health}"

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
    if curl -fsS "http://127.0.0.1:${HOST_PORT}${HEALTH_PATH}" | grep -Fq "$TAG_NAME"; then
      echo "Deploy OK: $TAG_NAME"
      exit 0
    fi
    sleep 2
  done
  echo "Health check failed for $TAG_NAME" >&2
  exit 1
fi

Referencia completa: docs/DEPLOY.md secciones C2 y §4.
```
