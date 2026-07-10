# Cómo levantar tu aplicación en ServerPilot

Esta guía es para **equipos de desarrollo y operaciones** que despliegan en un servidor donde ya está instalado ServerPilot (`sp`).

ServerPilot no reemplaza tu código ni tu pipeline de CI/CD: te da **puertos seguros**, **containers visibles**, **Nginx + SSL** y, si lo necesitás, **stacks Docker Compose** administrados.

Hay **dos formas principales** de levantar una aplicación:

| Enfoque | Cuándo usarlo |
|--------|----------------|
| **Container individual** (`sp port` + `docker run`) | Una sola app en un container, deploys simples, imágenes ya construidas en CI |
| **Docker Compose** (`sp compose`) | Varios servicios juntos (web + api + db + redis), `docker-compose.yml` en el repo |

---

## Antes de empezar

### En el servidor (una sola vez)

El administrador del servidor debe haber ejecutado:

```sh
sudo sp setup    # Docker, Nginx, Compose (opcional), credenciales del dashboard
sudo sp start -d # Dashboard en http://IP:8090
```

### Tu acceso

1. Conectate por **SSH** al servidor con tu usuario de deploy (o el que te hayan creado).
2. Verificá que podés usar Docker y `sp`:

```sh
docker --version
sp --version
```

3. Si vas a usar Compose:

```sh
docker compose version
```

Si Compose no está instalado, el admin puede volver a correr `sudo sp setup` y aceptar instalar el plugin, o instalar `docker-compose-plugin` con apt.

### Dónde vive el código

- Apps simples: cualquier ruta; lo habitual es `/opt/<nombre-app>/`.
- **Compose obligatorio bajo `/opt`**: el proyecto debe estar en algo como `/opt/mi-app/` con su `docker-compose.yml` adentro.

---

## Flujo 1 — Container individual (comando `sp`)

Este es el camino clásico: **una imagen Docker, un puerto, un dominio**.

### Resumen del flujo

```
CI construye imagen → SSH al servidor → sp port → docker run → Dashboard: Associate Site → SSL
```

### Paso 1: Entrar al servidor

```sh
ssh deploy@tu-servidor
```

### Paso 2: Reservar un puerto con ServerPilot

ServerPilot asigna un puerto libre en el rango **3000–3999** (por defecto) y evita choques con otros servicios:

```sh
PORT=$(sp port)
echo "Puerto asignado: $PORT"
```

Para otro rango:

```sh
PORT=$(sp port --min 4000 --max 4999)
```

Ver reservas activas:

```sh
sp port --list
```

**Importante:** el puerto queda en `127.0.0.1` del servidor. Nginx (vía ServerPilot) es quien lo expone al mundo con tu dominio.

### Paso 3: Levantar el container

Ejemplo con imagen que ya subiste a un registry:

```sh
docker pull registry.example.com/mi-app:1.2.3

docker run -d \
  --name mi-app \
  --restart unless-stopped \
  -p 127.0.0.1:${PORT}:8080 \
  -e NODE_ENV=production \
  registry.example.com/mi-app:1.2.3
```

Reglas:

- Usá **`-p 127.0.0.1:PUERTO:PUERTO_CONTAINER`** — no publiques en `0.0.0.0` manualmente.
- El puerto del container (`8080` en el ejemplo) debe ser el que escucha tu app dentro de la imagen.
- Usá el `PORT` que devolvió `sp port`.

### Paso 4: Verificar que corre

```sh
docker ps --filter name=mi-app
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:${PORT}/
```

### Paso 5: Asociar dominio en el dashboard

1. Abrí el dashboard de ServerPilot (`http://IP:8090` o el dominio del panel).
2. Pestaña **Docker Containers**.
3. Encontrá tu container → **Associate Site**.
4. Elegí plantilla (**API** o **NestJS** si usás WebSockets).
5. Dominio: `api.midominio.com`.
6. Confirmá y, si querés, habilitá **SSL** desde la pestaña de sitios.

ServerPilot crea el vhost de Nginx apuntando a `127.0.0.1:PUERTO`.

### Paso 6: Actualizar en un release nuevo (CI/CD)

Patrón típico en tu script de deploy:

```sh
#!/bin/sh
set -eu

IMAGE="registry.example.com/mi-app:${VERSION}"
PORT="${DEPLOY_PORT:-$(sp port)}"   # o reutilizá el mismo puerto si ya está reservado

docker pull "$IMAGE"
docker stop mi-app 2>/dev/null || true
docker rm mi-app 2>/dev/null || true

docker run -d \
  --name mi-app \
  --restart unless-stopped \
  -p 127.0.0.1:${PORT}:8080 \
  "$IMAGE"
```

Si el sitio Nginx ya existe y el puerto no cambió, no hace falta tocar el dashboard.

### Réplicas (opcional)

Para clones blue/green de **un solo container** (no Compose), el dashboard ofrece **Create Replica**. No uses réplicas en containers que pertenezcan a un stack Compose.

---

## Flujo 2 — Docker Compose (`sp compose`)

Usá este flujo cuando tu repo trae **`docker-compose.yml`** con varios servicios (web, api, base de datos, colas, etc.).

### Resumen del flujo

```
Código en /opt/mi-app → docker-compose.yml con ${SP_COMPOSE_PORT} → sp compose validate → sp compose deploy → Associate Site (solo servicios públicos)
```

### Reglas que debés respetar

1. **Proyecto bajo `/opt`**, por ejemplo `/opt/mi-app/`.
2. **No uses puertos fijos** en el host (`"8080:80"` está prohibido). Usá variables de ServerPilot.
3. Los puertos públicos se publican solo en **`127.0.0.1`**; ServerPilot los asigna al hacer deploy.
4. Servicios solo con `expose:` son **internos** (no reciben sitio Nginx).
5. No uses `privileged`, `network_mode: host`, montajes de `/`, ni el socket de Docker en el compose.

### Variables de puerto

| Variable | Uso |
|----------|-----|
| `${SP_COMPOSE_PORT}` | Un solo servicio expuesto al público |
| `${SP_COMPOSE_PORT_WEB_8080}` | Varios servicios: `SERVICIO` + `_` + puerto interno |

Convención para varios endpoints: `SP_COMPOSE_PORT_<SERVICE>_<CONTAINER_PORT>` en mayúsculas, con guiones del nombre de servicio reemplazados por `_`.

### Ejemplo de `docker-compose.yml`

```yaml
services:
  web:
    build: .
    ports:
      - "${SP_COMPOSE_PORT}:8080"
    environment:
      API_URL: http://api:3000
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/health"]
      interval: 10s
      timeout: 3s
      retries: 3

  api:
    image: nginx:alpine
    expose:
      - "80"          # interno: no recibe dominio

  db:
    image: postgres:16-alpine
    volumes:
      - db_data:/var/lib/postgresql/data

volumes:
  db_data:
```

`expose` = solo red interna del stack.  
`ports` con `${SP_COMPOSE_PORT...}` = ServerPilot asigna puerto host y luego podés ponerle dominio.

### Paso 1: Subir el proyecto al servidor

```sh
ssh deploy@tu-servidor
sudo mkdir -p /opt/mi-app
sudo chown deploy:deploy /opt/mi-app
cd /opt/mi-app
git clone https://github.com/tu-org/mi-app.git .
# o rsync/scp desde tu máquina
```

### Paso 2: Validar antes de desplegar

```sh
sudo sp compose validate \
  --name mi-app \
  --file /opt/mi-app/docker-compose.yml
```

Con salida JSON (útil en CI):

```sh
sudo sp compose validate \
  --name mi-app \
  --file /opt/mi-app/docker-compose.yml \
  --json
```

Si hay errores de política (puerto fijo, paths fuera de `/opt`, etc.), el comando te los lista **sin levantar nada**.

### Paso 3: Desplegar el stack

```sh
sudo sp compose deploy \
  --name mi-app \
  --file /opt/mi-app/docker-compose.yml \
  --alias "Mi App Producción" \
  --json
```

ServerPilot:

1. Analiza el compose y Dockerfiles.
2. Reserva puertos en `127.0.0.1`.
3. Genera override y archivo de entorno con los puertos.
4. Ejecuta `docker compose up -d`.
5. Registra el proyecto en su inventario.

### Paso 4: Ver estado

```sh
sudo sp compose list --json
sudo sp compose status --name mi-app --json
```

En el dashboard, los containers aparecen agrupados bajo **Compose stack: mi-app**, con el servicio (`web`, `api`, etc.).

### Paso 5: Dominio y SSL (solo servicios publicados)

1. Dashboard → **Docker Containers** → stack **mi-app**.
2. En el servicio que tiene puerto publicado (ej. `web`) → **Associate Site**.
3. Dominio + plantilla + SSL igual que en el flujo de container individual.

Los servicios internos (`db`, `redis`, etc.) **no** deben tener sitio Nginx.

### Paso 6: Release / CI/CD con Compose

Script de deploy en tu pipeline (corre por SSH en el servidor):

```sh
#!/bin/sh
set -eu

cd /opt/mi-app
git fetch --tags
git checkout "${VERSION}"

sudo sp compose validate --name mi-app --file docker-compose.yml
sudo sp compose deploy --name mi-app --file docker-compose.yml --json
```

Cada `deploy` exitoso crea una **nueva generación** del stack. Los sitios Nginx siguen apuntando al puerto reservado mientras el servicio público mantenga el mismo endpoint.

### Paso 7: Clonar el stack completo (staging / blue-green)

Para duplicar **todo** el proyecto (todos los servicios), no un container suelto:

```sh
sudo sp compose clone \
  --parent mi-app \
  --name mi-app-staging \
  --alias "Staging" \
  --non-interactive \
  --json
```

En modo interactivo (dashboard o CLI futura con políticas por volumen), elegís por cada volumen persistente:

| Política | Efecto |
|----------|--------|
| `empty` | Datos nuevos (ideal staging limpio) |
| `copy` | Copia datos del padre (pausa breve de escritores si hace falta) |
| `share` | Mismo volumen (riesgo si ambos escriben; requiere confirmación explícita) |

Si el padre se actualizó y el clon quedó viejo:

```sh
sudo sp compose sync --name mi-app-staging --json
```

Eliminar un stack clonado:

```sh
sudo sp compose delete --name mi-app-staging
```

---

## Prompt / checklist — Docker Compose en ServerPilot

Copiá y completá esto antes de pedir un deploy o armar tu PR:

```text
PROYECTO SERVERPILOT — DOCKER COMPOSE

Nombre del proyecto (sp compose --name): _______________
Ruta en servidor (debe ser bajo /opt):   /opt/_______________
Archivo compose:                        docker-compose.yml
Servicio público (el que lleva dominio): _______________
Puerto interno de ese servicio:         _______________

En docker-compose.yml:
[ ] El servicio público usa ports: "${SP_COMPOSE_PORT}:<puerto-interno}"
    (o ${SP_COMPOSE_PORT_<SERVICE>_<PORT>} si hay varios públicos)
[ ] No hay puertos fijos tipo "8080:80" o "3000:3000"
[ ] Servicios internos usan solo expose: o sin ports
[ ] No hay privileged, network_mode: host, ni montajes de / o docker.sock
[ ] Build context y Dockerfiles están dentro de /opt/<proyecto>/
[ ] Hay healthcheck en el servicio público (recomendado)

Comandos:
  sudo sp compose validate --name <nombre> --file /opt/<app>/docker-compose.yml
  sudo sp compose deploy   --name <nombre> --file /opt/<app>/docker-compose.yml --json

Después del deploy:
[ ] Container público visible en dashboard bajo "Compose stack: <nombre>"
[ ] Associate Site en el servicio correcto (no en db/redis)
[ ] SSL habilitado si aplica

Dominio objetivo: _______________
Plantilla Nginx:  [ ] API  [ ] NestJS (WebSocket)
```

---

## ¿Cuál flujo elijo?

| Pregunta | Respuesta → Flujo |
|----------|-------------------|
| ¿Un solo proceso/container? | **Container + `sp port`** |
| ¿Varios servicios en compose.yml? | **`sp compose`** |
| ¿Solo necesito cambiar la imagen? | Container: `docker pull` + `docker run` |
| ¿Necesito clonar web+api+db juntos? | **`sp compose clone`** |
| ¿Base de datos compartida entre prod y staging? | Evitá `share`; preferí `empty` o `copy` con cuidado |

---

## Errores frecuentes

| Error | Causa | Solución |
|-------|--------|----------|
| `project must live under /opt` | Compose fuera de `/opt` | Mové el proyecto a `/opt/<nombre>/` |
| `must use ${SP_COMPOSE_PORT...}` | Puerto fijo en compose | Reemplazá por la variable de ServerPilot |
| No aparece "Associate Site" | Servicio solo `expose`, sin `ports` | Es interno; solo el servicio con `ports` + deploy recibe sitio |
| `compose containers use stack deploy` | Intentás publish-port en un servicio Compose | Redeploy con `sp compose deploy` |
| Puerto en uso | No usaste `sp port` o `sp compose` | Dejá que ServerPilot asigne el puerto |

---

## Referencia rápida de comandos

```sh
# Container individual
PORT=$(sp port)
docker run -d --name mi-app -p 127.0.0.1:${PORT}:8080 imagen:tag

# Compose
sudo sp compose validate --name APP --file /opt/APP/docker-compose.yml
sudo sp compose deploy   --name APP --file /opt/APP/docker-compose.yml --json
sudo sp compose list --json
sudo sp compose status --name APP --json
sudo sp compose clone --parent APP --name APP-staging --non-interactive
sudo sp compose sync --name APP-staging
sudo sp compose delete --name APP-staging
```

Para más detalle del producto y del dashboard, ver el [README principal](../README.md).
