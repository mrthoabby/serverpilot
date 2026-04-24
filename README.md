# ServerPilot

Dashboard web para gestionar containers Docker y reverse proxies de Nginx en tus servidores. Un solo binario que te permite ver, asociar y configurar servicios con SSL automático desde el navegador.

## Qué hace

ServerPilot se instala en un servidor Linux y te da:

- **Vista de containers Docker** en tiempo real con puertos y estado.
- **Vista de sitios Nginx** con dominio, proxy pass y estado de SSL.
- **Mapeo automático** entre containers Docker y configuraciones Nginx (detecta la relación via reverse proxy).
- **SSL con un clic** usando Let's Encrypt (certbot), con renovación automática.
- **Asociar sitios a containers** eligiendo entre dos plantillas: NestJS (con WebSocket) o API (reverse proxy estándar).
- **Habilitar/deshabilitar sitios** Nginx directamente desde la interfaz.
- **Auto-actualización** del binario desde GitHub.

---

## Instalación rápida

```sh
curl -fsSL https://raw.githubusercontent.com/mrthoabby/serverpilot/master/install.sh | sh
```

El instalador detecta tu OS y arquitectura, descarga el binario correcto, y lo coloca en `/usr/local/bin/sp` (o `~/.local/bin/sp` si no tenés sudo).

### Compilar desde fuente

```sh
git clone https://github.com/mrthoabby/serverpilot.git
cd serverpilot
go build -o sp .
sudo mv sp /usr/local/bin/
```

---

## Uso

### Paso 1: Setup inicial

Ejecutá el asistente de configuración. Esto revisa las dependencias e instala lo que falte:

```sh
sudo sp setup
```

El setup hace dos cosas en orden:

**[1/2] Dependencias** — Verifica que Docker y Nginx estén instalados. Si alguno falta, te pregunta si querés instalarlo (usa `apt-get`). Si ya están instalados, sigue adelante.

**[2/2] Credenciales de admin** — Te pide un usuario y contraseña para el dashboard web. La contraseña se hashea con bcrypt y se guarda en `/etc/serverpilot/config.json` con permisos `0600`.

Ejemplo de salida:

```
=== ServerPilot Setup ===

[1/2] Checking dependencies...
  ✓ Docker is installed
  ✗ Nginx is not installed
  → Install Nginx? [Y/n]: Y
  ✓ Nginx installed successfully
  Dependencies OK.

[2/2] Setting up admin credentials...
  Enter admin username: admin
  Enter admin password: ********
  Confirm password: ********
  ✓ Credentials saved to /etc/serverpilot/config.json

=== Setup Complete ===
Run 'sp start' to launch the web dashboard.
```

### Paso 2: Iniciar el dashboard

```sh
sp start
```

El dashboard queda disponible en `http://IP-DEL-SERVIDOR:8090`. Para usar otro puerto:

```sh
sp start --port 9090
```

Para ejecutarlo en background:

```sh
nohup sp start &
```

O creá un servicio de systemd (ver sección más abajo).

### Paso 3: Acceder al dashboard

Abrí tu navegador y andá a:

```
http://tu-servidor:8090
```

Ingresá el usuario y contraseña que configuraste en el setup. El dashboard tiene tres pestañas:

**Docker Containers** — Muestra todos los containers corriendo con nombre, imagen, estado y puertos. Los containers que no tienen un sitio Nginx asociado muestran un botón "Associate Site".

**Nginx Sites** — Muestra todos los sitios configurados con dominio, puerto, proxy pass, estado de SSL y si está habilitado o no. Desde acá podés habilitar/deshabilitar SSL y activar/desactivar sitios.

**Mappings** — Muestra la relación entre containers y sitios. ServerPilot detecta esta relación analizando los `proxy_pass` de las configs de Nginx y comparándolos con los puertos de los containers. También te muestra containers sin sitio asociado y sitios huérfanos (que apuntan a containers que ya no existen).

### Actualizar ServerPilot

```sh
sp update
```

Descarga la última versión desde GitHub y reemplaza el binario actual. No necesita reiniciar el dashboard manualmente.

### Ver la versión

```sh
sp --version
```

---

## Funcionalidades del dashboard

### Asociar un sitio Nginx a un container Docker

1. Ir a la pestaña "Docker Containers".
2. Encontrar el container que no tiene sitio (muestra botón "Associate Site").
3. Hacer clic en "Associate Site".
4. Seleccionar la plantilla:
   - **NestJS** — Reverse proxy con soporte WebSocket, headers de proxy (`X-Forwarded-For`, `X-Real-IP`, `Upgrade`, `Connection`).
   - **API** — Reverse proxy estándar con headers de rate limiting.
5. Ingresar el dominio (ej: `api.miapp.com`).
6. Confirmar.

ServerPilot automáticamente: crea la config en `/etc/nginx/sites-available/`, la habilita con un symlink en `sites-enabled/`, valida la config con `nginx -t`, y recarga Nginx.

### Habilitar SSL

1. Ir a la pestaña "Nginx Sites".
2. Encontrar el sitio sin SSL (candado rojo).
3. Hacer clic en "Enable SSL".

ServerPilot ejecuta `certbot --nginx -d tu-dominio --non-interactive --agree-tos` para obtener el certificado de Let's Encrypt. La renovación automática queda configurada via el timer de certbot.

### Deshabilitar SSL

Mismo proceso pero con el botón "Disable SSL". Modifica la config de Nginx para remover las directivas SSL y recarga.

### Habilitar/Deshabilitar sitios

Los botones "Enable" y "Disable" en la pestaña "Nginx Sites" crean o eliminan el symlink en `/etc/nginx/sites-enabled/` y recargan Nginx.

---

## Ejecutar como servicio systemd

Para que ServerPilot arranque automáticamente con el servidor:

```sh
sudo tee /etc/systemd/system/serverpilot.service > /dev/null <<EOF
[Unit]
Description=ServerPilot Dashboard
After=network.target docker.service nginx.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sp start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable serverpilot
sudo systemctl start serverpilot
```

Verificar estado:

```sh
sudo systemctl status serverpilot
```

---

## Firewall

Si usás `ufw`, abrí el puerto del dashboard:

```sh
sudo ufw allow 8090/tcp
```

En producción, considerá acceder via SSH tunnel en lugar de exponer el puerto:

```sh
ssh -L 8090:localhost:8090 usuario@tu-servidor
# Luego abrí http://localhost:8090 en tu navegador local
```

---

## Configuración

La configuración se guarda en `/etc/serverpilot/config.json` con permisos `0600` (solo root puede leerlo). Contiene:

- `username` — Nombre de usuario del admin.
- `password_hash` — Hash bcrypt de la contraseña.
- `session_secret` — Secreto para firmar las sesiones (generado con `crypto/rand`).

Para cambiar las credenciales, ejecutá `sp setup` de nuevo.

---

## Estructura del proyecto

```
serverpilot/
├── main.go                         # Punto de entrada
├── version.go                      # Versión actual del binario
├── go.mod                          # Dependencias Go
│
├── cmd/                            # Comandos CLI (Cobra)
│   ├── root.go                     # Comando raíz "sp"
│   ├── setup.go                    # sp setup
│   ├── start.go                    # sp start [--port]
│   └── update.go                   # sp update (auto-actualización)
│
├── internal/
│   ├── deps/                       # Detector e instalador de Docker y Nginx
│   │   └── deps.go
│   ├── auth/                       # Autenticación (bcrypt + sesiones)
│   │   └── auth.go
│   ├── docker/                     # Módulo Docker (listar containers, puertos)
│   │   └── docker.go
│   ├── nginx/                      # Módulo Nginx (parsear configs, sites)
│   │   └── nginx.go
│   ├── mapper/                     # Mapeo Docker ↔ Nginx + gestión SSL
│   │   ├── mapper.go
│   │   └── ssl.go
│   ├── templates/                  # Plantillas Nginx (NestJS, API)
│   │   └── templates.go
│   └── web/                        # Servidor HTTP + dashboard
│       ├── server.go               # Servidor y rutas
│       ├── handlers.go             # Handlers de API REST
│       ├── middleware.go            # Auth, logging, recovery
│       └── static/
│           └── index.html          # Dashboard (HTML/CSS/JS embebido)
│
├── sp-pre-run/                     # Makefile de build y release
│   └── Makefile
├── homebrew/Formula/               # Fórmulas Homebrew
│   └── sp.rb
├── install.sh                      # Script de instalación Linux/macOS
├── install.ps1                     # Nota para Windows (Linux-only)
└── .vscommit                       # Paths para commit selectivo
```

---

## Seguridad

- **Contraseñas** hasheadas con bcrypt (costo por defecto). Nunca se guardan en texto plano.
- **Sesiones** con tokens generados con `crypto/rand` (32 bytes, hex). Cookies `HttpOnly` y `SameSite=Strict`.
- **Ejecución de comandos** con `exec.Command` y argumentos separados. Nunca se usa `sh -c` con input concatenado.
- **Validación de inputs** en todos los endpoints API con regex de allowlist. Se rechazan HTML tags.
- **Prevención de path traversal** en todas las operaciones de archivos (se valida que los paths estén dentro de `/etc/nginx/`).
- **Errores genéricos** en las respuestas API. Los errores internos se loguean server-side.
- **Config con permisos 0600** — Solo root puede leer el archivo de configuración.

---

## API REST

El dashboard usa estos endpoints internamente. Todos requieren autenticación excepto `/api/login`.

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/api/login` | Autenticar con usuario/contraseña |
| POST | `/api/logout` | Cerrar sesión |
| GET | `/api/containers` | Listar containers Docker |
| GET | `/api/sites` | Listar sitios Nginx |
| GET | `/api/mappings` | Mapeo Docker ↔ Nginx |
| POST | `/api/ssl/enable` | Habilitar SSL para un dominio |
| POST | `/api/ssl/disable` | Deshabilitar SSL para un dominio |
| POST | `/api/sites/create` | Crear sitio Nginx desde plantilla |
| POST | `/api/sites/enable` | Habilitar sitio Nginx |
| POST | `/api/sites/disable` | Deshabilitar sitio Nginx |

---

## Build y release

El proyecto usa un sistema de build inspirado en [versionator](https://github.com/mrthoabby/homebrew-versionator). Los binarios se distribuyen via **GitHub Releases**.

### Compilar y subir un release

```sh
# 1. Compilar para todas las plataformas
cd sp-pre-run && make build-all

# Los binarios se generan en release/{VERSION}/
# sp-linux-amd64, sp-linux-arm64, sp-darwin-amd64, sp-darwin-arm64

# 2. Crear el tag y push
git add .
git commit -m "chore: release v1.0.0"
git tag v1.0.0
git push origin main --tags

# 3. Crear el GitHub Release con los binarios
gh release create v1.0.0 release/1.0.0/* --title "v1.0.0" --notes "Initial release"
```

Para crear un release completo (binarios + fórmula Homebrew):

```sh
cd sp-pre-run && make all
```

El `install.sh` y `sp update` descargan los binarios desde `https://github.com/mrthoabby/serverpilot/releases/download/vX.Y.Z/sp-{os}-{arch}`.

---

## Requisitos del servidor

- Linux (Ubuntu 20.04+, Debian 11+, o similar con `apt-get`)
- Docker (se instala automáticamente si falta)
- Nginx (se instala automáticamente si falta)
- Certbot (se instala al habilitar SSL por primera vez)
- Puerto 8090 disponible (configurable)

---

## Contribuir

1. Fork del repositorio.
2. Crear branch: `git checkout -b feature/mi-feature`.
3. Hacer cambios y agregar tests: `go test ./...`.
4. Enviar pull request con descripción clara.

Para cambios grandes, abrir un issue primero para discutir el approach.

## Licencia

MIT License. Ver [LICENSE](LICENSE) para detalles.
