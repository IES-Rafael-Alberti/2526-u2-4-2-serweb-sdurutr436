# DESPLIEGUE — Evidencias y respuestas

Este documento recopila todas las evidencias y respuestas de la practica.

---

## Parte 1 — Evidencias minimas

### Fase 1: Instalacion y configuracion

1) Servicio Nginx activo
- Que demuestra: que el contenedor de Nginx está en ejecución y accesible, demostrando que el servicio web está operativo en el puerto 8080.
- Comando: `docker compose ps` — lista los contenedores en ejecución del proyecto Docker Compose, mostrando el estado "Up" del contenedor p41_web.
- Evidencia: ![Servicio activo con docker compose ps](evidencias/evidencias-checklist/comprobacion-docker-compose-ps.png)

2) Configuracion cargada
- Que demuestra: que el archivo de configuración `default.conf` ha sido correctamente inyectado en el contenedor Nginx en la ruta `/etc/nginx/conf.d/default.conf`, confirmando que la configuración personalizada está siendo aplicada.
- Comando: `docker compose exec web cat /etc/nginx/conf.d/default.conf` — ejecuta un comando dentro del contenedor web para mostrar el contenido del archivo de configuración cargado.
- Evidencia: ![Configuracion cargada](evidencias/evidencias-checklist/comprobacion-listado-conf.png)

3) Resolucion de nombres
- Que demuestra: que el sistema resuelve correctamente la URL `p41.local` hacia localhost (127.0.0.1), permitiendo acceder al servidor web usando un nombre de dominio en lugar de la dirección IP, lo cual es útil para simular un entorno de producción.
- Evidencia: ![Comandos de Windows para la resolución de nombres](evidencias/evidencias-checklist/comandos-para-añadir-p41.local.png) — muestra los comandos en PowerShell para añadir la entrada en el archivo `hosts` de Windows.
- Evidencia: ![Acceso a través de p41.local](evidencias/evidencias-checklist/acceso-a-traves-de-p41-hosts.png) — demuestra que la página es accesible a través de `p41.local:8080`.

4) Contenido Web
- Que demuestra: que el contenido web (sitio estático de CloudAcademy) ha sido correctamente desplegado en la carpeta compartida `./www` y es servido por Nginx en el puerto 8080, mostrando que la página principal personalizada se carga en lugar de la página por defecto de Nginx.
- Evidencia: ![Pagina CloudAcademy en 8080](evidencias/evidencias-checklist/demostracion-pagina-8080.png)

### Fase 2: Transferencia SFTP (Filezilla)

5) Conexion SFTP exitosa
- Que demuestra: que el cliente SFTP (FileZilla) es capaz de conectarse exitosamente al contenedor SFTP expuesto en el puerto 2222, utilizando las credenciales configuradas (usuario `daw`, contraseña `1234`), demostrando que el servicio SFTP está funcionando correctamente.
- Evidencia: ![Conexion filezilla correcta](evidencias/evidencias-checklist/filezilla-conexion-correcta.png)

6) Permisos de escritura
- Que demuestra: que el usuario SFTP (`daw`) tiene permisos de escritura en el directorio `/home/daw/upload` del contenedor SFTP, permitiendo subir archivos sin errores de "Permission denied", demostrando que la configuración de permisos en el contenedor es correcta.
- Evidencia: ![Pagina de Reloj añadida con permisos de escritura](evidencias/pagina-reloj-desde-filezilla.png)

### Fase 3: Infraestructura Docker

7) Contenedores activos
- Que demuestra: que ambos contenedores (p41_web para Nginx y p41_sftp para SFTP) están en ejecución simultáneamente y con sus puertos correctamente mapeados (8080:80 para HTTP, 8443:443 para HTTPS, y 2222:22 para SFTP), demostrando que la infraestructura Docker está completamente operativa.
- Comando: `docker compose ps` — lista todos los contenedores del proyecto mostrando su estado, puertos expuestos y nombres.
- Evidencia: ![Contenedores funcionando simultaneamente](evidencias/recreacion-contenedores-docker.png)

8) Persistencia (Volumen compartido)
- Que demuestra: que el volumen compartido entre los contenedores Nginx y SFTP (mapeo `./www:/home/daw/upload` en SFTP y `./www:/usr/share/nginx/html` en Nginx) funciona correctamente, permitiendo que los archivos subidos por SFTP aparezcan inmediatamente disponibles en el servidor web sin necesidad de reiniciar ningún contenedor.
- Evidencia: ![Contenido de reloj sincronizado](evidencias/reloj-funcionando-8080.png) — demuestra que después de subir los archivos de la página de reloj por SFTP, están inmediatamente disponibles en `http://localhost:8080/reloj`.

9) Despliegue multi-sitio
- Que demuestra: que Nginx puede servir múltiples sitios web desde un único contenedor usando rutas diferentes, demostrando que tanto el sitio principal en la raíz (`/`) como el sitio secundario en una subcarpeta (`/reloj`) funcionan simultáneamente con su propio contenido independiente.
- Evidencia: ![Reloj desde filezilla en subcarpeta](evidencias/reloj-desde-filezilla.png) — muestra la estructura de carpetas en SFTP con la carpeta `/reloj` creada como subcarpeta.
- Evidencia: ![Reloj funcionando en localhost:8080/reloj](evidencias/reloj-funcionando-8080.png) — demuestra que la aplicación está accesible en la ruta `/reloj`.

### Fase 4: Seguridad HTTPS

10) Cifrado SSL
- Que demuestra: que el servidor Nginx está configurado para servir contenido por HTTPS utilizando certificados SSL autofirmados (nginx-selfsigned.crt y nginx-selfsigned.key), demostrando que las comunicaciones entre el cliente y el servidor están cifradas.
- Evidencia: ![Acceso HTTPS funcionando](evidencias/conexion-certificado-indica-no-seguro.png) — muestra que el servidor responde por HTTPS (el navegador indica que el certificado es autofirmado y no es de una autoridad confiable).

11) Redireccion forzada
- Que demuestra: que el servidor Nginx está configurado para redirigir automáticamente todas las solicitudes HTTP (puerto 80) hacia HTTPS (puerto 443) con un código de respuesta 301 (redirección permanente), demostrando una política de seguridad que obliga a usar conexiones cifradas.
- Evidencia: ![Código 301 en las herramientas de desarrollador](evidencias/evidencia-301.png) — muestra en la pestaña Network del navegador que la solicitud a `http://localhost:8080` retorna un código 301 que redirige a `https://localhost:8443`.

---

## Parte 2 — Evaluacion RA2 (a–j)

### a) Parametros de administracion
- Respuesta: Los parámetros de administración más importantes de Nginx están configurados en `/etc/nginx/nginx.conf`. A continuación se detallan las directivas clave localizadas:

**1. worker_processes** (línea 3: `worker_processes auto;`)
- **Qué controla:** Define el número de procesos worker que Nginx ejecuta para atender peticiones. El valor `auto` ajusta automáticamente el número según los núcleos del CPU disponibles.
- **Configuración incorrecta:** Establecer `worker_processes 1;` en un servidor con múltiples núcleos limitaría el rendimiento, ya que solo un core procesaría todas las peticiones, creando un cuello de botella en servidores con alta concurrencia.
- **Cómo comprobarlo:** `grep -n worker_processes /etc/nginx/nginx.conf` y validar con `nginx -t`.

**2. worker_connections** (línea 5: `worker_connections 1024;`)
- **Qué controla:** Número máximo de conexiones simultáneas que puede manejar cada proceso worker. Con 1024 conexiones por worker, si tienes 4 workers, soportas hasta 4096 conexiones concurrentes.
- **Configuración incorrecta:** Establecer `worker_connections 10;` causaría errores "worker_connections are not enough" en los logs cuando se alcancen más de 10 conexiones simultáneas por worker, rechazando nuevas peticiones.
- **Cómo comprobarlo:** `grep -n worker_connections /etc/nginx/nginx.conf` y monitorizar logs con `tail -f /var/log/nginx/error.log`.

**3. access_log** (línea 10: `access_log /var/log/nginx/access.log;`)
- **Qué controla:** Ruta del archivo donde se registran todas las peticiones HTTP exitosas (GET, POST, códigos 200, 301, 404, etc.), incluyendo IP, método, URL y código de respuesta.
- **Configuración incorrecta:** Establecer `access_log off;` desactivaría completamente el registro de accesos, imposibilitando auditorías, análisis de tráfico o detección de patrones de ataque.
- **Cómo comprobarlo:** `ls -lh /var/log/nginx/access.log` y verificar que el archivo crece con `tail -f /var/log/nginx/access.log` mientras se generan peticiones.

**4. error_log** (línea 15: `error_log /var/log/nginx/error.log warn;`)
- **Qué controla:** Ruta y nivel de verbosidad del log de errores (debug, info, notice, warn, error, crit, alert, emerg). El nivel `warn` registra advertencias y errores más graves.
- **Configuración incorrecta:** Establecer `error_log /dev/null;` descartaría todos los errores, dificultando enormemente el diagnóstico de problemas de configuración, permisos o caídas del servicio.
- **Cómo comprobarlo:** `tail -f /var/log/nginx/error.log` y provocar un error (ej: solicitar una ruta inexistente o crear un error de sintaxis en la configuración).

**5. keepalive_timeout** (línea 22: `keepalive_timeout 65;`)
- **Qué controla:** Tiempo en segundos que el servidor mantiene abierta una conexión HTTP persistente esperando nuevas peticiones del mismo cliente antes de cerrarla.
- **Configuración incorrecta:** Establecer `keepalive_timeout 0;` desactivaría las conexiones persistentes, obligando a crear una nueva conexión TCP para cada recurso (HTML, CSS, JS, imágenes), aumentando drásticamente la latencia y el uso de CPU.
- **Cómo comprobarlo:** `grep -n keepalive_timeout /etc/nginx/nginx.conf` y observar los headers HTTP con `curl -I` (buscar `Connection: keep-alive`).

**6. include** (líneas 27 y 29: `include /etc/nginx/mime.types;` e `include /etc/nginx/conf.d/*.conf;`)
- **Qué controla:** Permite cargar configuración desde archivos externos. `mime.types` define los tipos MIME (text/html, image/png, etc.) y `conf.d/*.conf` carga configuraciones de sitios virtuales.
- **Configuración incorrecta:** Omitir `include /etc/nginx/mime.types;` haría que Nginx sirva todos los archivos como `application/octet-stream`, provocando que los navegadores descarguen archivos CSS/JS en lugar de interpretarlos.
- **Cómo comprobarlo:** `ls -l /etc/nginx/conf.d/` para verificar archivos cargados y `curl -I http://localhost` para inspeccionar el header `Content-Type`.

**7. gzip** (línea 31: `# gzip on;`)
- **Qué controla:** Activa la compresión gzip de respuestas HTTP, reduciendo el ancho de banda y mejorando tiempos de carga. Está comentado por defecto en nginx:alpine.
- **Configuración incorrecta:** Activar `gzip on;` sin especificar `gzip_types` limitaría la compresión solo a `text/html`, desperdiciando la oportunidad de comprimir CSS, JavaScript y JSON.
- **Cómo comprobarlo:** `curl -H "Accept-Encoding: gzip" -I http://localhost` y buscar el header `Content-Encoding: gzip` en la respuesta.

**Cambio aplicado:**
Se validó la configuración por defecto de `keepalive_timeout 65;` ejecutando `nginx -t` para verificar la sintaxis y `nginx -s reload` para aplicar cualquier cambio en la configuración de forma segura sin interrumpir el servicio. No se realizó modificación del valor ya que 65 segundos es óptimo para aplicaciones web estáticas.

- Evidencias:

![Grep de nginxconf](evidencias/evidencias-parte2/a-01-grep-nginxconf.png)

![Nginx estado](evidencias/evidencias-parte2/a-02-nginx-t.png)

![Reload del contenedor](evidencias/evidencias-parte2/a-03-reload.png)

### b) Ampliacion de funcionalidad + modulo investigado
- Opcion elegida (B1 o B2): **B2 - Cabeceras de seguridad HTTP**
- Respuesta: Se implementó la ampliación de funcionalidad mediante la configuración de cabeceras HTTP de seguridad personalizadas. Se agregaron tres cabeceras esenciales: `X-Content-Type-Options: nosniff` para prevenir ataques de MIME-sniffing donde el navegador intenta "adivinar" el tipo de contenido; `X-Frame-Options: DENY` para prevenir ataques de clickjacking impidiendo que la página se cargue en un iframe; y `Content-Security-Policy` para controlar qué recursos pueden cargarse en la página, mitigando ataques XSS (Cross-Site Scripting). Estas cabeceras se configuran directamente en el bloque `server` de `default.conf` usando la directiva `add_header` con el flag `always` para asegurar que se incluyan en todas las respuestas.
- Evidencias (B1 o B2):

```bash
  # Cabeceras de seguridad
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "DENY" always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
```

![Estado de nginx](evidencias/evidencias-parte2/b-02-nginx-t.png)

![Curl de los heads](evidencias/evidencias-parte2/b-03-curl-http-headers.png)

#### Modulo investigado: Modulos de Headers de Seguridad HTTP
- Para que sirve: Estos módulos permiten agregar headers HTTP personalizados a las respuestas del servidor para mejorar la seguridad. Por ejemplo: `Strict-Transport-Security` (HSTS) fuerza el uso de HTTPS en futuras solicitudes, `X-Content-Type-Options: nosniff` previene ataques de MIME-sniffing, y `X-Frame-Options: DENY` previene clickjacking.
- Como se instala/carga: Los módulos de headers están compilados de forma nativa en la imagen `nginx:alpine`. Se configuran agregando directivas como `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` en los bloques `server` o `location` del archivo de configuración `default.conf`.
- Fuente(s): Documentación oficial de Nginx - http://nginx.org/en/docs/http/ngx_http_headers_module.html

### c) Sitios virtuales / multi-sitio
- Respuesta: Se ha implementado un despliegue multi-sitio donde Nginx sirve dos aplicaciones web independientes desde el mismo contenedor: la aplicación principal (CloudAcademy) en la raíz (`/`) y una aplicación secundaria (Reloj) en la subcarpeta (`/reloj`). Ambos sitios comparten el mismo **volumen nombrado `shared-data`** definido en `docker-compose.yml`, que se monta en `/usr/share/nginx/html` (Nginx) y `/home/daw/upload` (SFTP). Los sitios se acceden a través del mismo host pero en rutas diferentes, siendo un ejemplo de **multi-sitio por path** (basado en rutas) en lugar de por nombre de dominio.

**Diferencias entre tipos de multi-sitio:**
- **Multi-sitio por path:** Usa la misma dirección IP/dominio pero diferentes rutas (ej: `localhost:8443/` y `localhost:8443/reloj`). Se configura con bloques `location` en el mismo `server` block.
- **Multi-sitio por nombre (server_name):** Múltiples dominios apuntando a la misma IP, cada uno con su propio `server` block diferenciado por la directiva `server_name` (ej: `site1.com` y `site2.com`).

**Otros tipos de multi-sitio:**
- **Por puerto:** Diferentes aplicaciones escuchando en puertos distintos (ej: `listen 80;` vs `listen 8080;`), cada uno con su propio `server` block.
- **Por IP:** Servidor con múltiples IPs, cada aplicación configurada con `listen IP:puerto;` específico.
- **Por subdominios:** Variante de multi-sitio por nombre usando subdominios (ej: `blog.example.com`, `shop.example.com`), diferenciados con `server_name` usando wildcards o nombres explícitos.

**Configuración activa en default.conf:**
```nginx
server {
  listen 443 ssl;
  server_name localhost;
  
  root /usr/share/nginx/html;  # Directorio raíz donde están los archivos
  index index.html;             # Archivo por defecto
  
  location / {                  # Bloque para el sitio principal
    try_files $uri $uri/ =404;  # Intenta servir archivo, luego directorio, sino 404
  }
  
  location /reloj {             # Bloque específico para la aplicación en /reloj
    try_files $uri $uri/ =404;  # Busca archivos en /usr/share/nginx/html/reloj/
  }
}
```

Las directivas clave son:
- **root:** Define el directorio base desde donde Nginx sirve archivos (`/usr/share/nginx/html`)
- **location:** Define bloques de configuración para rutas específicas (`/` para raíz, `/reloj` para subcarpeta)
- **try_files:** Intenta servir el archivo solicitado, si no existe intenta como directorio, y si tampoco existe retorna 404

- Evidencias:

![Pagina root (Web Academy)](evidencias/evidencias-parte2/c-01-root.png)

![Pagina reloj](evidencias/evidencias-parte2/c-02-reloj.png)

![Demostración del interior de defaultconf](evidencias/evidencias-parte2/c-03-defaultconf-inside.png)

### d) Autenticacion y control de acceso
- Respuesta: Se implementó autenticación básica HTTP en Nginx para proteger rutas específicas del servidor. Se crea un archivo `.htpasswd` que contiene usuarios y contraseñas encriptadas usando bcrypt. Luego, en `default.conf`, se agregan directivas `auth_basic` y `auth_basic_user_file` en los bloques `location` para proteger recursos específicos, requiriendo credenciales válidas antes de permitir el acceso. Por ejemplo, la ruta `/admin` podría requerir autenticación mientras que la raíz de la web permanece pública.
- Evidencias:

```bash
PS C:\Users\Sergio\Documents\DAW_2\DW_Despliegue\2526-u2-4-2-serweb-sdurutr436> Get-Content webdata\admin\index.html
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de AdministraciÃ³n</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .admin-panel {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 500px;
        }
        h1 {
            color: #667eea;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            line-height: 1.6;
        }
        .success {
            background: #4CAF50;
            color: white;
            padding: 10px;
            border-radius: 5px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="admin-panel">
        <h1>ðŸ”’ Panel de AdministraciÃ³n</h1>
        <p>Has accedido exitosamente al Ã¡rea protegida.</p>
        <p>Esta secciÃ³n requiere autenticaciÃ³n HTTP bÃ¡sica para prevenir accesos no autorizados.</p>
        <div class="success">
            âœ“ AutenticaciÃ³n exitosa
        </div>
    </div>
</body>
</html>
PS C:\Users\Sergio\Documents\DAW_2\DW_Despliegue\2526-u2-4-2-serweb-sdurutr436>
```

![Configuracion de autenticación default](evidencias/evidencias-parte2/d-02-defaultconf-auth.png)

![Acceso sin credenciales](evidencias/evidencias-parte2/d-03-curl-401.png)

![Acceso con credenciales](evidencias/evidencias-parte2/d-04-curl-200.png)


### e) Certificados digitales
- Respuesta: Los certificados digitales SSL/TLS permiten establecer comunicaciones cifradas entre el cliente y el servidor mediante HTTPS. En este proyecto se generaron certificados autofirmados utilizando OpenSSL.

**¿Qué es cada archivo?**
- **`.crt` (Certificate):** Archivo que contiene el certificado público. Incluye información como el dominio, organización, fecha de validez y la clave pública. El navegador recibe este archivo para validar la identidad del servidor y establecer el cifrado.
- **`.key` (Private Key):** Archivo que contiene la clave privada correspondiente al certificado. Se utiliza en el servidor para descifrar las comunicaciones cifradas con la clave pública. **Debe mantenerse secreto** y nunca compartirse o exponerse públicamente.

**¿Por qué se usa `-nodes` en laboratorio?**
El flag `-nodes` (no DES) en el comando OpenSSL indica que **no se cifre la clave privada** con una contraseña. Esto es útil en entornos de laboratorio/desarrollo porque:
- Permite que Nginx inicie automáticamente sin requerir intervención manual para introducir la contraseña de la clave privada.
- Simplifica el desarrollo y testing al evitar la gestión de contraseñas adicionales.
- **En producción NO se recomienda** usar `-nodes`, ya que la clave privada quedaría desprotegida si el archivo es comprometido.

**Generación de certificados (comando utilizado):**
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx-selfsigned.key \
  -out nginx-selfsigned.crt \
  -subj "/C=ES/ST=Andalucia/L=Cadiz/O=IES Rafael Alberti/CN=localhost"
```

**Ubicación de los certificados:**
- En el host: raíz del proyecto (`./nginx-selfsigned.crt` y `./nginx-selfsigned.key`)
- En el contenedor: `/etc/ssl/certs/nginx-selfsigned.crt` y `/etc/ssl/private/nginx-selfsigned.key`

**Montaje en docker-compose.yml:**
```yaml
volumes:
  - ./nginx-selfsigned.crt:/etc/ssl/certs/nginx-selfsigned.crt:ro
  - ./nginx-selfsigned.key:/etc/ssl/private/nginx-selfsigned.key:ro
```

**Uso en default.conf:**
```nginx
server {
  listen 443 ssl;
  ssl_certificate     /etc/ssl/certs/nginx-selfsigned.crt;
  ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
  # ... resto de configuración
}
```

- Evidencias:

![Listado de certificados en host](evidencias/evidencias-parte2/e-01-ls-certs.png)

![Montaje de certificados en compose](evidencias/evidencias-parte2/e-02-compose-certs.png)

![Configuracion SSL en default conf](evidencias/evidencias-parte2/e-03-defaultconf-ssl.png)

### f) Comunicaciones seguras
- Respuesta: Se implementó HTTPS como protocolo de comunicación segura usando los certificados SSL/TLS generados en la sección anterior. La configuración garantiza que todas las comunicaciones entre cliente y servidor estén cifradas.

**Configuración HTTPS (puerto 443):**
Nginx está configurado para escuchar en el puerto 443 con SSL habilitado:
```nginx
server {
  listen 443 ssl;
  server_name localhost;
  
  ssl_certificate     /etc/ssl/certs/nginx-selfsigned.crt;
  ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
  
  # ... resto de configuración del sitio
}
```

**Redirección forzada HTTP → HTTPS (código 301):**
Se configuró un segundo `server` block que escucha en el puerto 80 (HTTP) y redirige automáticamente todas las solicitudes hacia HTTPS con un código 301 (redirección permanente):
```nginx
server {
  listen 80;
  server_name localhost;
  
  location / {
    return 301 https://$server_name:8443$request_uri;
  }
}
```

**¿Por qué usar dos server blocks?**
Esta es una arquitectura de seguridad común que separa responsabilidades:

1. **Server block en puerto 80 (HTTP):** Actúa como "puerta de entrada" que captura todas las solicitudes HTTP no cifradas y las redirige automáticamente a HTTPS. No sirve ningún contenido directamente.

2. **Server block en puerto 443 (HTTPS):** Es el único que realmente sirve contenido web. Todas las conexiones aquí están cifradas mediante SSL/TLS, protegiendo los datos transmitidos (credenciales, cookies, información sensible).

**Ventajas de esta configuración:**
- **Seguridad total:** No se sirve contenido sensible por HTTP sin cifrar.
- **301 Permanent:** Los navegadores y buscadores aprenden la redirección y futuros accesos van directamente a HTTPS.
- **SEO y compatibilidad:** Los enlaces antiguos HTTP siguen funcionando gracias a la redirección automática.
- **Prevención de downgrades:** No hay forma de acceder al sitio por HTTP sin cifrar.

**Puertos configurados en docker-compose.yml:**
- `8080:80` → Puerto HTTP que redirige a HTTPS
- `8443:443` → Puerto HTTPS que sirve el contenido cifrado

- Evidencias:

![Acceso HTTPS funcionando](evidencias/evidencias-parte2/f-01-https.png)

![Redireccion 301 en Network](evidencias/evidencias-parte2/f-02-301-network.png)


### g) Documentacion
- Respuesta: Se ha documentado todo el proceso en este archivo (`DESPLIEGUE.md`) y en el archivo `README_VOLCADO.md`, que incluye: explicación de decisiones técnicas, justificación de cada paso, checklist de requisitos cumplidos, comandos utilizados, configuración completa de `docker-compose.yml` y `default.conf`, estructura del proyecto, y evidencias fotográficas de cada punto. La documentación es clara, estructura y proporciona una guía completa para entender, reproducir y mantener la solución.
- Evidencias: enlaces a este documento y a [README_VOLCADO.md](README_VOLCADO.md) que contiene documentación detallada de todo el proceso.

### h) Ajustes para implantacion de apps
- Respuesta: Se han realizado ajustes en la configuración de Nginx para permitir el despliegue de aplicaciones web estáticas. Estos ajustes incluyen: configuración de la raíz del documento (`root /usr/share/nginx/html`), directiva de índice por defecto (`index index.html`), bloque `location` con `try_files` para servir archivos estáticos o retornar 404 si no existen, y soporte para múltiples aplicaciones en subcarpetas (como `/reloj`). Estos ajustes permiten alojar múltiples aplicaciones web estáticas de forma segura y eficiente.
- Evidencias: (No disponibles en carpeta evidencias)

### i) Virtualizacion en despliegue
- Respuesta: Se ha implementado la solución completa usando Docker y Docker Compose, creando dos contenedores virtualizados independientes: uno para Nginx (servicio web) y otro para SFTP (servicio de transferencia). La virtualización permite encapsular la aplicación con todas sus dependencias en contenedores reutilizables, facilitando el despliegue, escalado y mantenimiento. Los contenedores se orquestan mediante `docker-compose.yml`, que define servicios, puertos, volúmenes compartidos y dependencias entre contenedores, permitiendo un despliegue reproducible y consistente.
- Evidencias: (No disponibles en carpeta evidencias)

### j) Logs: monitorizacion y analisis
- Respuesta: Se implementó monitorización de logs utilizando los comandos de Docker Compose para acceder a los logs en tiempo real de los contenedores. Los logs de Nginx incluyen información sobre solicitudes HTTP (método, ruta, código de respuesta, tiempo de procesamiento), lo que permite identificar errores, monitorear el acceso y analizar el comportamiento de la aplicación. Mediante `docker compose logs -f` se pueden ver los logs en vivo, y analizando patrones de acceso es posible detectar problemas de configuración, intentos de acceso no autorizados, y rendimiento del servicio.
- Evidencias: (No disponibles en carpeta evidencias)

---

## Checklist final

### Parte 1
- [x] 1) Servicio Nginx activo
- [x] 2) Configuracion cargada
- [x] 3) Resolucion de nombres
- [x] 4) Contenido Web (Cloud Academy)
- [x] 5) Conexion SFTP exitosa
- [x] 6) Permisos de escritura
- [x] 7) Contenedores activos
- [x] 8) Persistencia (Volumen compartido)
- [x] 9) Despliegue multi-sitio (/reloj)
- [x] 10) Cifrado SSL
- [x] 11) Redireccion forzada (301)

### Parte 2 (RA2)
- [ ] a) Parametros de administracion
- [ ] b) Ampliacion de funcionalidad + modulo investigado
- [ ] c) Sitios virtuales / multi-sitio
- [ ] d) Autenticacion y control de acceso
- [ ] e) Certificados digitales
- [ ] f) Comunicaciones seguras
- [x] g) Documentacion
- [ ] h) Ajustes para implantacion de apps
- [ ] i) Virtualizacion en despliegue
- [ ] j) Logs: monitorizacion y analisis
