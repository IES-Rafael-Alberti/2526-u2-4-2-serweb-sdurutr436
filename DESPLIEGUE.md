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
- Respuesta: Los parámetros de administración de Nginx están configurados en el archivo `default.conf`, que incluye directivas como `listen 80` y `listen 443 ssl` para los puertos HTTP/HTTPS, `root` para el directorio raíz del contenido web, `ssl_certificate` y `ssl_certificate_key` para la configuración de certificados SSL, y bloques `location` para el manejo de rutas. Estos parámetros permiten controlar cómo Nginx atiende solicitudes, sirve contenido estático y gestiona certificados de seguridad. La configuración se valida con `nginx -t` dentro del contenedor.
- Evidencias: (No disponibles en carpeta evidencias)

### b) Ampliacion de funcionalidad + modulo investigado
- Opcion elegida (B1 o B2): **B2 - Módulos de compresión y seguridad HTTP (Headers)**
- Respuesta: Se implementó la ampliación de funcionalidad agregando módulos de compresión (gzip) para optimizar la transferencia de contenido, reduciendo el tamaño de las respuestas HTTP, y módulos de seguridad mediante headers HTTP personalizados como `Strict-Transport-Security`, `X-Content-Type-Options` y `X-Frame-Options` para proteger contra ataques comunes. Estos módulos están compilados de forma nativa en la imagen `nginx:alpine` y se configuran directamente en `default.conf`.
- Evidencias (B1 o B2): (No disponibles en carpeta evidencias)

#### Modulo investigado: Modulos de Headers de Seguridad HTTP
- Para que sirve: Estos módulos permiten agregar headers HTTP personalizados a las respuestas del servidor para mejorar la seguridad. Por ejemplo: `Strict-Transport-Security` (HSTS) fuerza el uso de HTTPS en futuras solicitudes, `X-Content-Type-Options: nosniff` previene ataques de MIME-sniffing, y `X-Frame-Options: DENY` previene clickjacking.
- Como se instala/carga: Los módulos de headers están compilados de forma nativa en la imagen `nginx:alpine`. Se configuran agregando directivas como `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` en los bloques `server` o `location` del archivo de configuración `default.conf`.
- Fuente(s): Documentación oficial de Nginx - http://nginx.org/en/docs/http/ngx_http_headers_module.html

### c) Sitios virtuales / multi-sitio
- Respuesta: Se ha implementado un despliegue multi-sitio donde Nginx sirve dos aplicaciones web independientes desde el mismo contenedor: la aplicación principal (CloudAcademy) en la raíz (`/`) y una aplicación secundaria (Reloj) en la subcarpeta (`/reloj`). Ambos sitios comparten el mismo volumen (`./www`) y se acceden a través del mismo host pero en rutas diferentes, siendo un ejemplo de uso de host virtual basado en rutas en lugar de dominios.
- Evidencias: (No disponibles en carpeta evidencias)

### d) Autenticacion y control de acceso
- Respuesta: Se implementó autenticación básica HTTP en Nginx para proteger rutas específicas del servidor. Se crea un archivo `.htpasswd` que contiene usuarios y contraseñas encriptadas usando bcrypt. Luego, en `default.conf`, se agregan directivas `auth_basic` y `auth_basic_user_file` en los bloques `location` para proteger recursos específicos, requiriendo credenciales válidas antes de permitir el acceso. Por ejemplo, la ruta `/admin` podría requerir autenticación mientras que la raíz de la web permanece pública.
- Evidencias: (No disponibles en carpeta evidencias)

### e) Certificados digitales
- Respuesta: Se generaron certificados SSL autofirmados (nginx-selfsigned.crt y nginx-selfsigned.key) utilizando OpenSSL. Estos certificados se almacenan en la carpeta `./certs/` del host y se montan como volúmenes en el contenedor Nginx en las rutas `/etc/ssl/certs/` y `/etc/ssl/private/`. La configuración en `default.conf` referencia estos certificados mediante las directivas `ssl_certificate` y `ssl_certificate_key`, permitiendo que Nginx sirva contenido por HTTPS en el puerto 443.
- Evidencias: (No disponibles en carpeta evidencias)

### f) Comunicaciones seguras
- Respuesta: Se implementó HTTPS como protocolo de comunicación segura usando los certificados SSL/TLS generados anteriormente. Nginx está configurado para escuchar en el puerto 443 con la directiva `listen 443 ssl` y se establece una política de redirección obligatoria que redirige todas las solicitudes HTTP (puerto 80) a HTTPS (puerto 443) con un código 301, asegurando que todas las comunicaciones cliente-servidor estén cifradas.
- Evidencias: (No disponibles en carpeta evidencias)

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
