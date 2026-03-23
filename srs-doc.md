# Documento de Requisitos de Software (SRS)

## SOC Log Ingestor & Rule Manager

**Versión:** 1.0.0
**Fecha:** Marzo 2026
**Clasificación:** Interno

---

## 1. Introducción

### 1.1 Propósito

Este documento describe los requisitos funcionales, no funcionales y técnicos de la aplicación **SOC Log Ingestor & Rule Manager**, una herramienta de escritorio diseñada para generar e ingestar logs de seguridad realistas en Elasticsearch y gestionar reglas de detección MITRE ATT&CK en Kibana a través de su API de Detection Engine.

### 1.2 Alcance

La aplicación cubre tres áreas funcionales principales:

- **Ingesta de datos**: generación y carga de eventos de seguridad sintéticos en Elasticsearch, tanto en modo masivo (bulk) como en modo continuo (stream).
- **Gestión de reglas**: creación, listado y eliminación de reglas de detección en Kibana, organizadas por tácticas MITRE ATT&CK y segmentadas por Kibana Spaces.
- **Monitorización de alertas**: consulta y visualización de las alertas generadas por las reglas desplegadas en Kibana.

### 1.3 Audiencia

Este documento está dirigido a analistas SOC, ingenieros de seguridad, equipos de QA de plataformas SIEM y cualquier persona que necesite comprender el funcionamiento técnico y funcional de la herramienta.

### 1.4 Definiciones y acrónimos

| Término | Definición |
|---------|-----------|
| SOC | Security Operations Center |
| SIEM | Security Information and Event Management |
| EPS | Eventos Por Segundo |
| KQL | Kibana Query Language |
| Data Stream | Modelo de almacenamiento temporal optimizado de Elasticsearch |
| Index Template | Plantilla de configuración para índices de Elasticsearch |
| MITRE ATT&CK | Framework de tácticas y técnicas de adversarios |
| Space | Espacio de trabajo aislado en Kibana |
| Detection Engine | Motor de reglas de detección de Kibana Security |
| Bulk API | API de ingesta masiva de Elasticsearch |

---

## 2. Descripción general del sistema

### 2.1 Perspectiva del producto

La aplicación funciona como herramienta independiente de escritorio con interfaz gráfica. Se conecta a dos servicios externos:

- **Elasticsearch**: como destino de ingesta de los logs generados.
- **Kibana**: como plataforma de gestión de reglas de detección y consulta de alertas.

No requiere infraestructura propia más allá de un entorno Python 3.10+ y acceso de red a las instancias de Elasticsearch y Kibana.

### 2.2 Arquitectura funcional

```
┌──────────────────────────────────────────────────────────┐
│                    INTERFAZ GRÁFICA (Tkinter)            │
│                                                          │
│  ┌─────────────────────┐    ┌──────────────────────────┐ │
│  │   MÓDULO INGESTA    │    │   MÓDULO REGLAS/ALERTAS  │ │
│  │  ┌───────┐┌───────┐ │    │  ┌────────┐ ┌─────────┐ │ │
│  │  │ Bulk  ││Stream │ │    │  │Generar │ │ Alertas │ │ │
│  │  └───────┘└───────┘ │    │  └────────┘ └─────────┘ │ │
│  └─────────┬───────────┘    └──────────┬───────────────┘ │
│            │                           │                 │
│  ┌─────────▼───────────┐    ┌──────────▼───────────────┐ │
│  │    GENERADORES      │    │   CONSTRUCTOR DE REGLAS  │ │
│  │ Auth|Net|EP|DNS|FW  │    │   22 reglas MITRE ATT&CK │ │
│  └─────────┬───────────┘    └──────────┬───────────────┘ │
│            │                           │                 │
│  ┌─────────▼───────────┐    ┌──────────▼───────────────┐ │
│  │  CLIENTE ELASTIC    │    │   CLIENTE KIBANA (HTTP)  │ │
│  │  (elasticsearch-py) │    │   (urllib - stdlib)      │ │
│  └─────────┬───────────┘    └──────────┬───────────────┘ │
└────────────┼───────────────────────────┼─────────────────┘
             │                           │
     ┌───────▼───────┐          ┌────────▼────────┐
     │ Elasticsearch │          │     Kibana      │
     │   7.x / 8.x  │          │    7.x / 8.x   │
     └───────────────┘          └─────────────────┘
```

### 2.3 Usuarios objetivo

- **Analistas SOC**: para poblar entornos de prueba con datos realistas y validar reglas de detección.
- **Ingenieros SIEM**: para testing de rendimiento, validación de pipelines de ingesta y calibración de reglas.
- **Equipos de formación**: para crear escenarios de ataque simulados en entornos de laboratorio.
- **QA de seguridad**: para pruebas de carga y verificación de alertas.

---

## 3. Requisitos funcionales

### 3.1 Módulo de Configuración (Wizard)

#### RF-CFG-001: Configuración de conexión a Elasticsearch

El sistema debe proporcionar un formulario de configuración con los siguientes campos:

| Campo | Tipo | Obligatorio | Descripción |
|-------|------|-------------|-------------|
| URL Elasticsearch | Texto | Sí | URL completa incluyendo protocolo y puerto |
| Método de autenticación | Selector | Sí | API Key o Usuario/Contraseña |
| API Key | Texto (oculto) | Condicional | Requerido si el método es API Key |
| Usuario | Texto | Condicional | Requerido si el método es Usuario/Contraseña |
| Contraseña | Texto (oculto) | Condicional | Requerido si el método es Usuario/Contraseña |
| Ruta CA cert | Selector de archivo | No | Ruta al certificado de CA para SSL |
| Verificar SSL | Checkbox | No | Activado por defecto |

#### RF-CFG-002: Prueba de conexión a Elasticsearch

El sistema debe permitir probar la conexión a Elasticsearch antes de guardar, mostrando la versión del servidor en caso de éxito o el mensaje de error en caso de fallo.

#### RF-CFG-003: Configuración de conexión a Kibana

El sistema debe proporcionar un campo para la URL de Kibana independiente de la de Elasticsearch. Las credenciales de autenticación se reutilizan de la configuración de Elasticsearch.

#### RF-CFG-004: Prueba de conexión a Kibana

El sistema debe permitir probar la conexión a Kibana de forma independiente, mostrando la versión del servidor.

#### RF-CFG-005: Configuración de índices por categoría

Para cada una de las 5 categorías de log (Autenticación, Network, Endpoint, DNS, Firewall), el sistema debe permitir configurar:

- **Nombre del índice**: campo de texto editable con valor por defecto.
- **Tipo de almacenamiento**: checkbox para seleccionar entre índice normal y Data Stream.

Valores por defecto de los índices:

| Categoría | Índice por defecto |
|-----------|-------------------|
| Autenticación | `soc-logs-auth` |
| Network | `soc-logs-network` |
| Endpoint | `soc-logs-endpoint` |
| DNS | `soc-logs-dns` |
| Firewall | `soc-logs-firewall` |

#### RF-CFG-006: Persistencia de configuración

La configuración debe almacenarse en un fichero JSON en el directorio home del usuario (`~/.soc_ingestor_config.json`) y cargarse automáticamente en cada inicio de la aplicación.

#### RF-CFG-007: Acceso posterior a configuración

Desde la pantalla principal, el usuario debe poder acceder al wizard de configuración en cualquier momento mediante un botón visible.

---

### 3.2 Módulo de Ingesta

#### 3.2.1 Generación de eventos

##### RF-ING-001: Categorías de log soportadas

El sistema debe generar eventos para las siguientes 5 categorías:

**Autenticación**
- Eventos de login exitoso y fallido.
- Simulación de ataques de fuerza bruta (múltiples intentos fallidos desde IPs maliciosas contra cuentas de administración).
- Campos: timestamp, categoría, resultado, acción, usuario, IP origen, geolocalización, host, SO, proveedor de autenticación, aplicación, razón de fallo, agente.

**Network**
- Conexiones de red con direccionamiento, puertos y protocolo.
- 10% de eventos sospechosos: conexiones a IPs maliciosas, volúmenes altos de datos, puertos C2.
- Campos: timestamp, IPs origen/destino, puertos, bytes transferidos, protocolo, dirección, host, user agent, agente.

**Endpoint**
- Eventos de creación de procesos con línea de comandos completa.
- 12% de eventos sospechosos: LOLBins, herramientas de hacking, comandos de reconocimiento, persistencia, volcado de credenciales, movimiento lateral.
- Campos: timestamp, proceso (nombre, PID, ejecutable, línea de comandos, hashes SHA256/MD5), proceso padre, usuario, host, SO, agente.

**DNS**
- Consultas DNS con tipo de query, código de respuesta e IPs resueltas.
- 8% de eventos sospechosos: dominios DGA generados dinámicamente, dominios de C2 conocidos, phishing/typosquatting, tunneling DNS.
- Campos: timestamp, dominio consultado, tipo de query, código de respuesta, IPs resueltas, host, agente.

**Firewall**
- Eventos de firewall con acciones (allowed, denied, dropped, reset).
- Tráfico bidireccional con zonas de seguridad y datos de NAT.
- Campos: timestamp, IPs origen/destino, puertos, acción, protocolo, dirección, vendor, producto, zonas, ID de regla, agente.

##### RF-ING-002: Pools de datos

La generación de datos debe utilizar pools expandidos para maximizar la variabilidad:

| Pool | Cantidad mínima | Descripción |
|------|----------------|-------------|
| IPs internas | 100+ | Distribuidas en múltiples subredes (10.x, 172.16.x, 192.168.x) |
| IPs externas | 200+ | Generadas aleatoriamente |
| IPs maliciosas | 35+ | Nodos Tor, C2, APT, escáneres, cryptomining |
| Hostnames | 100+ | Workstations, laptops por departamento, servidores, cloud |
| Usuarios | 60+ | Estándar, cuentas de servicio, administradores |
| Procesos normales | 30+ | Windows y Linux |
| Procesos sospechosos | 35+ | LOLBins, herramientas de hacking |
| Dominios legítimos | 25+ | Big tech, SaaS, CDN, updates |
| Dominios maliciosos | 16+ | C2, phishing, malware, cryptomining |
| Comandos sospechosos | 25+ | PowerShell, CMD, certutil, mimikatz, lateral movement, exfiltración |
| Países | 25+ | Para geolocalización |
| TLDs DGA | 12+ | Para generación dinámica de dominios |

##### RF-ING-003: Realismo en los eventos generados

Los eventos deben incluir:

- Timestamps distribuidos aleatoriamente en un rango configurable (por defecto 30 días hacia atrás para bulk, tiempo real para stream).
- Correlación entre campos (ej: procesos `.exe` con SO Windows, procesos sin extensión con Linux).
- Tags descriptivos en eventos sospechosos (`brute_force`, `suspicious_process`, `lolbin`, `dga_suspect`, `dns_tunnel_suspect`, `malicious_ip`, `blocked`).
- Versiones de agente y tipos variados (`winlogbeat`, `filebeat`, `elastic-agent`, `packetbeat`, `sysmon`, `auditbeat`).

#### 3.2.2 Modo Bulk

##### RF-ING-010: Selección de categorías

El usuario debe poder seleccionar qué categorías de log generar mediante checkboxes individuales.

##### RF-ING-011: Cantidad configurable por categoría

Cada categoría debe tener un campo numérico (spinbox) para especificar la cantidad de eventos a generar, con un rango de 1 a 100.000 y un valor por defecto de 500.

##### RF-ING-012: Ejecución en segundo plano

La ingesta bulk debe ejecutarse en un hilo separado para no bloquear la interfaz gráfica.

##### RF-ING-013: Barra de progreso

El sistema debe mostrar una barra de progreso que refleje el avance total de la ingesta.

##### RF-ING-014: Log de actividad por categoría

El sistema debe registrar en la consola el número de documentos ingestados exitosamente y el número de errores por cada categoría.

#### 3.2.3 Modo Stream

##### RF-ING-020: Selección de categorías

El usuario debe poder seleccionar qué categorías de log incluir en el stream.

##### RF-ING-021: Configuración de EPS

El usuario debe poder especificar los eventos por segundo (EPS) deseados mediante un campo numérico, con un rango de 1 a 10.000.

##### RF-ING-022: Inicio y parada

El stream debe poder iniciarse y detenerse mediante un único botón que alterne su estado y apariencia visual.

##### RF-ING-023: Timestamps en tiempo real

En modo stream, todos los eventos deben llevar el timestamp del momento exacto de generación.

##### RF-ING-024: Estadísticas en tiempo real

El sistema debe mostrar, actualizándose cada 2 segundos:
- EPS real medido.
- Total de eventos enviados.

##### RF-ING-025: Adaptación de lotes

Para EPS superiores a 200, el sistema debe agrupar eventos en lotes para optimizar el rendimiento, usando la Bulk API de Elasticsearch en lugar de indexado individual.

#### 3.2.4 Soporte de Data Streams

##### RF-ING-030: Creación automática de Index Templates

Cuando una categoría está configurada como Data Stream, el sistema debe crear automáticamente el index template con:
- `data_stream: {}` habilitado.
- Mappings para `@timestamp` (date), campos de evento (keyword), IPs (ip type) y mensaje (text).
- Priority 200 para prevalecer sobre templates por defecto.

##### RF-ING-031: Creación automática del Data Stream

Si el data stream no existe, el sistema debe crearlo tras crear el template.

##### RF-ING-032: Detección de recursos existentes

Si el template o data stream ya existen, el sistema debe detectarlo y omitir la creación, informando al usuario.

##### RF-ING-033: Adaptación de documentos

Los documentos destinados a un data stream deben adaptarse automáticamente:
- Eliminar campo `_id`.
- Establecer `_op_type: "create"`.

---

### 3.3 Módulo de Reglas MITRE ATT&CK

#### 3.3.1 Descubrimiento de Kibana Spaces

##### RF-RUL-001: Listado de Spaces

El sistema debe consultar la API de Kibana (`GET /api/spaces/space`) para obtener la lista de spaces disponibles y mostrarlos en un selector desplegable con formato `id — nombre`.

##### RF-RUL-002: Actualización de Spaces

El usuario debe poder forzar la recarga de la lista de spaces en cualquier momento.

##### RF-RUL-003: Selector de Space por sección

Los módulos de generación de reglas y de alertas deben tener selectores de Space independientes, permitiendo operar en spaces distintos simultáneamente.

#### 3.3.2 Generación de reglas

##### RF-RUL-010: Selección de tácticas

El usuario debe poder seleccionar qué tácticas MITRE ATT&CK incluir mediante checkboxes. Las tácticas disponibles son:

| Táctica | ID MITRE |
|---------|----------|
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Defense Evasion | TA0005 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Command and Control | TA0011 |
| Exfiltration | TA0010 |

##### RF-RUL-011: Catálogo de reglas

El sistema debe incluir un catálogo de 22 reglas de detección predefinidas:

| ID | Regla | Táctica | Tipo | Severidad |
|----|-------|---------|------|-----------|
| soc-ia-001 | Brute Force - Multiple Failed Logins | Initial Access | threshold | high |
| soc-ia-002 | Login from Known Malicious IP | Initial Access | query | critical |
| soc-ia-003 | Admin Login from External IP | Initial Access | query | high |
| soc-ex-001 | Suspicious PowerShell Encoded Command | Execution | query | high |
| soc-ex-002 | CMD Reconnaissance Commands | Execution | query | medium |
| soc-ex-003 | LOLBin Proxy Execution | Execution | query | high |
| soc-pe-001 | Registry Run Key Modification | Persistence | query | high |
| soc-pe-002 | Scheduled Task for Persistence | Persistence | query | medium |
| soc-pe-003 | Suspicious Service Installation | Persistence | query | high |
| soc-ca-001 | Credential Dumping - Mimikatz / LSASS | Credential Access | query | critical |
| soc-di-001 | Network Reconnaissance Tools | Discovery | query | medium |
| soc-lm-001 | Lateral Movement via PsExec / SMB | Lateral Movement | query | high |
| soc-lm-002 | External RDP Connection | Lateral Movement | query | medium |
| soc-de-001 | Certutil File Download | Defense Evasion | query | high |
| soc-de-002 | Shadow Copy Deletion - Ransomware | Defense Evasion | query | critical |
| soc-cc-001 | Outbound to Known Malicious IP | Command and Control | query | critical |
| soc-cc-002 | Suspicious DGA / DNS Tunnel | Command and Control | query | high |
| soc-cc-003 | Connection on Suspicious Port | Command and Control | query | medium |
| soc-xf-001 | Large Outbound Data Transfer | Exfiltration | query | high |
| soc-xf-002 | Data Archiving Before Exfiltration | Exfiltration | query | high |
| soc-fw-001 | Inbound Blocked from Malicious IP | Initial Access | query | medium |
| soc-fw-002 | Outbound to Malicious IP Allowed | Command and Control | query | critical |

##### RF-RUL-012: Formato de regla Kibana

Cada regla debe generarse en el formato nativo de la Detection Engine API de Kibana, incluyendo:

- `rule_id`: identificador único persistente.
- `name`, `description`: nombre y descripción legibles.
- `type`: `query` o `threshold`.
- `query`: consulta KQL contra los índices configurados.
- `language`: `kuery`.
- `index`: array con el nombre del índice configurado para la categoría correspondiente.
- `severity`: `low`, `medium`, `high` o `critical`.
- `risk_score`: valor numérico de 0 a 100.
- `interval`: frecuencia de ejecución (por defecto `5m`).
- `from` / `to`: ventana temporal de la consulta.
- `enabled`: estado de activación.
- `tags`: incluyendo siempre `SOC-Ingestor` y `Auto-Generated`.
- `threat`: bloque completo de threat mapping MITRE ATT&CK con tactic ID, technique ID, subtechniques y referencias.

##### RF-RUL-013: Carga en Kibana

Las reglas deben crearse mediante la API `POST /s/{space}/api/detection_engine/rules`. La petición debe incluir las cabeceras `kbn-xsrf: true` y `elastic-api-version: 2023-10-31`.

##### RF-RUL-014: Actualización de reglas existentes

Si una regla ya existe en el space (error 409/conflict), el sistema debe:
1. Eliminar la regla existente por `rule_id`.
2. Recrear la regla con la nueva definición.
3. Informar al usuario de que la regla fue actualizada.

##### RF-RUL-015: Ejecución en segundo plano

La carga de reglas debe ejecutarse en un hilo separado, informando del progreso en la consola de actividad.

#### 3.3.3 Listado y eliminación de reglas

##### RF-RUL-020: Listado de reglas

El sistema debe consultar las reglas del space seleccionado mediante `GET /s/{space}/api/detection_engine/rules/_find` y mostrarlas en una tabla con las columnas: ID, Nombre, Táctica, Severidad, Estado (habilitada/deshabilitada).

##### RF-RUL-021: Colorización por severidad

Las filas de la tabla deben colorearse según severidad:
- Critical: rojo (`#f38ba8`)
- High: naranja (`#fab387`)
- Medium: amarillo (`#f9e2af`)
- Low: verde (`#a6e3a1`)

##### RF-RUL-022: Eliminación selectiva

La función de eliminación solo debe afectar a las reglas que contengan el tag `SOC-Ingestor`, preservando cualquier otra regla existente en el space.

##### RF-RUL-023: Confirmación de eliminación

El sistema debe solicitar confirmación al usuario antes de proceder con la eliminación.

#### 3.3.4 Consulta de alertas

##### RF-RUL-030: Búsqueda de alertas

El sistema debe consultar las alertas/signals generadas en el space seleccionado mediante `POST /s/{space}/api/detection_engine/signals/search`.

##### RF-RUL-031: Visualización de alertas

Las alertas deben mostrarse en una tabla con las columnas: Timestamp, Severidad, Regla, Táctica, Host, Source IP. Las filas deben colorearse por severidad con el mismo esquema de colores de las reglas.

##### RF-RUL-032: Ordenación temporal

Las alertas deben mostrarse ordenadas por timestamp descendente (más recientes primero).

##### RF-RUL-033: Límite de resultados

La consulta debe limitarse a 200 alertas por ejecución.

##### RF-RUL-034: Filtro por estado de alerta

La sección de alertas debe incluir un selector que permita filtrar por estado de workflow:
- **Todas** (sin filtro)
- **open** — alertas abiertas
- **closed** — alertas cerradas
- **acknowledged** — alertas reconocidas

El filtro debe ser compatible con Kibana 7.x (`signal.status`) y Kibana 8.x (`kibana.alert.workflow_status`).

##### RF-RUL-035: Filtro por período temporal

La sección de alertas debe incluir un selector de período que limite la ventana temporal de la consulta:
- **Todo** (sin filtro de tiempo)
- Última hora
- Últimas 6h
- Últimas 24h
- Últimos 7 días
- Últimos 30 días

El filtro aplica un rango relativo sobre el campo `@timestamp` usando la notación de Elasticsearch (`now-{valor}`).

---

## 4. Requisitos no funcionales

### 4.1 Rendimiento

| Requisito | Valor |
|-----------|-------|
| RNF-PER-001 | El modo stream debe sostener al menos 200 EPS de forma continua. |
| RNF-PER-002 | Para EPS > 200, el sistema debe agrupar eventos en lotes y usar Bulk API. |
| RNF-PER-003 | La interfaz gráfica no debe bloquearse durante operaciones de ingesta o consulta. |
| RNF-PER-004 | Las operaciones de red deben tener un timeout máximo de 120 segundos para Elasticsearch y 30 segundos para Kibana. |

### 4.2 Usabilidad

| Requisito | Valor |
|-----------|-------|
| RNF-USA-001 | La aplicación debe funcionar nativamente en Windows sin dependencias de GUI externas (uso de Tkinter incluido en la distribución estándar de Python). |
| RNF-USA-002 | El wizard de configuración debe guiar al usuario paso a paso, mostrando resultados de pruebas de conexión antes de guardar. |
| RNF-USA-003 | La consola de actividad debe mostrar logs con timestamp para toda operación relevante. |
| RNF-USA-004 | Los mensajes de error deben ser descriptivos e incluir información accionable. |
| RNF-USA-005 | El tema visual debe ser oscuro (Catppuccin Mocha) para reducir fatiga visual en entornos SOC. |

### 4.3 Fiabilidad

| Requisito | Valor |
|-----------|-------|
| RNF-FIA-001 | El cliente de Elasticsearch debe reintentar hasta 3 veces en caso de timeout. |
| RNF-FIA-002 | Los errores de ingesta individual no deben detener el proceso completo; deben registrarse y continuar. |
| RNF-FIA-003 | La aplicación debe detectar la versión del cliente elasticsearch-py y rechazar versiones incompatibles (9.x) con un mensaje claro al inicio. |
| RNF-FIA-004 | Si la configuración es inválida, el sistema debe permitir guardarla igualmente previa confirmación del usuario. |

### 4.4 Seguridad

| Requisito | Valor |
|-----------|-------|
| RNF-SEG-001 | Las credenciales deben mostrarse ofuscadas (campos de tipo password) en la interfaz. |
| RNF-SEG-002 | Las credenciales se almacenan en texto plano en el fichero de configuración local; el usuario es responsable de proteger el acceso al fichero. |
| RNF-SEG-003 | La aplicación debe soportar conexiones TLS con verificación de certificados y CA personalizado. |
| RNF-SEG-004 | La cabecera `kbn-xsrf` debe enviarse en todas las peticiones a Kibana para cumplir con la protección CSRF. |

### 4.5 Compatibilidad

| Requisito | Valor |
|-----------|-------|
| RNF-COM-001 | Python 3.10 o superior. |
| RNF-COM-002 | Elasticsearch 7.x y 8.x. |
| RNF-COM-003 | Kibana 7.x y 8.x. |
| RNF-COM-004 | Cliente Python `elasticsearch>=8,<9` (la versión 9.x no es compatible). |
| RNF-COM-005 | Compatible con Elastic Cloud Enterprise (ECE) y Elastic Cloud. |
| RNF-COM-006 | Sistema operativo principal: Windows 10/11. Funcionamiento también válido en Linux y macOS. |

---

## 5. Requisitos de interfaz

### 5.1 Estructura de la interfaz principal

La interfaz principal se organiza en:

1. **Barra superior**: título de la aplicación, indicador de estado de conexión a ES y botón de acceso a configuración.
2. **Panel de pestañas principal** con dos secciones:
   - **📦 Ingesta**: contiene sub-pestañas Bulk y Stream.
   - **🔒 Reglas MITRE ATT&CK**: contiene sub-pestañas Generar y Alertas.
3. **Consola de actividad**: panel inferior con scroll que muestra logs de todas las operaciones.

### 5.2 Estructura del wizard de configuración

El wizard se organiza en tres pestañas:
1. **🔌 Elasticsearch**: parámetros de conexión y autenticación.
2. **🌐 Kibana**: URL de Kibana y prueba de conexión.
3. **📋 Configuración de Ingesta**: nombre de índice y tipo de almacenamiento por categoría.

### 5.3 Tema visual

La aplicación utiliza el tema **Catppuccin Mocha** con la siguiente paleta:

| Elemento | Color |
|----------|-------|
| Fondo principal | `#1e1e2e` |
| Fondo de paneles | `#181825` |
| Fondo de campos | `#313244` |
| Texto principal | `#cdd6f4` |
| Texto secundario | `#a6adc8` |
| Acento (botones, títulos) | `#89b4fa` |
| Éxito | `#a6e3a1` |
| Error / Critical | `#f38ba8` |
| Warning / High | `#fab387` |
| Medium | `#f9e2af` |

---

## 6. Dependencias externas

### 6.1 Dependencias Python

| Paquete | Versión | Propósito |
|---------|---------|-----------|
| `elasticsearch` | >=8, <9 | Cliente oficial de Elasticsearch |
| `faker` | >=20.0 | Generación de datos ficticios complementarios |
| `tkinter` | (stdlib) | Interfaz gráfica |
| `urllib` | (stdlib) | Peticiones HTTP a Kibana API |

### 6.2 Servicios externos

| Servicio | Propósito | Autenticación |
|----------|-----------|---------------|
| Elasticsearch | Destino de ingesta de logs | API Key o Basic Auth |
| Kibana | Gestión de reglas y alertas | API Key o Basic Auth (mismas credenciales que ES) |

---

## 7. Estructura del proyecto

```
soc-ingestor/
├── run.py                          # Punto de entrada de la aplicación
├── requirements.txt                # Dependencias pip
├── pyproject.toml                  # Metadata del paquete Python
├── README.md                       # Documentación de usuario
│
└── soc_ingestor/                   # Paquete principal
    ├── __init__.py                 # Versión del paquete
    ├── app.py                      # Orquestador: conecta UI, clientes y config
    ├── config.py                   # Carga, guardado y acceso a configuración
    │
    ├── clients/                    # Clientes de servicios externos
    │   ├── elastic.py              # Conexión ES, data streams, adaptación de docs
    │   └── kibana.py               # API HTTP: spaces, rules, alerts
    │
    ├── generators/                 # Generadores de eventos por categoría
    │   ├── __init__.py             # Registro GENERATORS con todos los generadores
    │   ├── helpers.py              # Utilidades: timestamps, IPs, SHA256, DGA
    │   ├── pools.py                # Pools de datos expandidos
    │   ├── auth.py                 # Eventos de autenticación
    │   ├── network.py              # Eventos de red
    │   ├── endpoint.py             # Eventos de endpoint/proceso
    │   ├── dns.py                  # Eventos DNS
    │   └── firewall.py             # Eventos de firewall
    │
    ├── rules/                      # Motor de reglas MITRE ATT&CK
    │   ├── mitre.py                # Constantes: tácticas, IDs, threat blocks
    │   └── builder.py              # Constructor de las 22 reglas en formato Kibana
    │
    └── ui/                         # Interfaz gráfica
        ├── styles.py               # Tema Catppuccin Mocha para ttk
        ├── wizard.py               # Wizard de configuración (3 pestañas)
        ├── ingestion.py            # Paneles Bulk y Stream
        └── rules_panel.py          # Paneles Generar Reglas y Alertas
```

---

## 8. Flujos de operación

### 8.1 Primera ejecución

```
Inicio → No hay config → Wizard → Configurar ES → Configurar Kibana →
Configurar índices → Guardar → Pantalla principal
```

### 8.2 Ingesta Bulk

```
Seleccionar categorías → Establecer cantidades → Iniciar →
[Si Data Stream: crear template + DS] → Generar eventos →
Bulk API → Refresh índices → Completado
```

### 8.3 Ingesta Stream

```
Seleccionar categorías → Establecer EPS → Iniciar →
[Si Data Stream: crear template + DS] → Loop (generar → indexar →
medir EPS → sleep) → Detener → Completado
```

### 8.4 Generación de reglas

```
Cargar Spaces → Seleccionar Space → Seleccionar tácticas → Generar →
[Por cada regla: crear via API, si existe: delete + recreate] →
Refrescar lista → Completado
```

### 8.5 Consulta de alertas

```
Seleccionar Space → Seleccionar Estado → Seleccionar Período →
Buscar → POST signals/search (con filtros) →
Parsear resultados → Mostrar en tabla coloreada
```

---

## 9. Limitaciones conocidas

| ID | Limitación | Impacto |
|----|-----------|---------|
| LIM-001 | El cliente `elasticsearch-py` versión 9.x no es compatible | El sistema valida la versión al inicio y muestra error informativo |
| LIM-002 | Las credenciales se almacenan en texto plano en el fichero de configuración | El usuario debe proteger el acceso al fichero |
| LIM-003 | La consulta de alertas está limitada a 200 resultados por ejecución | Alertas más antiguas pueden no mostrarse |
| LIM-004 | Las reglas threshold requieren licencia Platinum/Enterprise en Kibana | La regla de brute force puede fallar en licencias básicas |
| LIM-005 | La herramienta no gestiona el ciclo de vida de los data streams (rollover, ILM) | El usuario debe configurar ILM externamente si es necesario |
| LIM-006 | No se soporta autenticación con certificado de cliente (mTLS) | Solo API Key y Basic Auth están disponibles |

---

## 10. Historial de versiones

| Versión | Fecha | Cambios |
|---------|-------|---------|
| 1.0.0 | Marzo 2026 | Versión inicial: ingesta bulk/stream, 5 categorías, 22 reglas MITRE ATT&CK, integración Kibana Spaces, soporte Data Streams |
