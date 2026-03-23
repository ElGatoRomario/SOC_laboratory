# 🛡 SOC Log Ingestor & Rule Manager

Herramienta gráfica (Python + Tkinter) para generar, ingestar logs realistas de seguridad en **Elasticsearch** y gestionar reglas de detección **MITRE ATT&CK** en **Kibana**.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-7.x%20%7C%208.x-yellow)
![Kibana](https://img.shields.io/badge/Kibana-7.x%20%7C%208.x-purple)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📋 Características

### Ingesta de logs
- **Modo Bulk**: carga masiva con barra de progreso y número de eventos configurable por categoría.
- **Modo Stream**: ingesta continua a N eventos por segundo (EPS) configurable en tiempo real.
- **5 categorías de logs**: Autenticación, Network, Endpoint, DNS y Firewall.
- **Pools de datos expandidos**: +150 hosts, +120 usuarios, +60 IPs maliciosas (Tor, C2, APT), +90 dominios DNS, +60 comandos sospechosos, +80 procesos, etc.
- **Soporte Data Streams**: creación automática de index templates y data streams.

### Reglas MITRE ATT&CK
- **22 reglas de detección** cubriendo 9 tácticas MITRE ATT&CK.
- **Carga directa en Kibana** a través de la Detection Engine API.
- **Selector de Kibana Spaces**: descubrimiento automático de spaces y carga/gestión por space.
- **Visualización de alertas**: consulta de alertas/signals generadas por las reglas directamente desde la herramienta.

### Configuración
- **Wizard de configuración** con 3 secciones: Elasticsearch, Kibana e Ingesta.
- **Persistencia**: la configuración se guarda en `~/.soc_ingestor_config.json`.
- **Autenticación flexible**: API Key o Usuario/Contraseña.
- **SSL configurable**: verificación de certificados y soporte para CA personalizado.

---

## 🚀 Instalación

### 1. Clonar o descargar el proyecto

```bash
cd soc-ingestor
```

### 2. Crear entorno virtual (recomendado)

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

> **Importante**: se requiere `elasticsearch>=8,<9`. La versión 9.x del cliente no es compatible.

---

## ▶ Uso

```bash
python run.py
```

### Primera ejecución — Wizard de configuración

Al iniciar por primera vez se abrirá el wizard con 3 pestañas:

#### 🔌 Elasticsearch
| Campo | Descripción |
|-------|-------------|
| URL | URL completa, ej: `https://mi-cluster.es.cloud:9243` |
| Autenticación | API Key o Usuario/Contraseña |
| CA cert | Ruta al certificado CA (opcional, para SSL autofirmado) |
| Verificar SSL | Desmarca si usas certificados autofirmados |

> **Tip Elastic Cloud**: la URL de ES usa `.es.` en el subdominio, no `.kb.` (que es Kibana).

#### 🌐 Kibana
| Campo | Descripción |
|-------|-------------|
| URL Kibana | URL completa, ej: `https://mi-cluster.kb.cloud:9243` |

Usa las mismas credenciales configuradas en la pestaña de Elasticsearch.

#### 📋 Configuración de Ingesta

Para cada categoría de log puedes configurar:
- **Nombre del índice**: personalizable (por defecto `soc-logs-auth`, `soc-logs-network`, etc.)
- **Data Stream**: si se marca, el script crea automáticamente el index template y el data stream.

---

## 📦 Ingesta de logs

### Modo Bulk
1. Selecciona las categorías que quieres ingestar.
2. Configura el número de eventos por categoría (spinbox).
3. Pulsa **▶ Bulk**.

### Modo Stream
1. Selecciona las categorías.
2. Configura los **EPS** (eventos por segundo).
3. Pulsa **▶ Stream** para iniciar, **⏹ Detener** para parar.

---

## 🔒 Reglas MITRE ATT&CK

### Generar reglas
1. Selecciona el **Kibana Space** donde cargar las reglas.
2. Marca las **tácticas MITRE** deseadas.
3. Pulsa **▶ Generar reglas en Kibana**.

Las reglas se crean directamente en Kibana con:
- Queries KQL nativas.
- Threat mapping MITRE ATT&CK completo (tactic ID, technique, subtechniques).
- Intervalo de ejecución de 5 minutos.
- Tag `SOC-Ingestor` para identificarlas.

### Tácticas y reglas disponibles

| Táctica | # Reglas | Ejemplos |
|---------|----------|----------|
| Initial Access | 3 | Brute Force, Login desde IP maliciosa, Admin externo |
| Execution | 3 | PowerShell encoded, CMD recon, LOLBin proxy |
| Persistence | 3 | Registry Run keys, Scheduled Task, Service install |
| Credential Access | 1 | Mimikatz / LSASS / SAM dump |
| Discovery | 1 | nmap, masscan, net view |
| Lateral Movement | 2 | PsExec/SMB, RDP externo |
| Defense Evasion | 2 | Certutil download, Shadow copy deletion |
| Command & Control | 3 | IP maliciosa, DGA/DNS tunnel, Puertos sospechosos |
| Exfiltration | 2 | Transferencia >10MB, Archiving con password |

### Ver alertas
1. Selecciona el **Kibana Space**.
2. Pulsa **▶ Buscar alertas**.
3. Las alertas se muestran coloreadas por severidad.

### Eliminar reglas
El botón **🗑 Eliminar reglas SOC** solo elimina las reglas con tag `SOC-Ingestor`.

---

## 📁 Estructura del proyecto

```
soc-ingestor/
├── run.py                     # Punto de entrada
├── requirements.txt           # Dependencias
├── pyproject.toml             # Metadata del paquete
├── README.md                  # Esta documentación
└── soc_ingestor/
    ├── __init__.py
    ├── app.py                 # Clase principal de la aplicación
    ├── config.py              # Gestión de configuración
    ├── clients/
    │   ├── __init__.py
    │   ├── elastic.py         # Cliente y helpers de Elasticsearch
    │   └── kibana.py          # Cliente HTTP de Kibana API
    ├── generators/
    │   ├── __init__.py
    │   ├── pools.py           # Pools de datos (IPs, hosts, users, etc.)
    │   ├── helpers.py         # Funciones auxiliares (timestamps, IPs, etc.)
    │   ├── auth.py            # Generador de logs de autenticación
    │   ├── network.py         # Generador de logs de red
    │   ├── endpoint.py        # Generador de logs de endpoint
    │   ├── dns.py             # Generador de logs de DNS
    │   └── firewall.py        # Generador de logs de firewall
    ├── rules/
    │   ├── __init__.py
    │   ├── mitre.py           # Constantes MITRE ATT&CK
    │   └── builder.py         # Constructor de reglas para Kibana
    └── ui/
        ├── __init__.py
        ├── styles.py          # Estilos ttk (tema Catppuccin)
        ├── wizard.py          # Wizard de configuración
        ├── ingestion.py       # Pestañas Bulk y Stream
        └── rules_panel.py     # Pestañas Reglas y Alertas
```

---

## ⚠ Solución de problemas

| Error | Causa | Solución |
|-------|-------|----------|
| `HTTP 302` | URL con `http://` en vez de `https://` | Cambia a `https://` |
| `HTTP 302` al conectar | Apuntando a Kibana en vez de ES | Usa `.es.` en la URL |
| `media_type_header_exception` | Cliente elasticsearch-py 9.x | `pip install "elasticsearch>=8,<9"` |
| `ConnectionError` SSL | Certificado autofirmado | Desmarca "Verificar SSL" o añade el CA |
| `403 Forbidden` en Kibana | Sin permisos de Detection Engine | Necesitas rol `superuser` o equivalente |

---

## 📄 Licencia

MIT License.
