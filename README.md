# 🛡️ CyberSec Events Tracker

**Directorio automatizado de eventos de ciberseguridad, tecnología e innovación en Chile, LATAM y el mundo.**

[![Actualización automática](https://img.shields.io/badge/actualizaci%C3%B3n-lunes%20%26%20jueves-blue)](https://github.com/ttpsecspa/cybersec-events-tracker/actions)
[![Eventos](https://img.shields.io/badge/eventos-37-brightgreen)](docs/upcoming.md)
[![Próximos](https://img.shields.io/badge/pr%C3%B3ximos-34-orange)](docs/upcoming.md)
[![Fuentes](https://img.shields.io/badge/fuentes-32-purple)](docs/sources.md)
[![MIT License](https://img.shields.io/badge/licencia-MIT-green)](LICENSE)

> Mantenido por **[TTPSEC SpA](https://ttpsec.cl)** — Consultora de ciberseguridad OT/ICS en Chile

## 📅 Próximos eventos

|  |  | Evento | Región | Fecha | Lugar | Formato |
| :---: | :---: | --- | --- | --- | --- | --- |
| ✅ | 🇨🇴 | [Andina Link Smart Cities Expo 2026](https://andinalink.com/) | LATAM | 2026-03-09 → 2026-03-12 | Hotel Las Americas, Cartagena de Indias | Presencial |
| 🔴 | 🇨🇱 | [CyberSecurity Bank & Government Chile 2026](https://www.mticsproducciones.com/cybersecurity-bank-and-government-chile-2026/) | Chile | 2026-03-17 | Sheraton Santiago | Presencial |
| 🔴 | 🇵🇦 | [Cybertech Latin America 2026](https://panama.cybertechconference.com/) | LATAM | 2026-03-18 | City of Knowledge, Ciudad de Panamá | Presencial |
| 🔴 | 🇺🇸 | [Copa América de Ciberseguridad OEA 2026](https://www.oas.org/) | Global | 2026-03-18 | Virtual (CTF) | Online |
| 🔴 | 🇩🇴 | [HackConRD 2026 (4ta Edición)](https://hackconrd.org/) | LATAM | 2026-03-27 → 2026-03-28 | Dominican Fiesta Convention Center, Santo Domingo | Presencial |

> 🔴 Menos de 30 días | 🟡 Menos de 90 días | 🟢 Más de 90 días

👉 **[Ver todos los eventos →](docs/upcoming.md)**

## 📚 Índice

- 📋 **[Todos los próximos eventos](docs/upcoming.md)** (34 eventos)
- 🌎 **[Eventos por región](docs/by-region.md)** (🇨🇱 Chile: 6 | LATAM: 18 | 🌐 Global: 10)
- 🏷️ **[Eventos por categoría](docs/by-category.md)** (8 categorías)
- 📅 **[Vista calendario](docs/calendar.md)** (vista mensual con banderas)
- 📡 **[Fuentes monitoreadas](docs/sources.md)** (32 fuentes)

## ⚙️ Uso (CLI)

```bash
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar todo (scrape + generar docs + stats)
python scraper.py

# Solo scraping
python scraper.py --scrape

# Solo generar documentación
python scraper.py --generate

# Agregar evento manualmente
python scraper.py --add

# Ver estadísticas
python scraper.py --stats
```

## 🏷️ Categorías

- **Ciberseguridad** (31 eventos)
- **OT/ICS** (3 eventos)
- **Cloud & DevSecOps** (6 eventos)
- **IA & Data** (6 eventos)
- **Fintech** (1 eventos)
- **Transformación Digital** (5 eventos)
- **Hacking & CTF** (15 eventos)
- **Governance & Compliance** (10 eventos)

## 🤝 Contribuir

### Sugerir un evento

1. Abre un [nuevo issue](https://github.com/ttpsecspa/cybersec-events-tracker/issues/new?template=nuevo-evento.yml) con los datos del evento
2. O haz un Pull Request editando `data/events.json`

### Desarrollo local

```bash
git clone https://github.com/ttpsecspa/cybersec-events-tracker.git
cd cybersec-events-tracker
pip install -r requirements.txt
python scraper.py
```

## 📡 Actualización automática

Este repositorio se actualiza automáticamente cada **lunes y jueves a las 08:00 UTC** mediante GitHub Actions. El scraper revisa 32 fuentes y actualiza la documentación.

---

_🛡️ Desarrollado y mantenido por [TTPSEC SpA](https://ttpsec.cl) | Última actualización: 2026-03-10_


---
📋 [Próximos](docs/upcoming.md) | 🌎 [Por Región](docs/by-region.md) | 🏷️ [Por Categoría](docs/by-category.md) | 📅 [Calendario](docs/calendar.md) | 📡 [Fuentes](docs/sources.md)
