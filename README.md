# 🛡️ CyberSec Events Tracker

**Directorio automatizado de eventos de ciberseguridad, tecnología e innovación en Chile, LATAM y el mundo.**

[![Actualización automática](https://img.shields.io/badge/actualizaci%C3%B3n-cada%203%20horas-blue)](https://github.com/ttpsecspa/cybersec-events-tracker/actions)
[![Eventos](https://img.shields.io/badge/eventos-42-brightgreen)](docs/upcoming.md)
[![Próximos](https://img.shields.io/badge/pr%C3%B3ximos-33-orange)](docs/upcoming.md)
[![Fuentes](https://img.shields.io/badge/fuentes-32-purple)](docs/sources.md)
[![MIT License](https://img.shields.io/badge/licencia-MIT-green)](LICENSE)

> Mantenido por **[TTPSEC SpA](https://ttpsec.cl)** — Consultora de ciberseguridad OT/ICS en Chile

## 📅 Próximos eventos

|  |  | Evento | Región | Fecha | Lugar | Formato |
| :---: | :---: | --- | --- | --- | --- | --- |
| 🔴 | 🇩🇴 | [HackConRD 2026 (4ta Edición)](https://hackconrd.org/) | LATAM | 2026-03-27 → 2026-03-28 | Dominican Fiesta Convention Center, Santo Domingo | Presencial |
| 🔴 | 🇺🇸 | [RSA Conference 2026](https://www.rsaconference.com/) | Global | 2026-04-06 → 2026-04-09 | San Francisco, CA | Híbrido |
| 🔴 | 🇨🇱 | [MadeInnConce 2026](https://www.madeinnconce.org/) | Chile | 2026-04-07 → 2026-04-09 | Teatro Biobío, Concepción | Presencial |
| 🔴 | 🌐 | [Descubriendo el Laberinto Digital: Explorando las Profundidades de la Seguridad de Aplicaciones con Fuzzing](https://bsidesco.short.gy/LP-Fuzz) | Global | 2026-04-22 |  | Presencial |
| 🔴 | 🇵🇪 | [CyberSecurity Bank & Government Perú 2026](https://www.mticsproducciones.com/) | LATAM | 2026-04-23 | Lima, Perú | Presencial |

> 🔴 Menos de 30 días | 🟡 Menos de 90 días | 🟢 Más de 90 días

👉 **[Ver todos los eventos →](docs/upcoming.md)**

## 📚 Índice

- 📋 **[Todos los próximos eventos](docs/upcoming.md)** (33 eventos)
- 🌎 **[Eventos por región](docs/by-region.md)** (🇨🇱 Chile: 5 | LATAM: 16 | 🌐 Global: 12)
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

- **Ciberseguridad** (32 eventos)
- **OT/ICS** (3 eventos)
- **Cloud & DevSecOps** (6 eventos)
- **IA & Data** (6 eventos)
- **Fintech** (1 eventos)
- **Transformación Digital** (5 eventos)
- **Hacking & CTF** (20 eventos)
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

Este repositorio se actualiza automáticamente **cada 3 horas** mediante GitHub Actions. El scraper revisa 32 fuentes y actualiza la documentación.

---

_🛡️ Desarrollado y mantenido por [TTPSEC SpA](https://ttpsec.cl) | Última actualización: 2026-03-24_


---
📋 [Próximos](docs/upcoming.md) | 🌎 [Por Región](docs/by-region.md) | 🏷️ [Por Categoría](docs/by-category.md) | 📅 [Calendario](docs/calendar.md) | 📡 [Fuentes](docs/sources.md)
