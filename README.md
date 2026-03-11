# 🛡️ CyberSec Events Tracker

**Directorio automatizado de eventos de ciberseguridad, tecnología e innovación en Chile, LATAM y el mundo.**

[![Actualización automática](https://img.shields.io/badge/actualizaci%C3%B3n-lunes%20%26%20jueves-blue)](https://github.com/ttpsecspa/cybersec-events-tracker/actions)
[![Eventos](https://img.shields.io/badge/eventos-16-brightgreen)](docs/upcoming.md)
[![Próximos](https://img.shields.io/badge/pr%C3%B3ximos-13-orange)](docs/upcoming.md)
[![Fuentes](https://img.shields.io/badge/fuentes-12-purple)](docs/sources.md)
[![MIT License](https://img.shields.io/badge/licencia-MIT-green)](LICENSE)

> Mantenido por **[TTPSEC SpA](https://ttpsec.cl)** — Consultora de ciberseguridad OT/ICS en Chile

## 📅 Próximos eventos

|  |  | Evento | Región | Fecha | Lugar | Formato |
| :---: | :---: | --- | --- | --- | --- | --- |
| 🔴 | 🇨🇱 | [CyberSecurity Bank & Government Chile 2026](https://www.mticsproducciones.com/cybersecurity-bank-and-government-chile-2026/) | Chile | 2026-03-17 | Sheraton Santiago | Presencial |
| 🔴 | 🇺🇸 | [RSA Conference 2026](https://www.rsaconference.com/) | Global | 2026-04-06 → 2026-04-09 | San Francisco, CA | Híbrido |
| 🔴 | 🇨🇱 | [MadeInnConce 2026](https://www.madeinnconce.org/) | Chile | 2026-04-07 → 2026-04-09 | Teatro Biobío, Concepción | Presencial |
| 🟡 | 🇵🇪 | [8.8 Unreal Peru 2026](https://welcu.com/8dot8) | LATAM | 2026-05-06 | Miraflores, Lima | Presencial |
| 🟡 | 🇨🇱 | [Chile Fintech Forum 2026](https://www.chilefintechforum.com/) | Chile | 2026-05-06 → 2026-05-07 | Espacio Riesco, Santiago | Presencial |

> 🔴 Menos de 30 días | 🟡 Menos de 90 días | 🟢 Más de 90 días

👉 **[Ver todos los eventos →](docs/upcoming.md)**

## 📚 Índice

- 📋 **[Todos los próximos eventos](docs/upcoming.md)** (13 eventos)
- 🌎 **[Eventos por región](docs/by-region.md)** (🇨🇱 Chile: 6 | LATAM: 4 | 🌐 Global: 3)
- 🏷️ **[Eventos por categoría](docs/by-category.md)** (8 categorías)
- 📅 **[Vista calendario](docs/calendar.md)** (vista mensual con banderas)
- 📡 **[Fuentes monitoreadas](docs/sources.md)** (12 fuentes)

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

- **Ciberseguridad** (12 eventos)
- **OT/ICS** (2 eventos)
- **Cloud & DevSecOps** (2 eventos)
- **IA & Data** (2 eventos)
- **Fintech** (1 eventos)
- **Transformación Digital** (2 eventos)
- **Hacking & CTF** (7 eventos)
- **Governance & Compliance** (3 eventos)

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

Este repositorio se actualiza automáticamente cada **lunes y jueves a las 08:00 UTC** mediante GitHub Actions. El scraper revisa 12 fuentes y actualiza la documentación.

---

_🛡️ Desarrollado y mantenido por [TTPSEC SpA](https://ttpsec.cl) | Última actualización: 2026-03-10_


---
📋 [Próximos](docs/upcoming.md) | 🌎 [Por Región](docs/by-region.md) | 🏷️ [Por Categoría](docs/by-category.md) | 📅 [Calendario](docs/calendar.md) | 📡 [Fuentes](docs/sources.md)
