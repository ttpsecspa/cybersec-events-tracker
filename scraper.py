#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cybersec-events-tracker — Directorio automatizado de eventos de ciberseguridad
Chile, LATAM y el mundo.

Desarrollado por TTPSEC SpA (https://ttpsec.cl)
Licencia: MIT
"""

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from typing import Optional

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: Instala las dependencias con 'pip install -r requirements.txt'")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DOCS_DIR = os.path.join(BASE_DIR, "docs")
EVENTS_JSON = os.path.join(DATA_DIR, "events.json")

CATEGORIAS = [
    "Ciberseguridad",
    "OT/ICS",
    "Cloud & DevSecOps",
    "IA & Data",
    "Fintech",
    "Transformación Digital",
    "Hacking & CTF",
    "Governance & Compliance",
]

BANDERAS = {
    "Chile": "\U0001f1e8\U0001f1f1",
    "México": "\U0001f1f2\U0001f1fd",
    "Perú": "\U0001f1f5\U0001f1ea",
    "Colombia": "\U0001f1e8\U0001f1f4",
    "Brasil": "\U0001f1e7\U0001f1f7",
    "USA": "\U0001f1fa\U0001f1f8",
    "España": "\U0001f1ea\U0001f1f8",
    "Argentina": "\U0001f1e6\U0001f1f7",
    "Panamá": "\U0001f1f5\U0001f1e6",
    "Costa Rica": "\U0001f1e8\U0001f1f7",
    "Ecuador": "\U0001f1ea\U0001f1e8",
    "Rep. Dominicana": "\U0001f1e9\U0001f1f4",
    "Uruguay": "\U0001f1fa\U0001f1fe",
    "Alemania": "\U0001f1e9\U0001f1ea",
    "Luxemburgo": "\U0001f1f1\U0001f1fa",
}
BANDERA_GLOBAL = "\U0001f310"

MESES_ES = {
    1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril",
    5: "Mayo", 6: "Junio", 7: "Julio", 8: "Agosto",
    9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre",
}

FUENTES = [
    # Chile
    {"id": 1,  "nombre": "MTICS Producciones",              "url": "https://www.mticsproducciones.com/",       "foco": "Ciberseguridad, Compliance"},
    {"id": 2,  "nombre": "8.8 Computer Security Conference", "url": "https://welcu.com/8dot8",                  "foco": "Hacking, Ciberseguridad"},
    {"id": 3,  "nombre": "SeguridadExpo",                    "url": "https://www.seguridadexpo.cl/",            "foco": "Ciberseguridad, OT/ICS"},
    {"id": 4,  "nombre": "América Digital",                   "url": "https://congreso.america-digital.com/",   "foco": "Transformación Digital, IA"},
    {"id": 5,  "nombre": "CybersecChile",                    "url": "https://www.cybersecchile.cl/",            "foco": "Ciberseguridad"},
    {"id": 6,  "nombre": "Eventbrite Chile Ciberseguridad",  "url": "https://www.eventbrite.cl/",               "foco": "Ciberseguridad"},
    # LATAM — México
    {"id": 7,  "nombre": "Infosecurity México",              "url": "https://www.infosecuritymexico.com/",      "foco": "Ciberseguridad"},
    # LATAM — Colombia
    {"id": 8,  "nombre": "DragonJAR Security Conference",    "url": "https://www.dragonjarcon.org/",            "foco": "Hacking, Ciberseguridad"},
    {"id": 9,  "nombre": "ANDICOM",                           "url": "https://andicom.co/en/",                  "foco": "Ciberseguridad, IA, Telecom"},
    {"id": 10, "nombre": "Tactical Edge / CISOS Summit",     "url": "https://tacticaledge.co/",                 "foco": "CISO, Governance"},
    # LATAM — Argentina
    {"id": 11, "nombre": "Ekoparty",                          "url": "https://ekoparty.org/",                   "foco": "Hacking, Ciberseguridad"},
    {"id": 12, "nombre": "Segurinfo",                         "url": "https://www.segurinfo.org/",              "foco": "Ciberseguridad, Governance"},
    # LATAM — Brasil
    {"id": 13, "nombre": "Mind The Sec",                      "url": "https://www.mindthesec.com.br/",          "foco": "Ciberseguridad, Enterprise"},
    {"id": 14, "nombre": "H2HC (Hackers to Hackers Conf.)",   "url": "https://www.h2hc.com.br/",               "foco": "Hacking, Research"},
    {"id": 15, "nombre": "Roadsec",                            "url": "https://www.roadsec.com.br/",            "foco": "Hacking, CTF, Festival"},
    {"id": 16, "nombre": "Futurecom",                          "url": "https://www.futurecom.com.br/en/home.html", "foco": "Telecom, 5G, Ciberseguridad"},
    # LATAM — Panamá
    {"id": 17, "nombre": "Cybertech Latin America",           "url": "https://panama.cybertechconference.com/",  "foco": "Ciberseguridad, Gobierno"},
    # LATAM — Perú
    {"id": 18, "nombre": "SEGURITEC Perú",                    "url": "https://www.seguritecperu.com/",           "foco": "Ciberseguridad, Seguridad"},
    # LATAM — Rep. Dominicana
    {"id": 19, "nombre": "HackConRD",                         "url": "https://hackconrd.org/",                   "foco": "Hacking, Ciberseguridad"},
    # LATAM — Multi-país
    {"id": 20, "nombre": "ISEC Infosecurity Tour",            "url": "https://isec-infosecurity.com/vip/",       "foco": "Ciberseguridad, IA"},
    {"id": 21, "nombre": "LACNIC",                             "url": "https://www.lacnic.net/",                 "foco": "Internet, Infraestructura"},
    {"id": 22, "nombre": "ISACA Events",                       "url": "https://www.isaca.org/training-and-events", "foco": "Governance, Auditoría"},
    # OT/ICS
    {"id": 23, "nombre": "CCI - Centro Ciberseguridad Ind.",  "url": "https://cci-es.org/eventos/",              "foco": "OT/ICS"},
    {"id": 24, "nombre": "S4 Events (ICS/SCADA)",             "url": "https://s4xevents.com/",                   "foco": "OT/ICS"},
    {"id": 25, "nombre": "CS4CA LatAm",                        "url": "https://latam.cs4ca.com/",                "foco": "OT/ICS, Ciberseguridad"},
    # Global
    {"id": 26, "nombre": "RSA Conference",                     "url": "https://www.rsaconference.com/",          "foco": "Ciberseguridad, Cloud"},
    {"id": 27, "nombre": "Black Hat",                           "url": "https://www.blackhat.com/",              "foco": "Hacking, Ciberseguridad"},
    {"id": 28, "nombre": "DEF CON",                             "url": "https://defcon.org/",                   "foco": "Hacking"},
    {"id": 29, "nombre": "FIRST.org",                           "url": "https://www.first.org/events/",         "foco": "Incident Response, CSIRT"},
    {"id": 30, "nombre": "Gartner Security & Risk (Brasil)",   "url": "https://www.gartner.com/en/conferences/la/security-risk-management-brazil", "foco": "Governance, Risk"},
    {"id": 31, "nombre": "CrowdStrike Fal.Con",                "url": "https://www.crowdstrike.com/en-us/events/fal-con/", "foco": "Ciberseguridad, Threat Intel"},
    {"id": 32, "nombre": "BSides Colombia",                     "url": "http://www.bsidesco.org/",              "foco": "Hacking, Comunidad"},
]

# ──────────────────────────────────────────────────────────────────────────────
# Eventos semilla verificados (marzo 2026)
# ──────────────────────────────────────────────────────────────────────────────
EVENTOS_SEMILLA = [
    {
        "name": "CyberSecurity Bank & Government Chile 2026",
        "date_start": "2026-03-17",
        "date_end": None,
        "location": "Sheraton Santiago",
        "country": "Chile",
        "region": "Chile",
        "categories": ["Ciberseguridad", "Governance & Compliance"],
        "url": "https://www.mticsproducciones.com/cybersecurity-bank-and-government-chile-2026/",
        "description": "Congreso de ciberseguridad enfocado en banca, entidades financieras y gobierno",
        "cost": "Gratis para C-Level sector financiero/gobierno",
        "format": "Presencial",
        "organizer": "MTICS Producciones",
        "cfp_deadline": None,
        "relevance_tags": ["banca", "gobierno", "finanzas", "CISO"],
        "source": "MTICS Producciones",
    },
    {
        "name": "RSA Conference 2026",
        "date_start": "2026-04-06",
        "date_end": "2026-04-09",
        "location": "San Francisco, CA",
        "country": "USA",
        "region": "Global",
        "categories": ["Ciberseguridad", "Cloud & DevSecOps", "Governance & Compliance"],
        "url": "https://www.rsaconference.com/",
        "description": "La conferencia de ciberseguridad más grande del mundo",
        "cost": None,
        "format": "Híbrido",
        "organizer": "RSA",
        "cfp_deadline": None,
        "relevance_tags": ["enterprise", "cloud", "zero-trust", "keynotes"],
        "source": "RSA Conference",
    },
    {
        "name": "MadeInnConce 2026",
        "date_start": "2026-04-07",
        "date_end": "2026-04-09",
        "location": "Teatro Biobío, Concepción",
        "country": "Chile",
        "region": "Chile",
        "categories": ["Transformación Digital", "IA & Data"],
        "url": "https://www.madeinnconce.org/",
        "description": "Conferencia de innovación y emprendimiento tecnológico en la región del Biobío",
        "cost": None,
        "format": "Presencial",
        "organizer": "MadeInnConce",
        "cfp_deadline": None,
        "relevance_tags": ["innovación", "emprendimiento", "Biobío"],
        "source": "MadeInnConce",
    },
    {
        "name": "8.8 Unreal Peru 2026",
        "date_start": "2026-05-06",
        "date_end": None,
        "location": "Miraflores, Lima",
        "country": "Perú",
        "region": "LATAM",
        "categories": ["Hacking & CTF", "Ciberseguridad"],
        "url": "https://welcu.com/8dot8",
        "description": "Conferencia hacker técnica de seguridad de la información",
        "cost": "Gratis",
        "format": "Presencial",
        "organizer": "8.8 Computer Security Conference",
        "cfp_deadline": None,
        "relevance_tags": ["hacking", "ofensivo", "red-team"],
        "source": "8.8 Computer Security Conference",
    },
    {
        "name": "Chile Fintech Forum 2026",
        "date_start": "2026-05-06",
        "date_end": "2026-05-07",
        "location": "Espacio Riesco, Santiago",
        "country": "Chile",
        "region": "Chile",
        "categories": ["Fintech", "Ciberseguridad"],
        "url": "https://www.chilefintechforum.com/",
        "description": "IA, identidad digital, ciberseguridad en la industria financiera",
        "cost": None,
        "format": "Presencial",
        "organizer": "FinteChile",
        "cfp_deadline": None,
        "relevance_tags": ["fintech", "identidad-digital", "banca"],
        "source": "Chile Fintech Forum",
    },
    {
        "name": "CyberSecurity Bank & Government México 2026",
        "date_start": "2026-05-14",
        "date_end": None,
        "location": "Marriott Reforma, CDMX",
        "country": "México",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "Governance & Compliance"],
        "url": "https://www.mticsproducciones.com/cybersecurity-bank-and-government-mexico-2026/",
        "description": "Congreso de ciberseguridad para banca y gobierno en México",
        "cost": None,
        "format": "Presencial",
        "organizer": "MTICS Producciones",
        "cfp_deadline": None,
        "relevance_tags": ["banca", "gobierno", "México"],
        "source": "MTICS Producciones",
    },
    {
        "name": "CCICON LATAM 2026 - Congreso Ciberseguridad Industrial",
        "date_start": "2026-05-26",
        "date_end": "2026-05-27",
        "location": "Ciudad de México",
        "country": "México",
        "region": "LATAM",
        "categories": ["OT/ICS", "Ciberseguridad"],
        "url": "https://cci-con.org/congreso/26/",
        "description": "Congreso Internacional de Ciberseguridad Industrial. ISA/IEC 62443, IIoT, IA aplicada a OT",
        "cost": None,
        "format": "Presencial",
        "organizer": "CCI",
        "cfp_deadline": None,
        "relevance_tags": ["OT", "ICS", "IEC-62443", "SCADA"],
        "source": "CCI - Centro Ciberseguridad Ind.",
    },
    {
        "name": "Expo Seguridad México + Infosecurity México 2026",
        "date_start": "2026-06-02",
        "date_end": "2026-06-04",
        "location": "Centro Citibanamex, CDMX",
        "country": "México",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "Cloud & DevSecOps"],
        "url": "https://www.exposeguridadmexico.com",
        "description": "Ecosistema integral: seguridad física, digital e industrial. +35 conferencias, +400 expositores",
        "cost": None,
        "format": "Presencial",
        "organizer": "RX",
        "cfp_deadline": None,
        "relevance_tags": ["expo", "seguridad-física", "industrial"],
        "source": "Infosecurity México",
    },
    {
        "name": "Black Hat USA 2026",
        "date_start": "2026-08-01",
        "date_end": "2026-08-06",
        "location": "Las Vegas, NV",
        "country": "USA",
        "region": "Global",
        "categories": ["Hacking & CTF", "Ciberseguridad"],
        "url": "https://www.blackhat.com/",
        "description": "Conferencia de seguridad con trainings y briefings técnicos de clase mundial",
        "cost": None,
        "format": "Presencial",
        "organizer": "Black Hat / Informa",
        "cfp_deadline": None,
        "relevance_tags": ["trainings", "briefings", "0-day", "research"],
        "source": "Black Hat",
    },
    {
        "name": "DEF CON 34",
        "date_start": "2026-08-06",
        "date_end": "2026-08-09",
        "location": "Las Vegas, NV",
        "country": "USA",
        "region": "Global",
        "categories": ["Hacking & CTF", "Ciberseguridad"],
        "url": "https://defcon.org/",
        "description": "La convención hacker más grande del mundo. Villages, CTFs, charlas técnicas",
        "cost": None,
        "format": "Presencial",
        "organizer": "DEF CON",
        "cfp_deadline": None,
        "relevance_tags": ["villages", "CTF", "hardware", "comunidad"],
        "source": "DEF CON",
    },
    {
        "name": "SeguridadExpo Chile 2026",
        "date_start": "2026-09-08",
        "date_end": "2026-09-10",
        "location": "Metropolitan Santiago",
        "country": "Chile",
        "region": "Chile",
        "categories": ["Ciberseguridad", "OT/ICS"],
        "url": "https://www.seguridadexpo.cl/",
        "description": "Feria internacional líder de seguridad convergente en Chile",
        "cost": None,
        "format": "Presencial",
        "organizer": "SeguridadExpo",
        "cfp_deadline": None,
        "relevance_tags": ["feria", "seguridad-convergente", "expo"],
        "source": "SeguridadExpo",
    },
    {
        "name": "América Digital 2026 - 11° Congreso Latinoamericano",
        "date_start": "2026-09-09",
        "date_end": "2026-09-10",
        "location": "Espacio Riesco, Santiago",
        "country": "Chile",
        "region": "Chile",
        "categories": ["Transformación Digital", "IA & Data", "Ciberseguridad"],
        "url": "https://congreso.america-digital.com/",
        "description": "+5,000 C-Levels, +200 stands tech. IA, IoT, Cloud, Ciberseguridad, Fintech",
        "cost": None,
        "format": "Presencial",
        "organizer": "América Digital",
        "cfp_deadline": None,
        "relevance_tags": ["congreso", "C-Level", "IA", "IoT"],
        "source": "América Digital",
    },
    {
        "name": "8.8 Unreal Chile 2026",
        "date_start": "2026-10-01",
        "date_end": "2026-10-02",
        "location": "Santiago",
        "country": "Chile",
        "region": "Chile",
        "categories": ["Hacking & CTF", "Ciberseguridad"],
        "url": "https://unreal.8dot8.org/",
        "description": "La conferencia hacker técnica más importante de Chile y LATAM",
        "cost": None,
        "format": "Presencial",
        "organizer": "8.8 Computer Security Conference / Fundación 8.8",
        "cfp_deadline": None,
        "relevance_tags": ["hacking", "ofensivo", "research", "Chile"],
        "source": "8.8 Computer Security Conference",
    },
    # ── Nuevos eventos LATAM verificados (marzo 2026) ──────────────────────
    # Panamá
    {
        "name": "Cybertech Latin America 2026",
        "date_start": "2026-03-18",
        "date_end": None,
        "location": "City of Knowledge, Ciudad de Panamá",
        "country": "Panamá",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "Governance & Compliance"],
        "url": "https://panama.cybertechconference.com/",
        "description": "Plataforma internacional donde tecnología y ciberseguridad convergen. Academia, gobierno e industria",
        "cost": None,
        "format": "Presencial",
        "organizer": "Cybertech Global",
        "cfp_deadline": None,
        "relevance_tags": ["gobierno", "industria", "Panamá"],
        "source": "Cybertech Latin America",
    },
    # Rep. Dominicana
    {
        "name": "HackConRD 2026 (4ta Edición)",
        "date_start": "2026-03-27",
        "date_end": "2026-03-28",
        "location": "Dominican Fiesta Convention Center, Santo Domingo",
        "country": "Rep. Dominicana",
        "region": "LATAM",
        "categories": ["Hacking & CTF", "Ciberseguridad", "IA & Data"],
        "url": "https://hackconrd.org/",
        "description": "El evento de ciberseguridad y hacking más grande del Caribe y Centroamérica. 600+ asistentes",
        "cost": None,
        "format": "Presencial",
        "organizer": "RedTeamRD",
        "cfp_deadline": None,
        "relevance_tags": ["hacking", "Caribe", "CTF", "RF"],
        "source": "HackConRD",
    },
    # Perú — MTICS
    {
        "name": "CyberSecurity Bank & Government Perú 2026",
        "date_start": "2026-04-23",
        "date_end": None,
        "location": "Lima, Perú",
        "country": "Perú",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "Governance & Compliance"],
        "url": "https://www.mticsproducciones.com/",
        "description": "14° edición del congreso de ciberseguridad enfocado en banca y gobierno",
        "cost": None,
        "format": "Presencial",
        "organizer": "MTICS Producciones",
        "cfp_deadline": None,
        "relevance_tags": ["banca", "gobierno", "Perú"],
        "source": "MTICS Producciones",
    },
    # Brasil — Gartner
    {
        "name": "Gartner Security & Risk Management Summit Brasil 2026",
        "date_start": "2026-04-28",
        "date_end": "2026-04-29",
        "location": "São Paulo, Brasil",
        "country": "Brasil",
        "region": "LATAM",
        "categories": ["Governance & Compliance", "Ciberseguridad", "Cloud & DevSecOps"],
        "url": "https://www.gartner.com/en/conferences/la/security-risk-management-brazil",
        "description": "Cumbre de estrategia de ciberseguridad, riesgo, IA y cloud con expertos Gartner",
        "cost": None,
        "format": "Presencial",
        "organizer": "Gartner",
        "cfp_deadline": None,
        "relevance_tags": ["Gartner", "CISO", "risk", "strategy"],
        "source": "Gartner Security & Risk (Brasil)",
    },
    # México — LACNIC
    {
        "name": "LACNIC 45",
        "date_start": "2026-05-11",
        "date_end": "2026-05-14",
        "location": "Guadalajara, México",
        "country": "México",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "Cloud & DevSecOps"],
        "url": "https://www.lacnic.net/",
        "description": "Encuentro regional multistakeholder: Internet, seguridad de redes e infraestructura en LATAM",
        "cost": None,
        "format": "Presencial",
        "organizer": "LACNIC",
        "cfp_deadline": None,
        "relevance_tags": ["internet", "IPv6", "infraestructura", "redes"],
        "source": "LACNIC",
    },
    # Argentina — Ekoparty Miami
    {
        "name": "Ekoparty Miami 2026",
        "date_start": "2026-05-21",
        "date_end": "2026-05-22",
        "location": "Miami Beach, FL",
        "country": "USA",
        "region": "Global",
        "categories": ["Hacking & CTF", "Ciberseguridad"],
        "url": "https://ekoparty.org/miami/",
        "description": "Primera edición internacional de Ekoparty. Charlas, villages, CTF y networking",
        "cost": None,
        "format": "Presencial",
        "organizer": "Ekoparty",
        "cfp_deadline": None,
        "relevance_tags": ["ekoparty", "hacking", "LATAM-community"],
        "source": "Ekoparty",
    },
    # Perú — SEGURITEC
    {
        "name": "SEGURITEC Perú 2026",
        "date_start": "2026-05-27",
        "date_end": "2026-05-29",
        "location": "Centro de Exposiciones Jockey, Lima",
        "country": "Perú",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "OT/ICS"],
        "url": "https://www.seguritecperu.com/",
        "description": "15° edición. Feria líder de seguridad y comunicaciones en Latinoamérica",
        "cost": None,
        "format": "Presencial",
        "organizer": "SEGURITEC",
        "cfp_deadline": None,
        "relevance_tags": ["feria", "seguridad-física", "expo"],
        "source": "SEGURITEC Perú",
    },
    # Global — FIRST
    {
        "name": "FIRST Annual Conference 2026 (38th)",
        "date_start": "2026-06-14",
        "date_end": "2026-06-19",
        "location": "Denver, Colorado",
        "country": "USA",
        "region": "Global",
        "categories": ["Ciberseguridad", "Governance & Compliance"],
        "url": "https://www.first.org/conference/2026/",
        "description": "Conferencia anual CSIRT/PSIRT — líderes mundiales en respuesta a incidentes",
        "cost": None,
        "format": "Presencial",
        "organizer": "FIRST.org",
        "cfp_deadline": None,
        "relevance_tags": ["CSIRT", "incident-response", "PSIRT"],
        "source": "FIRST.org",
    },
    # Global — CrowdStrike
    {
        "name": "CrowdStrike Fal.Con 2026",
        "date_start": "2026-08-31",
        "date_end": "2026-09-03",
        "location": "Mandalay Bay, Las Vegas, NV",
        "country": "USA",
        "region": "Global",
        "categories": ["Ciberseguridad", "Cloud & DevSecOps"],
        "url": "https://www.crowdstrike.com/en-us/events/fal-con/",
        "description": "10,000+ asistentes. Threat Summit, keynotes, labs prácticos. La mayor edición",
        "cost": None,
        "format": "Presencial",
        "organizer": "CrowdStrike",
        "cfp_deadline": None,
        "relevance_tags": ["threat-intel", "endpoint", "XDR", "cloud"],
        "source": "CrowdStrike Fal.Con",
    },
    # Colombia — ANDICOM
    {
        "name": "ANDICOM 2026",
        "date_start": "2026-09-01",
        "date_end": "2026-09-04",
        "location": "Hotel Las Americas, Cartagena de Indias",
        "country": "Colombia",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "IA & Data", "Transformación Digital"],
        "url": "https://andicom.co/en/",
        "description": "Congreso TIC premier de LATAM. Ciberseguridad, IA, Smart Cities",
        "cost": None,
        "format": "Presencial",
        "organizer": "CINTEL",
        "cfp_deadline": None,
        "relevance_tags": ["telecom", "smart-cities", "IA"],
        "source": "ANDICOM",
    },
    # Ecuador — ISACA LATAM
    {
        "name": "ISACA Latin American Congress 2026",
        "date_start": "2026-09-09",
        "date_end": "2026-09-11",
        "location": "JW Marriott, Quito",
        "country": "Ecuador",
        "region": "LATAM",
        "categories": ["Governance & Compliance", "Ciberseguridad"],
        "url": "https://www.isaca.org/training-and-events",
        "description": "Congreso regional de auditoría, ciberseguridad y gestión de riesgos para CIOs y CISOs",
        "cost": None,
        "format": "Presencial",
        "organizer": "ISACA",
        "cfp_deadline": None,
        "relevance_tags": ["auditoría", "governance", "CISO", "riesgo"],
        "source": "ISACA Events",
    },
    # Colombia — DragonJAR
    {
        "name": "DragonJAR Security Conference 2026 (13° Edición)",
        "date_start": "2026-09-10",
        "date_end": "2026-09-11",
        "location": "Centro de Eventos El Tesoro, Medellín",
        "country": "Colombia",
        "region": "LATAM",
        "categories": ["Hacking & CTF", "Ciberseguridad"],
        "url": "https://www.dragonjarcon.org/",
        "description": "La conferencia de seguridad informática más influyente de Colombia. 0-day research, red team",
        "cost": None,
        "format": "Presencial",
        "organizer": "DragonJAR",
        "cfp_deadline": None,
        "relevance_tags": ["0-day", "red-team", "ofensivo", "research"],
        "source": "DragonJAR Security Conference",
    },
    # Brasil — Mind The Sec
    {
        "name": "Mind The Sec 2026",
        "date_start": "2026-09-15",
        "date_end": "2026-09-17",
        "location": "Transamerica Expo Center, São Paulo",
        "country": "Brasil",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "Governance & Compliance"],
        "url": "https://www.mindthesec.com.br/",
        "description": "Mayor congreso de ciberseguridad del hemisferio sur. 10,000+ participantes, 100+ sponsors",
        "cost": None,
        "format": "Presencial",
        "organizer": "Mind The Sec",
        "cfp_deadline": None,
        "relevance_tags": ["enterprise", "networking", "expo", "Brasil"],
        "source": "Mind The Sec",
    },
    # Brasil — Futurecom
    {
        "name": "Futurecom 2026 (31° Edición)",
        "date_start": "2026-10-06",
        "date_end": "2026-10-08",
        "location": "São Paulo Expo, São Paulo",
        "country": "Brasil",
        "region": "LATAM",
        "categories": ["Transformación Digital", "Ciberseguridad", "Cloud & DevSecOps"],
        "url": "https://www.futurecom.com.br/",
        "description": "29,000+ personas de 40 países. 5G/6G, IoT, cloud, ciberseguridad, data centers",
        "cost": None,
        "format": "Presencial",
        "organizer": "Futurecom",
        "cfp_deadline": None,
        "relevance_tags": ["5G", "IoT", "telecom", "cloud"],
        "source": "Futurecom",
    },
    # Panamá — MTICS
    {
        "name": "CyberSecurity Bank & Government Panamá 2026",
        "date_start": "2026-10-22",
        "date_end": None,
        "location": "Sheraton Grand Panama, Ciudad de Panamá",
        "country": "Panamá",
        "region": "LATAM",
        "categories": ["Ciberseguridad", "Governance & Compliance"],
        "url": "https://www.mticsproducciones.com/cybersecurity-bank-and-government-panama-2026/",
        "description": "Charlas y paneles exclusivos de ciberseguridad para banca y gobierno en Panamá",
        "cost": None,
        "format": "Presencial",
        "organizer": "MTICS Producciones",
        "cfp_deadline": None,
        "relevance_tags": ["banca", "gobierno", "Panamá"],
        "source": "MTICS Producciones",
    },
    # Argentina — Ekoparty Buenos Aires
    {
        "name": "Ekoparty Buenos Aires 2026",
        "date_start": "2026-11-02",
        "date_end": "2026-11-04",
        "location": "Centro de Convenciones Buenos Aires (CEC)",
        "country": "Argentina",
        "region": "LATAM",
        "categories": ["Hacking & CTF", "Ciberseguridad"],
        "url": "https://ekoparty.org/",
        "description": "La conferencia de ciberseguridad más grande de LATAM. 10,000 asistentes, 250+ charlas, CTF, villages",
        "cost": None,
        "format": "Presencial",
        "organizer": "Ekoparty",
        "cfp_deadline": None,
        "relevance_tags": ["hacking", "CTF", "villages", "comunidad"],
        "source": "Ekoparty",
    },
    # Colombia — Andina Link
    {
        "name": "Andina Link Smart Cities Expo 2026",
        "date_start": "2026-03-09",
        "date_end": "2026-03-12",
        "location": "Hotel Las Americas, Cartagena de Indias",
        "country": "Colombia",
        "region": "LATAM",
        "categories": ["Transformación Digital", "IA & Data"],
        "url": "https://andinalink.com/",
        "description": "31+ años. Innovación, tecnología y telecomunicaciones en LATAM. 200+ expositores, 6,000+ asistentes",
        "cost": None,
        "format": "Presencial",
        "organizer": "Andina Link",
        "cfp_deadline": None,
        "relevance_tags": ["smart-cities", "telecom", "IoT"],
        "source": "Andina Link",
    },
    # Global — OEA
    {
        "name": "Copa América de Ciberseguridad OEA 2026",
        "date_start": "2026-03-18",
        "date_end": None,
        "location": "Virtual (CTF)",
        "country": "USA",
        "region": "Global",
        "categories": ["Hacking & CTF", "Ciberseguridad"],
        "url": "https://www.oas.org/",
        "description": "1° edición. CTF organizado por OEA/CICTE. Equipos de estados miembros miden preparación ante incidentes",
        "cost": "Gratis",
        "format": "Online",
        "organizer": "OEA / CICTE",
        "cfp_deadline": None,
        "relevance_tags": ["CTF", "CSIRT", "gobierno", "OEA"],
        "source": "OEA",
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# 1. Event (dataclass)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Event:
    """Representa un evento de ciberseguridad / tecnología."""
    name: str
    date_start: str  # YYYY-MM-DD
    date_end: Optional[str] = None
    location: str = ""
    country: str = ""
    region: str = "Global"  # Chile | LATAM | Global
    categories: list = field(default_factory=list)
    url: str = ""
    description: str = ""
    cost: Optional[str] = None
    format: str = "Presencial"  # Presencial | Online | Híbrido
    organizer: str = ""
    cfp_deadline: Optional[str] = None
    relevance_tags: list = field(default_factory=list)
    source: str = ""
    last_updated: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))

    @property
    def event_id(self) -> str:
        """ID único basado en nombre + fecha + país."""
        raw = f"{self.name}{self.date_start}{self.country}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    @property
    def is_upcoming(self) -> bool:
        """Retorna True si el evento aún no ha ocurrido."""
        try:
            end = self.date_end or self.date_start
            return datetime.strptime(end, "%Y-%m-%d").date() >= date.today()
        except (ValueError, TypeError):
            return False

    @property
    def days_until(self) -> int:
        """Días hasta el inicio del evento. Negativo si ya pasó."""
        try:
            d = datetime.strptime(self.date_start, "%Y-%m-%d").date()
            return (d - date.today()).days
        except (ValueError, TypeError):
            return -9999

    @property
    def bandera(self) -> str:
        """Emoji de bandera del país."""
        return BANDERAS.get(self.country, BANDERA_GLOBAL)

    @property
    def urgencia(self) -> str:
        """Indicador de urgencia por proximidad."""
        d = self.days_until
        if d < 0:
            return "\u2705"   # ya pasó / en curso
        if d <= 30:
            return "\U0001f534"  # rojo — menos de 30 días
        if d <= 90:
            return "\U0001f7e1"  # amarillo — menos de 90 días
        return "\U0001f7e2"      # verde — más de 90 días

    @property
    def fecha_display(self) -> str:
        """Fecha formateada para mostrar."""
        start = self.date_start or "TBD"
        if self.date_end and self.date_end != self.date_start:
            return f"{start} → {self.date_end}"
        return start

    def to_dict(self) -> dict:
        """Convierte a diccionario serializable."""
        d = asdict(self)
        d["event_id"] = self.event_id
        d["is_upcoming"] = self.is_upcoming
        d["days_until"] = self.days_until
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Event":
        """Crea un Event desde un diccionario."""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


# ──────────────────────────────────────────────────────────────────────────────
# 2. EventDatabase
# ──────────────────────────────────────────────────────────────────────────────

class EventDatabase:
    """Gestiona la base de datos de eventos en JSON."""

    def __init__(self, path: str = EVENTS_JSON):
        self.path = path
        self.events: list[Event] = []
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def load(self) -> None:
        """Carga eventos desde el archivo JSON."""
        if not os.path.exists(self.path):
            self.events = []
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_events = data.get("events", [])
            self.events = [Event.from_dict(e) for e in raw_events]
            print(f"  \U0001f4c2 Cargados {len(self.events)} eventos desde {self.path}")
        except (json.JSONDecodeError, KeyError) as exc:
            print(f"  \u26a0\ufe0f  Error al leer JSON: {exc}")
            self.events = []

    def save(self) -> None:
        """Guarda eventos en el archivo JSON."""
        upcoming = [e for e in self.events if e.is_upcoming]
        data = {
            "metadata": {
                "project": "cybersec-events-tracker",
                "maintainer": "TTPSEC SpA — https://ttpsec.cl",
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "total_events": len(self.events),
                "upcoming_events": len(upcoming),
                "categories": CATEGORIAS,
                "regions": ["Chile", "LATAM", "Global"],
            },
            "events": sorted(
                [e.to_dict() for e in self.events],
                key=lambda x: x.get("date_start", "9999-99-99"),
            ),
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  \U0001f4be Guardados {len(self.events)} eventos en {self.path}")

    def add_event(self, event: Event) -> bool:
        """Agrega un evento si no existe (por event_id). Retorna True si se agregó."""
        existing_ids = {e.event_id for e in self.events}
        if event.event_id in existing_ids:
            return False
        self.events.append(event)
        return True

    def get_upcoming(self, region: Optional[str] = None) -> list[Event]:
        """Retorna eventos próximos, opcionalmente filtrados por región."""
        upcoming = [e for e in self.events if e.is_upcoming]
        if region:
            upcoming = [e for e in upcoming if e.region == region]
        return sorted(upcoming, key=lambda e: e.date_start)

    def get_by_category(self, category: str) -> list[Event]:
        """Retorna eventos que pertenecen a una categoría."""
        return sorted(
            [e for e in self.events if category in e.categories],
            key=lambda e: e.date_start,
        )

    def get_past(self) -> list[Event]:
        """Retorna eventos pasados."""
        return sorted(
            [e for e in self.events if not e.is_upcoming],
            key=lambda e: e.date_start, reverse=True,
        )

    def stats(self) -> dict:
        """Estadísticas de la base de datos."""
        upcoming = self.get_upcoming()
        return {
            "total": len(self.events),
            "upcoming": len(upcoming),
            "past": len(self.events) - len(upcoming),
            "chile": len([e for e in upcoming if e.region == "Chile"]),
            "latam": len([e for e in upcoming if e.region == "LATAM"]),
            "global": len([e for e in upcoming if e.region == "Global"]),
            "categorias": {
                cat: len(self.get_by_category(cat)) for cat in CATEGORIAS
            },
        }


# ──────────────────────────────────────────────────────────────────────────────
# 3. EventScraper
# ──────────────────────────────────────────────────────────────────────────────

class EventScraper:
    """Scraper de eventos desde múltiples fuentes web."""

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "es-CL,es;q=0.9,en;q=0.8",
    }
    TIMEOUT = 15

    # Patrón de fecha en español: "17 de marzo de 2026", "17-03-2026", etc.
    DATE_PATTERNS = [
        # YYYY-MM-DD
        re.compile(r"(\d{4})-(\d{2})-(\d{2})"),
        # DD/MM/YYYY o DD-MM-YYYY
        re.compile(r"(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})"),
        # "17 de marzo de 2026"
        re.compile(
            r"(\d{1,2})\s+de\s+(enero|febrero|marzo|abril|mayo|junio|"
            r"julio|agosto|septiembre|octubre|noviembre|diciembre)"
            r"\s+(?:de\s+)?(\d{4})",
            re.IGNORECASE,
        ),
    ]
    MESES_MAP = {
        "enero": 1, "febrero": 2, "marzo": 3, "abril": 4,
        "mayo": 5, "junio": 6, "julio": 7, "agosto": 8,
        "septiembre": 9, "octubre": 10, "noviembre": 11, "diciembre": 12,
    }

    def __init__(self, db: EventDatabase):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)

    def _fetch_page(self, url: str) -> Optional[BeautifulSoup]:
        """Descarga y parsea una página web."""
        try:
            resp = self.session.get(url, timeout=self.TIMEOUT)
            resp.raise_for_status()
            return BeautifulSoup(resp.content, "lxml")
        except requests.RequestException as exc:
            print(f"    \u26a0\ufe0f  No se pudo acceder a {url}: {exc}")
            return None

    def _parse_date_text(self, text: str) -> Optional[str]:
        """Intenta extraer una fecha YYYY-MM-DD de un texto."""
        for pattern in self.DATE_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            groups = match.groups()
            try:
                if len(groups) == 3 and groups[0].isdigit() and len(groups[0]) == 4:
                    # YYYY-MM-DD
                    return f"{groups[0]}-{groups[1].zfill(2)}-{groups[2].zfill(2)}"
                if len(groups) == 3 and groups[2].isdigit() and len(groups[2]) == 4:
                    if groups[1].isdigit():
                        # DD/MM/YYYY
                        return f"{groups[2]}-{groups[1].zfill(2)}-{groups[0].zfill(2)}"
                    else:
                        # "17 de marzo de 2026"
                        mes = self.MESES_MAP.get(groups[1].lower())
                        if mes:
                            return f"{groups[2]}-{str(mes).zfill(2)}-{groups[0].zfill(2)}"
            except (ValueError, IndexError):
                continue
        return None

    def _extract_events_generic(self, soup: BeautifulSoup, source_name: str,
                                 base_url: str) -> list[dict]:
        """Extracción genérica de eventos desde HTML."""
        found = []
        # Buscar en headings
        for tag in soup.find_all(["h1", "h2", "h3", "h4", "h5"]):
            title = tag.get_text(" ", strip=True)
            # Limpiar whitespace múltiple
            title = re.sub(r"\s+", " ", title).strip()
            if len(title) < 5 or len(title) > 200:
                continue

            # Buscar fecha cercana al título
            parent = tag.parent or tag
            text_block = parent.get_text(" ", strip=True)
            date_str = self._parse_date_text(text_block)

            # Validar que la fecha sea razonable (2024-2030)
            if date_str:
                try:
                    dt = datetime.strptime(date_str, "%Y-%m-%d")
                    if dt.year < 2024 or dt.year > 2030:
                        continue
                except ValueError:
                    continue

            # Buscar link
            link_tag = tag.find("a") or tag.find_next("a")
            url = ""
            if link_tag and link_tag.get("href"):
                href = link_tag["href"]
                if href.startswith("http"):
                    url = href
                elif href.startswith("/"):
                    url = base_url.rstrip("/") + href

            if date_str:
                found.append({
                    "name": title,
                    "date_start": date_str,
                    "url": url,
                    "source": source_name,
                })
        return found

    def scrape_source(self, source: dict) -> int:
        """Scrapea una fuente individual. Retorna cantidad de eventos encontrados."""
        nombre = source["nombre"]
        url = source["url"]
        print(f"  \U0001f50d Scrapeando: {nombre} ({url})")

        soup = self._fetch_page(url)
        if not soup:
            return 0

        raw_events = self._extract_events_generic(soup, nombre, url)
        added = 0
        for raw in raw_events:
            event = Event(
                name=raw["name"],
                date_start=raw["date_start"],
                url=raw.get("url", url),
                source=nombre,
                categories=self._infer_categories(raw["name"], source.get("foco", "")),
                country=self._infer_country(raw["name"], source),
                region=self._infer_region(source),
            )
            if self.db.add_event(event):
                added += 1
        print(f"    \u2705 {added} eventos nuevos desde {nombre}")
        return added

    def _infer_categories(self, title: str, foco: str) -> list[str]:
        """Infiere categorías desde el título y foco de la fuente."""
        cats = []
        combined = f"{title} {foco}".lower()
        keywords = {
            "Ciberseguridad": ["ciberseguridad", "cybersec", "security", "seguridad"],
            "OT/ICS": ["ot/ics", "ics", "scada", "industrial", "ot "],
            "Cloud & DevSecOps": ["cloud", "devsecops", "devops", "aws", "azure"],
            "IA & Data": ["ia ", "inteligencia artificial", "ai ", "data", "machine learning"],
            "Fintech": ["fintech", "financier", "banking", "banca"],
            "Transformación Digital": ["transformación digital", "digital transform", "innovación"],
            "Hacking & CTF": ["hack", "ctf", "pentest", "ofensiv", "red team", "bug bounty"],
            "Governance & Compliance": ["governance", "compliance", "regulat", "normativ", "iso 27"],
        }
        for cat, kws in keywords.items():
            if any(kw in combined for kw in kws):
                cats.append(cat)
        return cats or ["Ciberseguridad"]

    def _infer_country(self, title: str, source: dict) -> str:
        """Infiere el país del evento."""
        combined = f"{title} {source.get('url', '')}".lower()
        if any(kw in combined for kw in ["chile", ".cl"]):
            return "Chile"
        if any(kw in combined for kw in ["méxico", "mexico", ".mx"]):
            return "México"
        if any(kw in combined for kw in ["perú", "peru", ".pe"]):
            return "Perú"
        if any(kw in combined for kw in ["colombia", ".co", "medell", "bogot", "cartagena"]):
            return "Colombia"
        if any(kw in combined for kw in ["brasil", "brazil", ".br", "são paulo", "sao paulo"]):
            return "Brasil"
        if any(kw in combined for kw in ["argentina", ".ar", "buenos aires"]):
            return "Argentina"
        if any(kw in combined for kw in ["panamá", "panama", ".pa"]):
            return "Panamá"
        if any(kw in combined for kw in ["costa rica", ".cr"]):
            return "Costa Rica"
        if any(kw in combined for kw in ["ecuador", ".ec", "quito"]):
            return "Ecuador"
        if any(kw in combined for kw in ["dominicana", ".do", "santo domingo"]):
            return "Rep. Dominicana"
        if any(kw in combined for kw in ["uruguay", ".uy"]):
            return "Uruguay"
        return ""

    def _infer_region(self, source: dict) -> str:
        """Infiere la región desde la URL de la fuente."""
        url = source.get("url", "").lower()
        if ".cl" in url:
            return "Chile"
        if any(ext in url for ext in [".mx", ".pe", ".co", ".br", ".ar", ".pa", ".cr", ".ec", ".do", ".uy"]):
            return "LATAM"
        return "Global"

    def load_seed_events(self) -> int:
        """Carga los eventos semilla. Retorna cantidad agregada."""
        added = 0
        for seed in EVENTOS_SEMILLA:
            event = Event.from_dict(seed)
            if self.db.add_event(event):
                added += 1
        print(f"  \U0001f331 {added} eventos semilla cargados")
        return added

    def scrape_all(self) -> dict:
        """Ejecuta scraping de todas las fuentes + semilla."""
        print("\n\U0001f6e1\ufe0f  Iniciando scraping de eventos de ciberseguridad...")
        print("=" * 60)

        # SIEMPRE cargar semilla primero
        seed_count = self.load_seed_events()

        # Intentar scraping real de cada fuente
        scraped = 0
        errors = 0
        for source in FUENTES:
            try:
                scraped += self.scrape_source(source)
            except Exception as exc:
                print(f"    \u274c Error en {source['nombre']}: {exc}")
                errors += 1

        total = len(self.db.events)
        print("=" * 60)
        print(f"\U0001f4ca Resumen: {total} eventos totales "
              f"({seed_count} semilla + {scraped} scrapeados, {errors} errores)")

        return {
            "total": total,
            "seed": seed_count,
            "scraped": scraped,
            "errors": errors,
        }


# ──────────────────────────────────────────────────────────────────────────────
# 4. MarkdownGenerator
# ──────────────────────────────────────────────────────────────────────────────

class MarkdownGenerator:
    """Genera todos los archivos Markdown del proyecto."""

    def __init__(self, db: EventDatabase):
        self.db = db
        self.today = date.today().strftime("%Y-%m-%d")

    def _nav_bar(self) -> str:
        """Barra de navegación entre documentos."""
        return (
            "\n\n---\n"
            "\U0001f4cb [Próximos](docs/upcoming.md) | "
            "\U0001f30e [Por Región](docs/by-region.md) | "
            "\U0001f3f7\ufe0f [Por Categoría](docs/by-category.md) | "
            "\U0001f4c5 [Calendario](docs/calendar.md) | "
            "\U0001f4e1 [Fuentes](docs/sources.md)\n"
        )

    def _nav_bar_docs(self) -> str:
        """Barra de navegación desde docs/."""
        return (
            "\n\n---\n"
            "\U0001f3e0 [README](../README.md) | "
            "\U0001f4cb [Próximos](upcoming.md) | "
            "\U0001f30e [Por Región](by-region.md) | "
            "\U0001f3f7\ufe0f [Por Categoría](by-category.md) | "
            "\U0001f4c5 [Calendario](calendar.md) | "
            "\U0001f4e1 [Fuentes](sources.md)\n"
        )

    def _event_row(self, event: Event, show_region: bool = False) -> str:
        """Fila de tabla Markdown para un evento."""
        name_link = f"[{event.name}]({event.url})" if event.url else event.name
        cols = [
            event.urgencia,
            event.bandera,
            name_link,
            event.fecha_display,
            event.location,
            event.format,
        ]
        if show_region:
            cols.insert(3, event.region)
        return "| " + " | ".join(cols) + " |"

    def _table_header(self, show_region: bool = False) -> str:
        """Encabezado de tabla Markdown."""
        cols = ["", "", "Evento", "Fecha", "Lugar", "Formato"]
        if show_region:
            cols.insert(3, "Región")
        sep = [":---:" if i < 2 else "---" for i in range(len(cols))]
        header = "| " + " | ".join(cols) + " |"
        separator = "| " + " | ".join(sep) + " |"
        return f"{header}\n{separator}"

    def generate_readme(self) -> str:
        """Genera el README.md principal."""
        upcoming = self.db.get_upcoming()[:5]
        stats = self.db.stats()

        lines = []
        # Header
        lines.append("# \U0001f6e1\ufe0f CyberSec Events Tracker")
        lines.append("")
        lines.append("**Directorio automatizado de eventos de ciberseguridad, "
                      "tecnología e innovación en Chile, LATAM y el mundo.**")
        lines.append("")
        lines.append("[![Actualización automática]"
                      "(https://img.shields.io/badge/actualizaci%C3%B3n-lunes%20%26%20jueves-blue)]"
                      "(https://github.com/ttpsecspa/cybersec-events-tracker/actions)")
        lines.append("[![Eventos]"
                      f"(https://img.shields.io/badge/eventos-{stats['total']}-brightgreen)]"
                      "(docs/upcoming.md)")
        lines.append("[![Próximos]"
                      f"(https://img.shields.io/badge/pr%C3%B3ximos-{stats['upcoming']}-orange)]"
                      "(docs/upcoming.md)")
        lines.append("[![Fuentes]"
                      f"(https://img.shields.io/badge/fuentes-{len(FUENTES)}-purple)]"
                      "(docs/sources.md)")
        lines.append("[![MIT License]"
                      "(https://img.shields.io/badge/licencia-MIT-green)]"
                      "(LICENSE)")
        lines.append("")
        lines.append("> Mantenido por **[TTPSEC SpA](https://ttpsec.cl)** "
                      "— Consultora de ciberseguridad OT/ICS en Chile")
        lines.append("")

        # Próximos eventos (top 5)
        lines.append("## \U0001f4c5 Próximos eventos")
        lines.append("")
        if upcoming:
            lines.append(self._table_header(show_region=True))
            for event in upcoming:
                lines.append(self._event_row(event, show_region=True))
        else:
            lines.append("_No hay eventos próximos registrados._")
        lines.append("")
        lines.append(f"> \U0001f534 Menos de 30 días | \U0001f7e1 Menos de 90 días "
                      f"| \U0001f7e2 Más de 90 días")
        lines.append("")
        lines.append(f"\U0001f449 **[Ver todos los eventos →](docs/upcoming.md)**")
        lines.append("")

        # Índice
        lines.append("## \U0001f4da Índice")
        lines.append("")
        lines.append(f"- \U0001f4cb **[Todos los próximos eventos](docs/upcoming.md)** "
                      f"({stats['upcoming']} eventos)")
        lines.append(f"- \U0001f30e **[Eventos por región](docs/by-region.md)** "
                      f"(\U0001f1e8\U0001f1f1 Chile: {stats['chile']} | "
                      f"LATAM: {stats['latam']} | "
                      f"\U0001f310 Global: {stats['global']})")
        lines.append(f"- \U0001f3f7\ufe0f **[Eventos por categoría](docs/by-category.md)** "
                      f"({len(CATEGORIAS)} categorías)")
        lines.append(f"- \U0001f4c5 **[Vista calendario](docs/calendar.md)** "
                      f"(vista mensual con banderas)")
        lines.append(f"- \U0001f4e1 **[Fuentes monitoreadas](docs/sources.md)** "
                      f"({len(FUENTES)} fuentes)")
        lines.append("")

        # CLI
        lines.append("## \u2699\ufe0f Uso (CLI)")
        lines.append("")
        lines.append("```bash")
        lines.append("# Instalar dependencias")
        lines.append("pip install -r requirements.txt")
        lines.append("")
        lines.append("# Ejecutar todo (scrape + generar docs + stats)")
        lines.append("python scraper.py")
        lines.append("")
        lines.append("# Solo scraping")
        lines.append("python scraper.py --scrape")
        lines.append("")
        lines.append("# Solo generar documentación")
        lines.append("python scraper.py --generate")
        lines.append("")
        lines.append("# Agregar evento manualmente")
        lines.append("python scraper.py --add")
        lines.append("")
        lines.append("# Ver estadísticas")
        lines.append("python scraper.py --stats")
        lines.append("```")
        lines.append("")

        # Categorías
        lines.append("## \U0001f3f7\ufe0f Categorías")
        lines.append("")
        for cat in CATEGORIAS:
            count = stats["categorias"].get(cat, 0)
            lines.append(f"- **{cat}** ({count} eventos)")
        lines.append("")

        # Contribuir
        lines.append("## \U0001f91d Contribuir")
        lines.append("")
        lines.append("### Sugerir un evento")
        lines.append("")
        lines.append("1. Abre un [nuevo issue]"
                      "(https://github.com/ttpsecspa/cybersec-events-tracker/issues/new"
                      "?template=nuevo-evento.yml) con los datos del evento")
        lines.append("2. O haz un Pull Request editando `data/events.json`")
        lines.append("")
        lines.append("### Desarrollo local")
        lines.append("")
        lines.append("```bash")
        lines.append("git clone https://github.com/ttpsecspa/cybersec-events-tracker.git")
        lines.append("cd cybersec-events-tracker")
        lines.append("pip install -r requirements.txt")
        lines.append("python scraper.py")
        lines.append("```")
        lines.append("")

        # Footer
        lines.append("## \U0001f4e1 Actualización automática")
        lines.append("")
        lines.append("Este repositorio se actualiza automáticamente cada **lunes y jueves "
                      "a las 08:00 UTC** mediante GitHub Actions. El scraper revisa "
                      f"{len(FUENTES)} fuentes y actualiza la documentación.")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(f"_\U0001f6e1\ufe0f Desarrollado y mantenido por "
                      f"[TTPSEC SpA](https://ttpsec.cl) | "
                      f"Última actualización: {self.today}_")

        lines.append(self._nav_bar())

        content = "\n".join(lines)
        path = os.path.join(BASE_DIR, "README.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  \U0001f4dd README.md generado")
        return content

    def generate_upcoming(self) -> str:
        """Genera docs/upcoming.md con todos los eventos próximos."""
        upcoming = self.db.get_upcoming()
        lines = []
        lines.append("# \U0001f4cb Próximos eventos de ciberseguridad")
        lines.append("")
        lines.append(f"> Total: **{len(upcoming)}** eventos próximos | "
                      f"Actualizado: {self.today}")
        lines.append("")
        lines.append(f"> \U0001f534 Menos de 30 días | \U0001f7e1 Menos de 90 días "
                      f"| \U0001f7e2 Más de 90 días")
        lines.append("")

        if upcoming:
            lines.append("| | | Evento | Fecha | Lugar | Formato | Costo |")
            lines.append("| :---: | :---: | --- | --- | --- | --- | --- |")
            for event in upcoming:
                name_link = f"[{event.name}]({event.url})" if event.url else event.name
                cost = event.cost or "—"
                lines.append(
                    f"| {event.urgencia} | {event.bandera} "
                    f"| {name_link} | {event.fecha_display} "
                    f"| {event.location} | {event.format} | {cost} |"
                )
        else:
            lines.append("_No hay eventos próximos registrados._")

        lines.append(self._nav_bar_docs())
        content = "\n".join(lines)
        path = os.path.join(DOCS_DIR, "upcoming.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  \U0001f4dd docs/upcoming.md generado")
        return content

    def generate_by_region(self) -> str:
        """Genera docs/by-region.md agrupado por región."""
        lines = []
        lines.append("# \U0001f30e Eventos por región")
        lines.append("")
        lines.append(f"> Actualizado: {self.today}")
        lines.append("")

        for region, emoji in [
            ("Chile", "\U0001f1e8\U0001f1f1"),
            ("LATAM", "\U0001f30e"),
            ("Global", "\U0001f310"),
        ]:
            events = self.db.get_upcoming(region=region)
            lines.append(f"## {emoji} {region} ({len(events)} eventos)")
            lines.append("")
            if events:
                lines.append(self._table_header())
                for event in events:
                    lines.append(self._event_row(event))
            else:
                lines.append(f"_No hay eventos próximos en {region}._")
            lines.append("")

        lines.append(self._nav_bar_docs())
        content = "\n".join(lines)
        path = os.path.join(DOCS_DIR, "by-region.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  \U0001f4dd docs/by-region.md generado")
        return content

    def generate_by_category(self) -> str:
        """Genera docs/by-category.md agrupado por categoría."""
        lines = []
        lines.append("# \U0001f3f7\ufe0f Eventos por categoría")
        lines.append("")
        lines.append(f"> Actualizado: {self.today}")
        lines.append("")

        cat_emojis = {
            "Ciberseguridad": "\U0001f6e1\ufe0f",
            "OT/ICS": "\U0001f3ed",
            "Cloud & DevSecOps": "\u2601\ufe0f",
            "IA & Data": "\U0001f916",
            "Fintech": "\U0001f4b3",
            "Transformación Digital": "\U0001f680",
            "Hacking & CTF": "\U0001f3f4\u200d\u2620\ufe0f",
            "Governance & Compliance": "\U0001f4dc",
        }

        for cat in CATEGORIAS:
            events = [e for e in self.db.get_by_category(cat) if e.is_upcoming]
            emoji = cat_emojis.get(cat, "")
            lines.append(f"## {emoji} {cat} ({len(events)} eventos)")
            lines.append("")
            if events:
                lines.append(self._table_header(show_region=True))
                for event in events:
                    lines.append(self._event_row(event, show_region=True))
            else:
                lines.append(f"_No hay eventos próximos en {cat}._")
            lines.append("")

        lines.append(self._nav_bar_docs())
        content = "\n".join(lines)
        path = os.path.join(DOCS_DIR, "by-category.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  \U0001f4dd docs/by-category.md generado")
        return content

    def generate_calendar(self) -> str:
        """Genera docs/calendar.md con vista mensual."""
        upcoming = self.db.get_upcoming()
        lines = []
        lines.append("# \U0001f4c5 Calendario de eventos")
        lines.append("")
        lines.append(f"> Actualizado: {self.today}")
        lines.append("")

        # Agrupar por mes
        by_month: dict[str, list[Event]] = {}
        for event in upcoming:
            try:
                dt = datetime.strptime(event.date_start, "%Y-%m-%d")
                key = f"{dt.year}-{dt.month:02d}"
                by_month.setdefault(key, []).append(event)
            except ValueError:
                continue

        for month_key in sorted(by_month.keys()):
            events = by_month[month_key]
            year, month_num = month_key.split("-")
            month_name = MESES_ES.get(int(month_num), month_key)

            lines.append(f"### \U0001f4c6 {month_name} {year}")
            lines.append("")
            lines.append("| Día | | Evento | Lugar | Formato |")
            lines.append("| :---: | :---: | --- | --- | --- |")
            for event in sorted(events, key=lambda e: e.date_start):
                try:
                    day = datetime.strptime(event.date_start, "%Y-%m-%d").day
                except ValueError:
                    day = "?"
                name_link = f"[{event.name}]({event.url})" if event.url else event.name
                lines.append(
                    f"| {day} | {event.bandera} | {name_link} "
                    f"| {event.location} | {event.format} |"
                )
            lines.append("")

        if not by_month:
            lines.append("_No hay eventos próximos para mostrar en el calendario._")

        lines.append(self._nav_bar_docs())
        content = "\n".join(lines)
        path = os.path.join(DOCS_DIR, "calendar.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  \U0001f4dd docs/calendar.md generado")
        return content

    def generate_sources(self) -> str:
        """Genera docs/sources.md con las fuentes monitoreadas."""
        lines = []
        lines.append("# \U0001f4e1 Fuentes monitoreadas")
        lines.append("")
        lines.append(f"> Total: **{len(FUENTES)}** fuentes | Actualizado: {self.today}")
        lines.append("")
        lines.append("El scraper revisa automáticamente las siguientes fuentes "
                      "cada lunes y jueves:")
        lines.append("")
        lines.append("| # | Fuente | URL | Foco |")
        lines.append("| :---: | --- | --- | --- |")
        for src in FUENTES:
            lines.append(
                f"| {src['id']} | **{src['nombre']}** "
                f"| [{src['url']}]({src['url']}) | {src['foco']} |"
            )
        lines.append("")
        lines.append("### \U0001f527 Agregar una fuente")
        lines.append("")
        lines.append("Para agregar una nueva fuente de eventos, abre un "
                      "[issue](https://github.com/ttpsecspa/cybersec-events-tracker/issues) "
                      "con la URL y descripción de la fuente.")
        lines.append("")

        lines.append(self._nav_bar_docs())
        content = "\n".join(lines)
        path = os.path.join(DOCS_DIR, "sources.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  \U0001f4dd docs/sources.md generado")
        return content

    def generate_all(self) -> None:
        """Genera todos los archivos Markdown."""
        print("\n\U0001f4dd Generando documentación Markdown...")
        print("=" * 60)
        os.makedirs(DOCS_DIR, exist_ok=True)
        self.generate_readme()
        self.generate_upcoming()
        self.generate_by_region()
        self.generate_by_category()
        self.generate_calendar()
        self.generate_sources()
        print("=" * 60)
        print("\u2705 Toda la documentación generada correctamente")


# ──────────────────────────────────────────────────────────────────────────────
# 5. CLI (argparse)
# ──────────────────────────────────────────────────────────────────────────────

def interactive_add(db: EventDatabase) -> None:
    """Modo interactivo para agregar un evento."""
    print("\n\U0001f4dd Agregar nuevo evento")
    print("=" * 40)

    name = input("Nombre del evento: ").strip()
    if not name:
        print("\u274c Nombre requerido.")
        return

    date_start = input("Fecha inicio (YYYY-MM-DD): ").strip()
    if not re.match(r"\d{4}-\d{2}-\d{2}", date_start):
        print("\u274c Formato de fecha inválido.")
        return

    date_end = input("Fecha fin (YYYY-MM-DD, Enter para omitir): ").strip() or None
    location = input("Ubicación: ").strip()
    country = input("País: ").strip()

    print("Regiones: Chile, LATAM, Global")
    region = input("Región: ").strip() or "Global"

    print(f"Categorías disponibles: {', '.join(CATEGORIAS)}")
    cats_input = input("Categorías (separadas por coma): ").strip()
    categories = [c.strip() for c in cats_input.split(",") if c.strip()]

    url = input("URL: ").strip()
    description = input("Descripción: ").strip()
    cost = input("Costo (Enter para omitir): ").strip() or None

    print("Formatos: Presencial, Online, Híbrido")
    fmt = input("Formato: ").strip() or "Presencial"

    organizer = input("Organizador: ").strip()

    event = Event(
        name=name,
        date_start=date_start,
        date_end=date_end,
        location=location,
        country=country,
        region=region,
        categories=categories,
        url=url,
        description=description,
        cost=cost,
        format=fmt,
        organizer=organizer,
        source="Manual",
    )

    if db.add_event(event):
        db.save()
        print(f"\u2705 Evento '{name}' agregado correctamente (ID: {event.event_id})")
    else:
        print(f"\u26a0\ufe0f  El evento '{name}' ya existe en la base de datos.")


def show_stats(db: EventDatabase) -> None:
    """Muestra estadísticas de la base de datos."""
    stats = db.stats()
    print("\n\U0001f4ca Estadísticas del tracker")
    print("=" * 50)
    print(f"  \U0001f4c1 Total de eventos:     {stats['total']}")
    print(f"  \U0001f4c5 Próximos:             {stats['upcoming']}")
    print(f"  \U0001f4e6 Pasados:              {stats['past']}")
    print(f"  \U0001f1e8\U0001f1f1 Chile:               {stats['chile']}")
    print(f"  \U0001f30e LATAM:                {stats['latam']}")
    print(f"  \U0001f310 Global:               {stats['global']}")
    print()
    print("  \U0001f3f7\ufe0f  Eventos por categoría:")
    for cat, count in stats["categorias"].items():
        bar = "\u2588" * count + "\u2591" * (15 - min(count, 15))
        print(f"     {cat:.<30s} {count:>3d} {bar}")
    print("=" * 50)


def main():
    """Punto de entrada CLI."""
    parser = argparse.ArgumentParser(
        description="\U0001f6e1\ufe0f CyberSec Events Tracker — TTPSEC SpA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python scraper.py              Ejecutar todo\n"
            "  python scraper.py --scrape     Solo scraping\n"
            "  python scraper.py --generate   Solo generar docs\n"
            "  python scraper.py --add        Agregar evento interactivo\n"
            "  python scraper.py --stats      Mostrar estadísticas\n"
        ),
    )
    parser.add_argument("--scrape", action="store_true",
                        help="Ejecutar scraping de fuentes")
    parser.add_argument("--generate", action="store_true",
                        help="Generar documentación Markdown")
    parser.add_argument("--add", action="store_true",
                        help="Agregar evento de forma interactiva")
    parser.add_argument("--stats", action="store_true",
                        help="Mostrar estadísticas")
    args = parser.parse_args()

    # Si no se pasa ningún flag, ejecutar todo
    run_all = not any([args.scrape, args.generate, args.add, args.stats])

    # Inicializar DB
    db = EventDatabase()
    db.load()

    if args.add:
        interactive_add(db)
        return

    if run_all or args.scrape:
        scraper = EventScraper(db)
        scraper.scrape_all()
        db.save()

    if run_all or args.generate:
        gen = MarkdownGenerator(db)
        gen.generate_all()

    if run_all or args.stats:
        show_stats(db)

    if run_all:
        print(f"\n\u2705 Proyecto actualizado correctamente — {datetime.now().strftime('%Y-%m-%d %H:%M')}")


if __name__ == "__main__":
    main()
