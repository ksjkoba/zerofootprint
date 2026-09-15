# ZeroFootprint

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Qdrant](https://img.shields.io/badge/Vector_DB-Qdrant-DC2626)](https://qdrant.tech/)

A local-first personal identity and attack surface auditor. ZeroFootprint maps exposed public profile endpoints, extracts visual feature vectors using a local PyTorch ResNet-18 model, indexes embeddings into Qdrant for cross-account correlation, flags unstripped EXIF metadata leaks, and generates statutory GDPR/CCPA erasure notices.

---

### Key Features

* **Local-First Execution:** Runs entirely on your host via Docker. Zero external API calls, third-party trackers, or cloud storage.
* **Biometric & Avatar Correlation:** Extracts 512-dimensional feature vectors locally and indexes them into Qdrant to detect reused avatars across pseudonyms.
* **EXIF Metadata Inspection:** Automatically scans images for camera make/model, timestamps, and embedded GPS coordinates.
* **Interactive Threat Graph:** Visualizes pivot points and exposed platforms dynamically using Cytoscape.js.
* **Statutory Remediation:** Auto-generates pre-filled GDPR Article 17 ("Right to be Forgotten") and CCPA § 1798.105 erasure notices.
* **Audit Reporting:** Exports a timestamped JSON risk assessment file.

---

### Architecture Overview

```text
┌──────────────────────────────────────────────────────────┐
│              Browser Dashboard (Local UI)                │
│       • Target Alias Input & Avatar Upload               │
│       • Interactive Cytoscape Graph & Inspector Drawer   │
└─────────────────────────────┬────────────────────────────┘
                              │ HTTP / REST
┌─────────────────────────────▼────────────────────────────┐
│         FastAPI Audit Engine (Port 8090)                 │
│   ├── Parallel Async Platform Reconnaissance             │
│   ├── Local PyTorch ResNet-18 Vector Extraction          │
│   └── Binary EXIF Metadata Inspector                     │
└─────────────────────────────┬────────────────────────────┘
                              │ gRPC / REST (Port 6333)
┌─────────────────────────────▼────────────────────────────┐
│               Qdrant Vector Database                     │
│       • 512-d Cosine Similarity Index                    │
│       • Local Vector Persistence Engine                  │
└──────────────────────────────────────────────────────────┘
