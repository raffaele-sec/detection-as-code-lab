# Detection-as-Code Lab

![Project Status](https://img.shields.io/badge/Status-Active_Development-orange?style=for-the-badge)

Questo repository ospita una pipeline **Detection-as-Code (DaC)** automatizzata per la creazione, la conversione e il deployment di regole di sicurezza. Il progetto è una simulazione di un ambiente aziendale che utilizza CI/CD per gestire il ciclo di vita delle detection rule.

## 🏗️ Architettura

```mermaid
graph TD
    A[Attacker<br/>Atomic Red Team] -->|Simulazione| B(Target<br/>Windows + Sysmon)
    B -->|Log Forwarding| C{Splunk}
    D[Sigma Rules] -->|Push| E[GitHub Actions]
    E -->|Validation & Parsing| F[Python Scripts]
    F -->|Conversion| G[SPL Queries]
    F -->|Mapping| H[JSON Layer]
    G -->|Deploy API| C
    H -->|Coverage Map| I[MITRE Navigator]
```

## 📊 Stato di Avanzamento

Il progetto è in fase di sviluppo attivo. Di seguito lo stato attuale dei moduli principali:

| Componente | Stato | Dettagli |
| :--- | :--- | :--- |
| **Infrastructure** | ![80%](https://geps.dev/progress/80) | Lab locale su Fedora (Docker) + VM Windows (Sysmon/UF) configurati. |
| **Automation Scripts** | ![70%](https://geps.dev/progress/70) | Script Python per estrazione tag e conversione Sigma parzialmente completi. |
| **CI/CD Pipeline** | ![60%](https://geps.dev/progress/60) | Workflow GitHub Actions base implementato. |
| **Coverage Mapping** | ![60%](https://geps.dev/progress/60) | Generazione layer JSON completata, integrazione con ATT&CK Navigator in corso. |
| **Rules Deployment** | ![70%](https://geps.dev/progress/70) | Iniezione automatica su Splunk via REST API in fase di test. |

## 🛠️ Stack

* **SIEM:** Splunk Enterprise
* **Data Collection:** Sysmon (Olaf Hartong Config) + Splunk Universal Forwarder
* **Detection Format:** Sigma Rules
* **Coverage Framework:** MITRE ATT&CK Navigator
* **Simulation:** Atomic Red Team
* **CI/CD:** GitHub Actions

## 📂 Struttura del Repository

* `/rules`: Regole Sigma sorgente.
* `/scripts`: Tooling Python per il mapping delle Techniques ID/generazione JSON layer (`TechniqueExtractor.py`), per la conversione (`Sigma-SPLconverter.py`) e per l'eliminazione delle query (`SavedSearchDeleter.py`).
* `/.github/workflows`: Pipeline di automazione.
