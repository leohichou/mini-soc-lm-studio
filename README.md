# SOC_AI – Local AI-Assisted Security Operations Center

## Overview

SOC_AI is a lightweight simulation project that reproduces the core workflow of a Security Operations Center (SOC) using autonomous agents and a locally hosted Large Language Model (LLM).

The goal of this project is to explore how AI can assist in security event analysis, classification, and automated response while keeping all data processing strictly **local**.

The system demonstrates an end-to-end pipeline:

Detection → Collection → Analysis → Response

without relying on cloud services or external APIs.

---

## Key Features

- Multi-agent architecture
- Fully local execution
- AI-assisted event analysis
- Simulated incident response
- JSON-based communication between components

---

## Architecture

The system is structured around four independent agents communicating via HTTP and JSON:

[SENSOR] → [COLLECTOR] → [ANALYZER (AI)] → [RESPONDER]

**Sensor**  
Generates simulated security events (e.g., SSH failures, port scans).

**Collector**  
Receives, aggregates, and forwards events.

**Analyzer**  
Queries a locally hosted LLM via LM Studio to:
- Assess severity
- Categorize the event
- Recommend an action

**Responder**  
Executes simulated defensive actions (e.g., IP blocking, ticket creation).

Example event:

```json
{"type": "ssh_failed", "src": "192.168.56.102"}
````

Example AI output:

```json
{
  "severity": "High",
  "category": "brute_force",
  "recommended_action": "block_ip"
}
```

---

## Technologies Used

* Python 3
* Flask (API endpoints)
* requests (inter-agent communication)
* LM Studio (local LLM runtime)
* Local LLM (e.g., Mistral, LLaMA, etc.)

No cloud services, no external API keys.

---

## Running the Project

1. Start LM Studio and load a model
2. Verify the API is available:

[http://127.0.0.1:1234/v1/models](http://127.0.0.1:1234/v1/models)

3. Launch agents in separate terminals:

```bash
python sensor.py
python collector.py
python analyzer.py
python responder.py
```

The Sensor will automatically generate events.

---

## Purpose

This project is designed to:

* Experiment with AI-assisted SOC concepts
* Understand agent-based system design
* Explore local LLM integration in cybersecurity workflows

---

## Limitations

* Simulated events only
* Basic log persistence
* AI decisions are prompt-dependent
* No full SIEM integration (ELK / Wazuh)

---

## Possible Improvements

* Persistent log storage
* Dashboard (Grafana / Kibana)
* Hybrid rule-based + AI analysis
* Expanded event types
* Knowledge base integration

