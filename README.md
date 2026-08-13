# 🛡️ User-Mode EDR (Endpoint Detection and Response)

> **⚠️ Project Status:** This project is currently **Under Active Development (Work-in-Progress)**. Features, ETW parsing logic, and telemetry pipelines are continuously being refined.

A lightweight, asynchronous **User-Mode Endpoint Detection and Response (EDR)** architecture prototype built using **C#** and **Python**. Designed to explore endpoint visibility, process monitoring, and threat response without relying on custom kernel-mode drivers.

---

## 👥 Team & Collaboration
This project is developed collaboratively as an independent open-source initiative by a dedicated development team.

---

## 🏗️ Architecture Overview

The system operates on a client-server (Agent-C2) model:
1. **The Agent (`Agent-CSharp`):** Runs on the endpoint with administrative privileges, utilizing ETW (Event Tracing for Windows) to listen directly to kernel-level process creation events in real-time.
2. **The C2 Server (`Server-Python`):** A centralized Flask-based backend that distributes detection rules (`/api/rules`) and ingests incoming security telemetry (`/api/telemetry`).

---

## 💡 Engineering Decisions & Trade-offs (Why User-Mode?)

When designing an EDR, developers face fundamental architectural trade-offs between speed, security, and OS restrictions:

* **Why not Kernel-Mode?** Writing kernel drivers requires Microsoft's official Early Launch Antimalware (ELAM) or Antimalware certification signatures. Without corporate certification, modern Windows blocks unsigned kernel drivers via Driver Signature Enforcement.
* **Why not PPL (Protected Process Light)?** PPL prevents an agent from being killed by malware, but it also strictly requires Microsoft's proprietary security certificates.
* **The ETW Trade-off:** We utilize ETW because it provides powerful visibility into kernel events from User-Mode. However, because ETW is an asynchronous post-event mechanism constrained by OS buffer flush limits (`BufferSizeMB = 1`), there is a natural 1–2 second delay before threats are caught and terminated. This repository embraces this limitation as an educational proof-of-concept (PoC).

---

## 🚀 Getting Started

### Prerequisites
* Windows 10 / 11 (for the C# Agent)
* Python 3.x (for the C2 Server)
* .NET SDK (.NET 6.0 or higher recommended)

### 1. Running the C2 Server (Python)
Navigate to the server directory, install dependencies, and start the listener:

```bash
cd Server-Python
pip install flask
python3 EDR_Console.py
```
### 2. Running the EDR Agent (C#)
*Open PowerShell as Administrator (required for ETW session creation).*
Navigate to the agent directory and run the project:

```bash
cd Agent-CSharp
dotnet run
```
---

## Tech Stack
* **Agent:** C#, .NET, `Microsoft.Diagnostics.Tracing.TraceEvent` (ETW Kernel Parser), `System.Net.Http`
* **Server:** Python, Flask, JSON REST API

---

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page or submit a pull request.

---

## 📜 License
This project is licensed under the terms of the MIT License.
