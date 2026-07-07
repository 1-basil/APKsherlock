<div align="center">

# 🕵️‍♂️ APKsherlock

**A lightweight, high-impact toolkit for analyzing APKs and uncovering hidden threats fast.**

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](#)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](#)
[![Security](https://img.shields.io/badge/Cybersecurity-Enabled-red?style=for-the-badge)](#)

</div>

---

## 📌 Overview

**APKsherlock** is a comprehensive, full-stack environment designed for the rapid static and dynamic analysis of Android applications. Built for security researchers and software engineers, it streamlines the process of dissecting APKs, capturing network traffic, and performing behavior analytics within a secure, isolated container.

By combining a robust Python backend with a responsive TypeScript frontend, APKsherlock transforms complex vulnerability scanning and anomaly detection into a streamlined, visual workflow.

## ✨ Core Features

* **⚡ Static Inspection:** Instantly extract manifests, permissions, and embedded structural data without executing the payload.
* **🔬 Dynamic Sandboxing:** Safely execute applications within an isolated `/sandbox` environment to monitor runtime behavioral anomalies.
* **🌐 Network Traffic Capture:** Built-in `.pcap` analysis intercepts and logs network requests to detect data exfiltration and malicious callbacks.
* **🧠 Advanced Blob Analysis:** Utilize `analyze_blob.py` to dissect complex data structures and extract obfuscated intelligence.
* **🖥️ Unified Web Interface:** Navigate threats, view metrics, and manage uploads through a modern, component-driven frontend architecture.

## 🏗️ Architecture

The repository is modularly structured to separate the execution environment from the user interface and analysis engine:

```text
APKsherlock/
├── 📁 backend/       # Core API, analysis scripts, and data routing (Python)
├── 📁 frontend/      # User interface and visualization dashboard (TypeScript)
├── 📁 sandbox/       # Isolated execution environment for threat containment
├── 📁 dynamic/       # Runtime monitoring and behavior analytics modules
├── 📄 analyze_blob.py# Standalone script for deep data extraction
├── 📄 capture.pcap   # Network traffic logs generated during execution
└── 📄 docker-compose.yml # Container orchestration configuration
