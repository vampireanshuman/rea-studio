# REA Studio ⚡

<p align="center">
  <strong>Next-Generation Desktop Reverse-Engineering & Architecture Visualization Studio for Electron & Node.js</strong>
</p>

<p align="center">
  <a href="https://github.com/vampireanshuman/rea-studio/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge" alt="License: MIT"></a>
  <a href="https://electronjs.org"><img src="https://img.shields.io/badge/Electron-v44-47848F?style=for-the-badge&logo=electron&logoColor=white" alt="Electron"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node.js-%3E%3D18-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js"></a>
  <img src="https://img.shields.io/badge/Display-120%2B%20FPS-FFB450?style=for-the-badge&logo=speedtest&logoColor=black" alt="120+ FPS">
  <img src="https://img.shields.io/badge/UI-Liquid%20Glass-9d4edd?style=for-the-badge" alt="Liquid Glass UI">
  <a href="https://github.com/vampireanshuman/rea-studio/issues"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge" alt="PRs Welcome"></a>
</p>

---

## 🌟 Overview

**REA Studio** is an open-source, hardware-accelerated desktop workstation designed for security researchers, reverse engineers, and full-stack developers. It visualizes the internal architecture of complex Electron, Node.js, and JavaScript applications into interactive live dependency graphs, security heatmaps, and IPC execution flows.

Powered by **REA** (`rea-agents analyze-javascript-application`), **Vis.js**, and an integrated **Google Gemini AI Copilot**, REA Studio renders AST-derived structural evidence in a high-refresh **Liquid Glass** interface.

---

## ✨ Key Features

### 🚀 120+ FPS Liquid Glass UI
* **High-Refresh Pipeline**: Built with Chromium GPU rasterization, zero-copy buffers, and an uncapped display refresh rate (120 Hz+) with a real-time delta-time FPS monitor.
* **Liquid Glass Aesthetic**: Ambient radial cursor spotlights, backdrop blurs, floating spring physics micro-interactions, and reactive glass panels.
* **Wallpaper Engine**: Built-in dynamic theme switcher with cyber, dark, and custom wallpaper overlays.

### 🕸️ Interactive AST Architecture Map
* **Organic & Hierarchical Force Graph**: Inspect Electron `Main`, `Preload`, `ContextBridge`, `Renderers`, `IPC Channels`, and local/external modules.
* **Directional Edge Pulse Particles**: Animated glowing particles travel along connecting graph lines showing execution flows (`Renderer -> Preload -> Main Process`).
* **Interactive Path Tracer**: Select any IPC endpoint (e.g., `notes:export`) or node to isolate the full caller-bridge-handler-utility trace path while softly dimming unrelated noise.
* **Export Diagrams**: One-click export to high-res SVG or copy standard Mermaid.js sequence and flow diagram syntax.

### 🛡️ Security Audit & CVE Scanner
* **Automated Security Health Score**: Real-time evaluation of Electron security posture (Context Isolation, Node Integration, Sandbox flags, remote module status, navigation vulnerabilities).
* **Side-by-Side Code Diff & AI Patch Drawer**: Inspect vulnerable code patterns with line-numbered AST evidence alongside automated defensive patches.
* **Interactive IPC Simulator**: Trace and preview mock IPC messages across process boundaries in real-time.

### 🤖 Gemini AI Copilot Integration
* Built-in multi-model Google Gemini support (**Gemini 2.5 Flash / Pro**, **Gemini 1.5 Pro / Flash**, and **Gemini 3.1 Pro**).
* Client-side private API key handling (stored strictly in local client storage, never transmitted to external third parties or committed).
* Automatic context injection: The AI understands the currently analyzed application's topology, IPC boundaries, and AST evidence.

---

## 📸 Architecture Pipeline

```
[Target Application / Source Directory]
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│  REA 19-Step AST & Static Analysis Pipeline      │
│  (Imports, IPC Bindings, ContextBridge, Asar)    │
└──────────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│  Express Analysis & Decompilation Bridge Server  │
└──────────────────────────────────────────────────┘
                   │  (Fast Local SSE & IPC)
                   ▼
┌──────────────────────────────────────────────────┐
│  Electron 120+ FPS Hardware-Accelerated Studio   │
│  ├── Liquid Glass UI Engine                      │
│  ├── Vis.js Organic Network Graph & Path Tracer  │
│  ├── Security Audit & Fix Drawer                 │
│  └── Gemini AI Copilot Integration               │
└──────────────────────────────────────────────────┘
```

---

## 🛠️ Quick Start

### Prerequisites
* [Node.js](https://nodejs.org/) (v18.0.0 or higher recommended)
* [npm](https://www.npmjs.com/) (bundled with Node.js)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vampireanshuman/rea-studio.git
   cd rea-studio
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start REA Studio Desktop:**
   ```bash
   npm start
   ```

4. *(Optional)* **Run Web Version Only:**
   ```bash
   npm run start:web
   ```
   Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🔒 Security & Privacy

* **Zero Data Telemetry**: Analyzed files and extracted AST evidence remain strictly on your local machine.
* **Safe Local Storage**: Gemini API keys are kept in your local client-side session store (`localStorage`) and are never written to disk or repository commits.
* **Sandboxed Preload**: Follows Electron security best practices with `contextIsolation: true` and guarded IPC messaging.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
Feel free to check the [issues page](https://github.com/vampireanshuman/rea-studio/issues) if you want to contribute.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feat/AmazingFeature`)
3. Commit your Changes (`git commit -m 'feat: Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feat/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is open-source and licensed under the **[MIT License](LICENSE)**.
Created and maintained with ❤️ by [Anshuman (VampireAnshuman)](https://github.com/vampireanshuman).
