# REA Studio ⚡

An interactive visual web application for reverse engineering and analyzing JavaScript and Electron applications using **REA** (`rea-agents analyze-javascript-application`).

## Features

- **Real-time REA Analysis**: Runs `npx rea-agents@latest analyze-javascript-application <targetPath> --json` against any local folder path with live progress streaming (19-step AST analysis pipeline).
- **Interactive Flow Diagram (Vis.js Network)**:
  - Visual graph displaying Electron Main, Preload, Context Bridge, IPC Channels, Renderers, and Modules.
  - Interactive controls: Pan, zoom, node drag, layout switcher (Hierarchical vs Organic Force-Directed), and category filters (IPC Flow, Modules & Dependencies, Core Architecture).
  - Click any node or edge to inspect full AST observations, properties, and evidence in a slide-out drawer.
- **Electron IPC Boundaries Explorer**:
  - Interactive paired cards highlighting IPC channels (e.g. `notes:export`).
  - Displays transmission flows: Renderer (`ipcRenderer.invoke`) ➔ Main Process (`ipcMain.handle`).
  - Context Bridge mapping (`window.notes.exportCsv()`).
  - One-click source code snippets with exact line and column numbers.
- **Modules & Imports Matrix**:
  - Breakdown of local project modules, Node.js built-ins (`node:path`, `node:fs`), and external packages (`electron`).
  - Specifiers, import bindings, CommonJS/ESM formats, and exports.
  - Instant live search.
- **Evidence & Provenance Inspector**:
  - Immutable REA Evidence ID, subject root SHA-256 digest, authority (`shipped-artifact`), and confidence rating.
  - Transparent list of REA static analysis limitations and disclaimers.
- **Mermaid Sequence & Flow Diagrams**:
  - One-click generation of architecture and IPC communication sequence diagrams.
  - Built-in live SVG preview and copyable Markdown code.
- **Source Code Viewer Modal**:
  - Directly inspect local file contents with line-number highlighting for AST evidence ranges.
- **Raw JSON Explorer**:
  - Formatted JSON viewer with search, copy to clipboard, and JSON export.

## Architecture

```
rea-studio/
├── server.js              # Express backend, child_process runner & SSE stream
├── package.json           # Node.js dependencies (express, cors)
├── public/
│   ├── index.html         # Clean dark-mode UI layout & Vis.js/Mermaid integration
│   ├── styles.css         # Modern dark theme design system
│   └── app.js             # Client-side state, graph rendering & API handlers
└── README.md
```

## Running the Web App

The server is currently running at:
**[http://localhost:3000](http://localhost:3000)**

To run or restart manually:
```bash
npm start
```
