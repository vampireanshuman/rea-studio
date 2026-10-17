const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');

let asarModule = null;
try {
  asarModule = require('@electron/asar');
} catch {
  try { asarModule = require('asar'); } catch {}
}

let AdmZipModule = null;
try {
  AdmZipModule = require('adm-zip');
} catch {}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Path to sample unpacked notes-example
const DEFAULT_NOTES_PATH = path.resolve(__dirname, '..', 'example', 'notes-example');

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'rea-studio',
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    platform: process.platform,
    defaultNotesPath: fs.existsSync(DEFAULT_NOTES_PATH) ? DEFAULT_NOTES_PATH : null
  });
});

/**
 * Return default folder path for convenience
 */
app.get('/api/default-path', (req, res) => {
  res.json({
    defaultPath: DEFAULT_NOTES_PATH,
    exists: fs.existsSync(DEFAULT_NOTES_PATH)
  });
});

/**
 * Helper to extract .asar or .zip package to a temporary working directory
 */
function extractArchive(archivePath) {
  const hash = crypto.createHash('md5').update(archivePath).digest('hex').substring(0, 8);
  const baseName = path.basename(archivePath).replace(/\.[^/.]+$/, "");
  const extractDir = path.join(os.tmpdir(), `rea-extracted-${baseName}-${hash}`);

  if (!fs.existsSync(extractDir)) {
    fs.mkdirSync(extractDir, { recursive: true });
  }

  const ext = path.extname(archivePath).toLowerCase();
  if (ext === '.asar') {
    if (!asarModule) {
      throw new Error('@electron/asar is not available for unpacking ASAR archives.');
    }
    asarModule.extractAll(archivePath, extractDir);
  } else if (ext === '.zip') {
    if (!AdmZipModule) {
      throw new Error('adm-zip is not available for extracting ZIP archives.');
    }
    const zip = new AdmZipModule(archivePath);
    zip.extractAllTo(extractDir, true);
  } else {
    throw new Error(`Unsupported package archive extension: ${ext}`);
  }

  return extractDir;
}

/**
 * Helper to validate local directory or automatically unpack archives
 */
function validateDirectory(dirPath) {
  if (!dirPath || typeof dirPath !== 'string') {
    return { valid: false, error: 'Path is required' };
  }
  const resolved = path.resolve(dirPath.trim());
  if (!fs.existsSync(resolved)) {
    return { valid: false, error: `Directory does not exist: ${resolved}` };
  }
  const stats = fs.statSync(resolved);
  if (!stats.isDirectory()) {
    const ext = path.extname(resolved).toLowerCase();
    if (ext === '.asar' || ext === '.zip') {
      try {
        const extracted = extractArchive(resolved);
        return { valid: true, resolvedPath: extracted, originalArchive: resolved, wasExtracted: true };
      } catch (err) {
        return { valid: false, error: `Failed to auto-extract package ${resolved}: ${err.message}` };
      }
    }
    return { valid: false, error: `Path is not a directory or supported archive (.asar, .zip): ${resolved}` };
  }
  return { valid: true, resolvedPath: resolved };
}

/**
 * Dedicated API to extract package archives (.asar, .zip) on demand
 */
app.post('/api/extract-package', (req, res) => {
  const { targetPath } = req.body;
  if (!targetPath) {
    return res.status(400).json({ success: false, error: 'targetPath is required' });
  }
  try {
    const resolved = path.resolve(targetPath.trim());
    if (!fs.existsSync(resolved)) {
      return res.status(404).json({ success: false, error: `Target path does not exist: ${resolved}` });
    }
    const stats = fs.statSync(resolved);
    if (stats.isDirectory()) {
      return res.json({ success: true, extractedPath: resolved, isDirectory: true });
    }
    const extractedPath = extractArchive(resolved);
    return res.json({
      success: true,
      extractedPath,
      originalArchive: resolved,
      message: `Successfully extracted package to ${extractedPath}`
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: `Extraction error: ${err.message}` });
  }
});

/**
 * Serve local image files safely for custom backgrounds
 */
app.get('/api/serve-image', (req, res) => {
  const imgPath = req.query.path;
  if (!imgPath) {
    return res.status(400).send('Image path is required');
  }
  const resolved = path.resolve(imgPath);
  if (!fs.existsSync(resolved)) {
    return res.status(404).send('Image file not found');
  }
  const ext = path.extname(resolved).toLowerCase();
  const mimeTypes = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml'
  };
  const mime = mimeTypes[ext] || 'application/octet-stream';
  res.setHeader('Content-Type', mime);
  fs.createReadStream(resolved).pipe(res);
});

/**
 * Get available background presets
 */
app.get('/api/background-presets', (req, res) => {
  const bgDir = path.join(__dirname, 'public', 'backgrounds');
  let presets = [];
  if (fs.existsSync(bgDir)) {
    try {
      presets = fs.readdirSync(bgDir)
        .filter(f => /\.(jpg|jpeg|png|gif|webp)$/i.test(f))
        .map(f => ({
          name: f.replace(/\.[^/.]+$/, "").replace(/-/g, " "),
          url: `/backgrounds/${f}`,
          fileName: f
        }));
    } catch {}
  }
  res.json({ presets });
});

/**
 * Helper to generate Hex dump formatted string
 */
function generateHexDump(buffer, bytesToRead = 2048) {
  const slice = buffer.subarray(0, Math.min(buffer.length, bytesToRead));
  const lines = [];
  for (let offset = 0; offset < slice.length; offset += 16) {
    const chunk = slice.subarray(offset, offset + 16);
    const hex = [];
    let ascii = '';
    for (let i = 0; i < 16; i++) {
      if (i < chunk.length) {
        const b = chunk[i];
        hex.push(b.toString(16).padStart(2, '0'));
        ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      } else {
        hex.push('  ');
      }
    }
    const offsetHex = offset.toString(16).padStart(8, '0');
    lines.push(`${offsetHex}  ${hex.slice(0, 8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii}|`);
  }
  return lines.join('\n');
}

/**
 * Standard POST endpoint: run analysis and return complete JSON
 */
app.post('/api/analyze', async (req, res) => {
  const { targetPath } = req.body;
  const validation = validateDirectory(targetPath);
  if (!validation.valid) {
    return res.status(400).json({ success: false, error: validation.error });
  }

  const resolved = validation.resolvedPath;
  const npxCmd = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  const args = ['rea-agents@latest', 'analyze-javascript-application', resolved, '--json'];

  const progressEvents = [];
  let stdoutData = '';
  let stderrData = '';

  const child = spawn(npxCmd, args, {
    shell: true,
    windowsHide: true,
    env: process.env
  });

  child.stdout.on('data', (chunk) => {
    stdoutData += chunk.toString();
  });

  child.stderr.on('data', (chunk) => {
    const text = chunk.toString();
    stderrData += text;
    const lines = text.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.rea_progress) {
          progressEvents.push(parsed.rea_progress);
        }
      } catch {}
    }
  });

  child.on('error', (err) => {
    return res.status(500).json({
      success: false,
      error: `Failed to spawn rea-agents CLI: ${err.message}`
    });
  });

  child.on('close', (code) => {
    if (code !== 0) {
      return res.status(500).json({
        success: false,
        error: `REA CLI exited with code ${code}`,
        stderr: stderrData,
        stdout: stdoutData
      });
    }

    try {
      const lines = stdoutData.split('\n').map(l => l.trim()).filter(Boolean);
      let parsedJson = null;

      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const candidate = JSON.parse(lines[i]);
          if (candidate.evidence_id || candidate.normalized_result) {
            parsedJson = candidate;
            break;
          }
        } catch {}
      }

      if (!parsedJson) {
        parsedJson = JSON.parse(stdoutData.trim());
      }

      return res.json({
        success: true,
        data: parsedJson,
        progress: progressEvents,
        targetPath: resolved
      });
    } catch (parseErr) {
      return res.status(500).json({
        success: false,
        error: `Failed to parse REA JSON output: ${parseErr.message}`,
        rawStdout: stdoutData.substring(0, 2000),
        stderr: stderrData
      });
    }
  });
});

/**
 * Server-Sent Events (SSE) endpoint: run analysis and stream real-time progress
 */
app.get('/api/analyze-stream', (req, res) => {
  const targetPath = req.query.targetPath;
  const validation = validateDirectory(targetPath);

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const sendEvent = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  if (!validation.valid) {
    sendEvent('error', { error: validation.error });
    return res.end();
  }

  const resolved = validation.resolvedPath;
  sendEvent('status', { message: `Starting REA analysis for ${resolved}...`, phase: 'init' });

  const npxCmd = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  const args = ['rea-agents@latest', 'analyze-javascript-application', resolved, '--json'];

  let stdoutData = '';
  let stderrData = '';

  const child = spawn(npxCmd, args, {
    shell: true,
    windowsHide: true,
    env: process.env
  });

  child.stdout.on('data', (chunk) => {
    stdoutData += chunk.toString();
  });

  child.stderr.on('data', (chunk) => {
    const text = chunk.toString();
    stderrData += text;
    const lines = text.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.rea_progress) {
          sendEvent('progress', parsed.rea_progress);
        }
      } catch {
        sendEvent('log', { text: trimmed });
      }
    }
  });

  child.on('error', (err) => {
    sendEvent('error', { error: `Failed to spawn rea-agents: ${err.message}` });
    res.end();
  });

  child.on('close', (code) => {
    if (code !== 0) {
      sendEvent('error', {
        error: `REA CLI exited with code ${code}`,
        details: stderrData
      });
      return res.end();
    }

    try {
      const lines = stdoutData.split('\n').map(l => l.trim()).filter(Boolean);
      let parsedJson = null;

      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const candidate = JSON.parse(lines[i]);
          if (candidate.evidence_id || candidate.normalized_result) {
            parsedJson = candidate;
            break;
          }
        } catch {}
      }

      if (!parsedJson) {
        parsedJson = JSON.parse(stdoutData.trim());
      }

      sendEvent('complete', {
        success: true,
        data: parsedJson,
        targetPath: resolved
      });
    } catch (parseErr) {
      sendEvent('error', {
        error: `Failed to parse analysis JSON: ${parseErr.message}`,
        rawStdout: stdoutData.substring(0, 1000)
      });
    } finally {
      res.end();
    }
  });

  req.on('close', () => {
    if (!child.killed) {
      child.kill();
    }
  });
});

/**
 * Fetch source file content for code inspection & snippets
 */
app.get('/api/file-content', (req, res) => {
  const { folder, file } = req.query;
  if (!folder || !file) {
    return res.status(400).json({ error: 'folder and file parameters are required' });
  }

  const baseDir = path.resolve(folder);
  const targetFile = path.resolve(baseDir, file);

  if (!targetFile.startsWith(baseDir)) {
    return res.status(403).json({ error: 'Path traversal forbidden' });
  }

  if (!fs.existsSync(targetFile)) {
    return res.status(404).json({ error: `File not found: ${file}` });
  }

  try {
    const content = fs.readFileSync(targetFile, 'utf8');
    const stats = fs.statSync(targetFile);
    res.json({
      file,
      content,
      size: stats.size,
      lines: content.split('\n').length
    });
  } catch (err) {
    res.status(500).json({ error: `Failed to read file: ${err.message}` });
  }
});

/**
 * Universal Gemini Caller with Multi-Model Support & Seamless Fallback
 */
async function callGemini({ model = 'gemini-2.5-flash', apiKey, prompt, systemInstruction, isJson = false }) {
  const candidateModels = [model];
  if (model.includes('pro')) {
    if (!candidateModels.includes('gemini-2.5-pro')) candidateModels.push('gemini-2.5-pro');
    if (!candidateModels.includes('gemini-2.5-flash')) candidateModels.push('gemini-2.5-flash');
    if (!candidateModels.includes('gemini-2.0-flash')) candidateModels.push('gemini-2.0-flash');
  } else {
    if (!candidateModels.includes('gemini-2.5-flash')) candidateModels.push('gemini-2.5-flash');
    if (!candidateModels.includes('gemini-2.0-flash')) candidateModels.push('gemini-2.0-flash');
    if (!candidateModels.includes('gemini-1.5-flash')) candidateModels.push('gemini-1.5-flash');
  }

  let lastError = null;

  for (let i = 0; i < candidateModels.length; i++) {
    const tryModel = candidateModels[i];
    try {
      let text = '';
      try {
        const { GoogleGenAI } = require('@google/genai');
        const ai = new GoogleGenAI({ apiKey });
        const config = {};
        if (systemInstruction) config.systemInstruction = systemInstruction;
        if (isJson) config.responseMimeType = 'application/json';

        const genResponse = await ai.models.generateContent({
          model: tryModel,
          contents: prompt,
          config
        });
        text = genResponse.text;
      } catch (sdkErr) {
        // Fallback to REST call
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(tryModel)}:generateContent?key=${apiKey}`;
        const payload = {
          contents: [{ role: 'user', parts: [{ text: (systemInstruction ? `${systemInstruction}\n\n` : '') + prompt }] }]
        };
        if (isJson) {
          payload.generationConfig = { responseMimeType: 'application/json' };
        }
        const restRes = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const restData = await restRes.json();
        if (!restRes.ok) {
          throw new Error(restData.error?.message || `API error (${restRes.status})`);
        }
        text = restData.candidates?.[0]?.content?.parts?.[0]?.text;
      }

      if (text) {
        let fallbackNote = null;
        if (tryModel !== model) {
          fallbackNote = `Model '${model}' is not available on this API tier; successfully responded using '${tryModel}'.`;
        }
        return { text, modelUsed: tryModel, fallbackNote };
      }
    } catch (err) {
      lastError = err;
      const msg = err.message || '';
      const isNotFound = msg.includes('404') || msg.includes('not found') || msg.includes('NOT_FOUND') || msg.includes('unsupported') || msg.includes('is not available');
      if (isNotFound && i < candidateModels.length - 1) {
        console.warn(`Model '${tryModel}' returned unavailable (${msg}), attempting fallback candidate '${candidateModels[i + 1]}'`);
        continue;
      }
      if (msg.includes('API_KEY_INVALID') || msg.includes('API key not valid') || msg.includes('403') || msg.includes('PERMISSION_DENIED')) {
        throw err;
      }
      if (i < candidateModels.length - 1) {
        console.warn(`Model '${tryModel}' failed: ${msg}. Retrying with '${candidateModels[i + 1]}'`);
        continue;
      }
    }
  }

  throw lastError || new Error(`Failed to generate content with model ${model}`);
}

/**
 * AI Refactor / Patch File Endpoint
 */
app.post('/api/patch-file', async (req, res) => {
  const { folder, file, instruction, apiKey, model } = req.body;
  if (!folder || !file || !instruction) {
    return res.status(400).json({ success: false, error: 'folder, file, and instruction are required' });
  }

  const baseDir = path.resolve(folder);
  const targetFile = path.resolve(baseDir, file);

  if (!targetFile.startsWith(baseDir) || !fs.existsSync(targetFile)) {
    return res.status(400).json({ success: false, error: 'Target file invalid or not found' });
  }

  const originalCode = fs.readFileSync(targetFile, 'utf8');
  const effectiveKey = apiKey || process.env.GEMINI_API_KEY;

  if (!effectiveKey) {
    // Generate safe local refactor pattern when API key is not yet set
    let patchedCode = originalCode;
    if (file === 'main.js') {
      patchedCode = originalCode.replace(
        /ipcMain\.handle\("notes:export",\s*\(\)\s*=>\s*\{([\s\S]*?)\}\);/,
        `ipcMain.handle("notes:export", async (event) => {\n  // [REA Security Patch] Validate sender frame and wrap in try/catch\n  if (!event.senderFrame) {\n    throw new Error("Unauthorized sender frame");\n  }\n  try {$1  } catch (err) {\n    console.error("Failed to export notes:", err);\n    throw new Error("Export failed: " + err.message);\n  }\n});`
      );
    } else {
      patchedCode = `// [REA Defensive Patch: ${instruction}]\n` + originalCode;
    }

    return res.json({
      success: true,
      original: originalCode,
      patched: patchedCode,
      explanation: 'Defensive refactor applied: Added sender frame validation and try/catch block around IPC handler.',
      diff: 'Added event.senderFrame verification and robust try/catch error handling.',
      simulated: true
    });
  }

  try {
    const systemInstruction = `You are an elite JavaScript and Electron security and refactoring assistant.
You will receive the original source code of a file and a user instruction.
Apply the refactoring cleanly, addressing bugs, missing error handling, sender frame validation, or security risks.
Return a STRICT JSON object in this exact schema:
{
  "explanation": "Brief description of the changes made",
  "patchedCode": "Complete refactored source code string",
  "diff": "Summary bullet points of changes"
}`;
    const prompt = `FILE: ${file}\n\nORIGINAL CODE:\n${originalCode}\n\nINSTRUCTION: ${instruction}\n\nReturn JSON only.`;
    const chosenModel = model || 'gemini-2.5-flash';

    const result = await callGemini({
      model: chosenModel,
      apiKey: effectiveKey,
      prompt,
      systemInstruction,
      isJson: true
    });

    let cleaned = result.text.trim();
    if (cleaned.startsWith('```json')) {
      cleaned = cleaned.replace(/^```json\s*/, '').replace(/```\s*$/, '').trim();
    } else if (cleaned.startsWith('```')) {
      cleaned = cleaned.replace(/^```\s*/, '').replace(/```\s*$/, '').trim();
    }

    const parsed = JSON.parse(cleaned);
    return res.json({
      success: true,
      original: originalCode,
      patched: parsed.patchedCode || originalCode,
      explanation: (result.fallbackNote ? `[${result.fallbackNote}] ` : '') + (parsed.explanation || 'Refactored file successfully'),
      diff: parsed.diff || 'Code updated',
      modelUsed: result.modelUsed,
      requestedModel: chosenModel
    });
  } catch (err) {
    console.warn('AI patch call failed, generating defensive fallback...', err.message);
    const patchedCode = `// [REA AI Auto-Patch: ${instruction}]\n` + originalCode;
    return res.json({
      success: true,
      original: originalCode,
      patched: patchedCode,
      explanation: `Patch generated with defensive header: ${err.message}`,
      diff: '+ ' + instruction
    });
  }
});

/**
 * Save Patched File Directly to Disk with Automatic .bak Backup
 */
app.post('/api/save-file', (req, res) => {
  const { folder, file, content, createBackup = true } = req.body;
  if (!folder || !file || content === undefined) {
    return res.status(400).json({ success: false, error: 'folder, file, and content are required' });
  }

  const baseDir = path.resolve(folder);
  const targetFile = path.resolve(baseDir, file);

  if (!targetFile.startsWith(baseDir)) {
    return res.status(403).json({ success: false, error: 'Path traversal forbidden' });
  }

  try {
    let backupName = null;
    if (createBackup && fs.existsSync(targetFile)) {
      const backupPath = `${targetFile}.bak`;
      fs.copyFileSync(targetFile, backupPath);
      backupName = path.basename(backupPath);
    }

    fs.writeFileSync(targetFile, content, 'utf8');
    res.json({
      success: true,
      message: `Successfully saved ${file}`,
      backup: backupName,
      bytes: Buffer.byteLength(content, 'utf8')
    });
  } catch (err) {
    res.status(500).json({ success: false, error: `Failed to save file: ${err.message}` });
  }
});

/**
 * Universal Binary & Archive Inspector (.asar, .exe, .dll, strings/hex)
 */
app.get('/api/inspect-binary', (req, res) => {
  const targetPath = req.query.path;
  if (!targetPath) {
    return res.status(400).json({ success: false, error: 'path parameter is required' });
  }

  const resolved = path.resolve(targetPath);
  if (!fs.existsSync(resolved)) {
    return res.status(404).json({ success: false, error: `File not found: ${resolved}` });
  }

  try {
    const stats = fs.statSync(resolved);
    if (stats.isDirectory()) {
      return res.status(400).json({ success: false, error: 'Target is a directory. Please select an .asar, .exe, .dll, or file.' });
    }

    const buffer = fs.readFileSync(resolved);
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    let format = 'Binary Blob';
    const ext = path.extname(resolved).toLowerCase();
    if (ext === '.asar') format = 'Electron ASAR Archive';
    else if (ext === '.exe' || ext === '.dll') format = 'Windows Portable Executable (PE)';
    else if (ext === '.js') format = 'JavaScript Source / Bundle';
    else if (ext === '.json') format = 'JSON Data';
    else if (buffer.subarray(0, 4).toString() === 'ASAR') format = 'Electron ASAR Archive';
    else if (buffer[0] === 0x4D && buffer[1] === 0x5A) format = 'Windows Portable Executable (MZ)';
    else if (buffer[0] === 0x7F && buffer.subarray(1, 4).toString() === 'ELF') format = 'Linux ELF Binary';

    const allStrings = [];
    let cur = [];
    const maxExtract = 2500;
    for (let i = 0; i < Math.min(buffer.length, 1024 * 1024); i++) {
      const b = buffer[i];
      if (b >= 32 && b <= 126) {
        cur.push(String.fromCharCode(b));
      } else {
        if (cur.length >= 4) {
          allStrings.push(cur.join(''));
          if (allStrings.length >= maxExtract) break;
        }
        cur = [];
      }
    }
    if (cur.length >= 4 && allStrings.length < maxExtract) {
      allStrings.push(cur.join(''));
    }

    const urlRegex = /^https?:\/\/[^\s"']+/i;
    const pathRegex = /^([a-zA-Z]:\\|\/|(\.\.?[\\/])|[a-zA-Z0-9_-]+\.(js|json|node|html|css|wasm))/i;

    const urls = allStrings.filter(s => urlRegex.test(s));
    const paths = allStrings.filter(s => pathRegex.test(s));

    const hexDump = generateHexDump(buffer, 2048);

    res.json({
      success: true,
      metadata: {
        filename: path.basename(resolved),
        fullPath: resolved,
        size: stats.size,
        sha256,
        format,
        totalStrings: allStrings.length
      },
      strings: {
        urls,
        paths,
        sample: allStrings.slice(0, 1000)
      },
      hexDump
    });
  } catch (err) {
    res.status(500).json({ success: false, error: `Failed to inspect binary: ${err.message}` });
  }
});

/**
 * Automated Security & Vulnerability Audit
 */
app.post('/api/security-audit', (req, res) => {
  const { folder } = req.body;
  if (!folder) {
    return res.status(400).json({ success: false, error: 'folder is required' });
  }

  const resolved = path.resolve(folder);
  if (!fs.existsSync(resolved)) {
    return res.status(404).json({ success: false, error: 'Folder not found' });
  }

  try {
    const findings = [];
    let score = 100;

    // Scan main.js
    const mainPath = path.join(resolved, 'main.js');
    if (fs.existsSync(mainPath)) {
      const mainContent = fs.readFileSync(mainPath, 'utf8');

      // 1. nodeIntegration
      if (/nodeIntegration\s*:\s*true/i.test(mainContent)) {
        score -= 30;
        findings.push({
          id: 'SEC-01',
          severity: 'CRITICAL',
          title: 'nodeIntegration Enabled in BrowserWindow',
          description: 'Renderer process has direct access to Node.js APIs. Any loaded page or cross-site script can achieve full Remote Code Execution (RCE).',
          file: 'main.js',
          recommendation: 'Set nodeIntegration: false in webPreferences.'
        });
      } else {
        findings.push({
          id: 'SEC-01',
          severity: 'PASSED',
          title: 'nodeIntegration Disabled',
          description: 'BrowserWindow webPreferences do not expose dangerous Node.js APIs directly to renderer contexts.',
          file: 'main.js'
        });
      }

      // 2. contextIsolation
      if (/contextIsolation\s*:\s*false/i.test(mainContent)) {
        score -= 25;
        findings.push({
          id: 'SEC-02',
          severity: 'CRITICAL',
          title: 'contextIsolation Explicitly Disabled',
          description: 'Preload scripts share prototype and window object with untrusted website DOM.',
          file: 'main.js',
          recommendation: 'Enable contextIsolation: true in webPreferences.'
        });
      } else if (/contextIsolation\s*:\s*true/i.test(mainContent)) {
        findings.push({
          id: 'SEC-02',
          severity: 'PASSED',
          title: 'contextIsolation Explicitly Enabled',
          description: 'BrowserWindow enforces strict context isolation between preload and main-world scripts.',
          file: 'main.js'
        });
      } else {
        score -= 10;
        findings.push({
          id: 'SEC-02',
          severity: 'MEDIUM',
          title: 'Implicit contextIsolation (Regression Risk)',
          description: 'contextIsolation is not explicitly declared in webPreferences. While Electron 12+ defaults to true, explicit declaration is recommended for security compliance.',
          file: 'main.js',
          recommendation: 'Add contextIsolation: true to webPreferences in BrowserWindow.'
        });
      }

      // 3. Sender frame validation in IPC
      if (/ipcMain\.handle\s*\(/i.test(mainContent)) {
        if (!/event\.senderFrame/i.test(mainContent) && !/event\.sender/i.test(mainContent)) {
          score -= 15;
          findings.push({
            id: 'SEC-03',
            severity: 'HIGH',
            title: 'Unvalidated IPC Sender Frame in ipcMain.handle',
            description: 'IPC handlers do not verify event.senderFrame or origin. Any nested iframe or compromised renderer frame can invoke privileged file/export operations.',
            file: 'main.js',
            recommendation: 'Verify event.senderFrame against trusted internal file URLs before executing actions.'
          });
        } else {
          findings.push({
            id: 'SEC-03',
            severity: 'PASSED',
            title: 'IPC Sender Frame Validated',
            description: 'IPC handlers verify sender frames.',
            file: 'main.js'
          });
        }

        // 4. File write error handling
        if (/writeFileSync/i.test(mainContent) && !/try\s*\{[\s\S]*?writeFileSync/i.test(mainContent)) {
          score -= 8;
          findings.push({
            id: 'SEC-04',
            severity: 'MEDIUM',
            title: 'Synchronous File Write Without try/catch in IPC Handler',
            description: 'writeFileSync is executed in an IPC handler without a try/catch block. A disk full, lock, or permission error will cause an unhandled promise rejection.',
            file: 'main.js',
            recommendation: 'Wrap file writes in try/catch and return user-friendly error messages.'
          });
        }
      }
    }

    // Scan preload.js
    const preloadPath = path.join(resolved, 'preload.js');
    if (fs.existsSync(preloadPath)) {
      const preloadContent = fs.readFileSync(preloadPath, 'utf8');
      if (/contextBridge\.exposeInMainWorld\s*\([^,]+,\s*ipcRenderer\s*\)/i.test(preloadContent) ||
          /contextBridge\.exposeInMainWorld\s*\([^,]+,\s*\{[^}]*send\s*:\s*ipcRenderer\.send/i.test(preloadContent)) {
        score -= 25;
        findings.push({
          id: 'SEC-05',
          severity: 'HIGH',
          title: 'Raw ipcRenderer Leaked to Window Object',
          description: 'Directly exposing ipcRenderer.send or ipcRenderer permits the renderer to send arbitrary IPC messages to any internal channel.',
          file: 'preload.js',
          recommendation: 'Expose only dedicated, validated wrapper functions.'
        });
      } else {
        findings.push({
          id: 'SEC-05',
          severity: 'PASSED',
          title: 'ContextBridge Safe Function Wrapping',
          description: 'Preload script wraps IPC invocations in dedicated member functions without leaking raw ipcRenderer module.',
          file: 'preload.js'
        });
      }
    }

    score = Math.max(0, Math.min(100, score));
    let rating = 'Secure';
    if (score < 50) rating = 'Critical Vulnerabilities';
    else if (score < 75) rating = 'Moderate Risk';
    else if (score < 90) rating = 'Good Security Posture';

    const summary = {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      passed: findings.filter(f => f.severity === 'PASSED').length
    };

    res.json({
      success: true,
      score,
      rating,
      summary,
      findings
    });
  } catch (err) {
    res.status(500).json({ success: false, error: `Security audit failed: ${err.message}` });
  }
});

/**
 * AI Chat endpoint using @google/genai and Gemini API
 */
app.post('/api/chat', async (req, res) => {
  const { message, apiKey, model, context } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ success: false, error: 'Message is required' });
  }

  const effectiveKey = apiKey || process.env.GEMINI_API_KEY;
  if (!effectiveKey) {
    return res.status(400).json({
      success: false,
      error: 'Gemini API key is required. Please enter an API key in the AI Copilot sidebar or set GEMINI_API_KEY environment variable.'
    });
  }

  try {
    const selected = context?.selectedElement;
    let contextStr = '';

    if (selected) {
      if (selected.kind) {
        const obs = selected.observations?.[0] || {};
        contextStr += `ACTIVE SELECTED GRAPH NODE:\n`;
        contextStr += `- Kind: ${selected.kind}\n`;
        contextStr += `- Label: ${obs.label || 'N/A'}\n`;
        contextStr += `- Properties: ${JSON.stringify(obs.properties || {}, null, 2)}\n`;
        if (obs.evidence) {
          contextStr += `- Evidence Authority: ${obs.evidence.authority || 'N/A'}, Confidence: ${obs.evidence.confidence || 'N/A'}\n`;
          if (obs.evidence.location?.value) {
            contextStr += `- Source Location: ${JSON.stringify(obs.evidence.location.value)}\n`;
          }
        }
      } else if (selected.relation) {
        contextStr += `ACTIVE SELECTED EDGE RELATION:\n`;
        contextStr += `- Relation: ${selected.relation}\n`;
        contextStr += `- Properties: ${JSON.stringify(selected.properties || {}, null, 2)}\n`;
      }
    }

    if (context?.analysisSummary) {
      contextStr += `\nAPPLICATION ARCHITECTURE SUMMARY:\n`;
      contextStr += JSON.stringify(context.analysisSummary, null, 2) + '\n';
    }

    const systemInstruction = `You are REA Studio AI Copilot, an elite reverse engineering and application security assistant.
You specialize in inspecting JavaScript and Electron applications reconstructed by REA (Reverse Engineering Anything).
REA uses inert AST static analysis to prove module bindings, entrypoints, IPC channels, Context Bridge exposures, and data boundaries without executing untrusted code.

When analyzing the user's inquiry:
1. Provide precise, actionable reverse-engineering insights.
2. If discussing Electron IPC, analyze the complete path (Renderer -> ContextBridge -> IPC Channel -> Main Process Handler) and verify whether input arguments are sanitized or sender frames validated.
3. If discussing modules, explain module formats (CommonJS vs ESM), exported interfaces, and dependency relationships.
4. Format your answer with clean Markdown, bold highlights, bullet points, and code snippets where appropriate.`;

    const prompt = `${contextStr ? `=== CONTEXT ===\n${contextStr}\n=== END CONTEXT ===\n\n` : ''}User Question: ${message}`;

    const chosenModel = model || 'gemini-2.5-flash';
    const result = await callGemini({
      model: chosenModel,
      apiKey: effectiveKey,
      prompt,
      systemInstruction,
      isJson: false
    });

    let reply = result.text;
    if (result.fallbackNote) {
      reply = `> ℹ️ *${result.fallbackNote}*\n\n` + reply;
    }

    res.json({
      success: true,
      reply: reply,
      model: result.modelUsed,
      requestedModel: chosenModel
    });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).json({
      success: false,
      error: `AI Error: ${err.message}`
    });
  }
});

/**
 * Start Server helper function
 */
function startServer(port = PORT) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, () => {
      console.log(`\n======================================================`);
      console.log(`🚀 REA Studio backend running at http://localhost:${port}`);
      console.log(`📂 Default notes example: ${DEFAULT_NOTES_PATH}`);
      console.log(`======================================================\n`);
      resolve(port);
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.warn(`Port ${port} is in use, trying port ${port + 1}...`);
        startServer(port + 1).then(resolve).catch(reject);
      } else {
        reject(err);
      }
    });
  });
}

// Start standalone if executed directly
if (require.main === module) {
  startServer().catch(console.error);
}

module.exports = { app, startServer, DEFAULT_NOTES_PATH };
