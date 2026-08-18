// inspect-k8s 데스크톱 앱 — 기존 웹 하네스(FastAPI+SSE)를 감싸는 Electron 셸.
//
// 동작: 앱 시작 시 프로젝트의 파이썬 웹 서버(src.web)를 자식 프로세스로 띄우고,
// 준비되면 그 로컬 URL(127.0.0.1)을 BrowserWindow에 로드한다. 종료 시 서버도 정리한다.
//
// 설정은 사용자 환경변수(AGENT_ALLOW_REAL_CLUSTER, KUBE_CONTEXT, SOURCE_SSH_HOST 등)를
// 그대로 상속한다 — 앱은 자격증명을 저장하지 않는다.

"use strict";
const { app, BrowserWindow, shell, Menu, dialog } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const path = require("path");
const fs = require("fs");
const { checkAndPull } = require("./updater");

const UPDATE_INTERVAL_MS = 30 * 60 * 1000; // 30분마다 자동 확인
let updateTimer = null;

// 프로젝트 소스 위치. 패키징된 .app은 번들 밖의 실제 저장소를 가리켜야 하므로,
// 환경변수 > 저장된 설정 > 개발 기본값(../) 순으로 해석한다.
function resolveProjectRoot() {
  if (process.env.INSPECT_K8S_PROJECT) return process.env.INSPECT_K8S_PROJECT;
  const cfgPath = path.join(app.getPath("userData"), "project-root");
  try {
    const saved = fs.readFileSync(cfgPath, "utf-8").trim();
    if (saved && fs.existsSync(path.join(saved, "src", "web.py"))) return saved;
  } catch (_) {}
  // 개발 실행(npm start)에서는 desktop/의 상위가 저장소다.
  const devRoot = path.resolve(__dirname, "..");
  if (fs.existsSync(path.join(devRoot, "src", "web.py"))) return devRoot;
  // 패키징된 기본값 (설치 환경) — 실제 저장소 경로로 고정.
  return "/Users/shinhheejoon/PycharmProjects/inspect-k8s";
}

const PROJECT_ROOT = resolveProjectRoot();
const HOST = "127.0.0.1";
const PORT = Number(process.env.INSPECT_K8S_PORT || 8799);
const BASE_URL = `http://${HOST}:${PORT}`;

let serverProc = null;
let mainWindow = null;
let serverStderr = []; // 최근 stderr 버퍼 (에러 진단용)
let serverReady = false;

function resolvePython() {
  // 프로젝트 .venv 우선, 없으면 시스템 python3
  const venvPy = path.join(PROJECT_ROOT, ".venv", "bin", "python");
  return fs.existsSync(venvPy) ? venvPy : "python3";
}

// GUI로 실행하면 터미널 환경변수를 상속받지 못한다. 프로젝트 .env를 읽고,
// 실 클러스터 read-only 조사를 위한 합리적 기본값을 채운다.
function parseEnvFile(file) {
  const out = {};
  try {
    for (const raw of fs.readFileSync(file, "utf-8").split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#") || !line.includes("=")) continue;
      const idx = line.indexOf("=");
      out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
  } catch (_) {}
  return out;
}

function buildBackendEnv() {
  const home = app.getPath("home");
  const fromFile = parseEnvFile(path.join(PROJECT_ROOT, ".env"));
  const env = { ...process.env, ...fromFile }; // .env가 GUI 환경보다 우선
  // 기본값: GUI 실행에서도 실 클러스터 read-only 조사가 바로 되게 한다.
  const defaults = {
    AGENT_ALLOW_REAL_CLUSTER: "1",
    KUBECONFIG: path.join(home, ".kube", "config"),
    KUBE_CONTEXT: "aws-seoul-clouddev",
    MODEL_PROVIDER: "codex-oauth",
    SOURCE_SSH_HOST: "heejoon@172.29.70.161",
  };
  for (const [k, v] of Object.entries(defaults)) {
    if (!env[k]) env[k] = v;
  }
  // ~ 확장
  if (env.KUBECONFIG && env.KUBECONFIG.startsWith("~")) {
    env.KUBECONFIG = env.KUBECONFIG.replace(/^~/, home);
  }
  // GUI 앱은 PATH가 최소라 homebrew/docker/strix 등을 못 찾는다 — 보강한다.
  const extraPaths = [
    "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
    path.join(home, ".strix", "bin"), path.join(home, ".local", "bin"),
    "/Applications/Docker.app/Contents/Resources/bin",
  ];
  env.PATH = [...extraPaths, ...(env.PATH || "").split(":")].filter(Boolean).join(":");
  env.WEB_HOST = HOST;
  env.WEB_PORT = String(PORT);
  env.PYTHONUNBUFFERED = "1";
  return env;
}

function startServer() {
  const py = resolvePython();
  const env = buildBackendEnv();
  serverProc = spawn(py, ["-m", "src.web"], { cwd: PROJECT_ROOT, env });
  serverProc.stdout.on("data", (d) => process.stdout.write(`[server] ${d}`));
  serverProc.stderr.on("data", (d) => {
    const s = d.toString();
    process.stderr.write(`[server] ${s}`);
    serverStderr.push(s);
    if (serverStderr.length > 40) serverStderr.shift();
  });
  serverProc.on("exit", (code) => {
    serverProc = null;
    if (code && code !== 0 && !serverReady) {
      // 서버가 준비 전에 죽었으면 실제 원인(stderr 마지막 줄)을 보여준다.
      const tail = serverStderr.join("").trim().split("\n").slice(-6).join("\n");
      dialog.showErrorBox(
        "백엔드 시작 실패",
        `inspect-k8s 서버가 코드 ${code}로 종료되었습니다.\n\n원인:\n${tail || "(로그 없음)"}\n\n` +
          `환경변수(KUBECONFIG, AGENT_ALLOW_REAL_CLUSTER, KUBE_CONTEXT 등)를 확인하세요.`
      );
    }
  });
}

function waitForServer(timeoutMs = 30000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      const req = http.get(`${BASE_URL}/api/health`, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retry();
      });
      req.on("error", retry);
      req.setTimeout(2000, () => req.destroy());
    };
    const retry = () => {
      if (Date.now() - started > timeoutMs) return reject(new Error("서버 시작 시간 초과"));
      setTimeout(tick, 500);
    };
    tick();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 900,
    minWidth: 960,
    minHeight: 600,
    title: "inspect-k8s",
    backgroundColor: "#10161d",
    titleBarStyle: "hiddenInset", // Claude Code 유사 — 상단바 최소화
    trafficLightPosition: { x: 16, y: 18 },
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // 외부 링크는 기본 브라우저로
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (!url.startsWith(BASE_URL)) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  mainWindow.loadFile(path.join(__dirname, "splash.html"));

  waitForServer()
    .then(() => {
      serverReady = true;
      if (mainWindow) mainWindow.loadURL(BASE_URL);
    })
    .catch((err) => {
      const tail = serverStderr.join("").trim().split("\n").slice(-6).join("\n");
      dialog.showErrorBox(
        "시작 실패",
        `백엔드 서버를 시작하지 못했습니다.\n${err.message}\n\n` +
          (tail ? `서버 로그:\n${tail}\n\n` : "") +
          `터미널에서 다음을 확인하세요:\n  cd ${PROJECT_ROOT}\n  .venv/bin/python -m src.web`
      );
    });

  mainWindow.on("closed", () => (mainWindow = null));
}

function restartBackend() {
  if (serverProc) {
    try { serverProc.kill("SIGTERM"); } catch (_) {}
    serverProc = null;
  }
  serverReady = false;
  serverStderr = [];
  startServer();
  if (mainWindow) {
    mainWindow.loadFile(path.join(__dirname, "splash.html"));
    waitForServer().then(() => { serverReady = true; mainWindow.loadURL(BASE_URL); }).catch(() => {});
  }
}

// 주기적 자동 업데이트: 최신을 당겨 변경이 있으면 백엔드 재시작으로 반영.
async function runAutoUpdate(interactive) {
  try {
    const r = await checkAndPull();
    if (r.updated) {
      restartBackend();
      if (mainWindow) {
        const n = new (require("electron").Notification)({
          title: "inspect-k8s 업데이트 적용됨",
          body: `${r.from} → ${r.to} (${r.remote}). 새 기능이 반영되었습니다.`,
        });
        n.show();
      }
    } else if (interactive && mainWindow) {
      dialog.showMessageBox(mainWindow, {
        type: "info", message: "업데이트 확인 완료",
        detail: r.reason || "이미 최신 버전입니다.",
      });
    }
  } catch (_) { /* 업데이트 실패는 조용히 무시 (오프라인 등) */ }
}

function buildMenu() {
  const template = [
    ...(process.platform === "darwin" ? [{ role: "appMenu" }] : []),
    {
      label: "보기",
      submenu: [
        { label: "새로고침", accelerator: "CmdOrCtrl+R", click: () => mainWindow && mainWindow.reload() },
        { label: "업데이트 확인", click: () => runAutoUpdate(true) },
        { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" },
        { type: "separator" }, { role: "togglefullscreen" },
      ],
    },
    { role: "editMenu" },
    { role: "windowMenu" },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(async () => {
  // 시작 시 자동 업데이트: 백엔드 기동 전에 최신 소스를 먼저 당긴다(로컬 변경 없을 때만).
  await runAutoUpdate(false).catch(() => {});
  startServer();
  buildMenu();
  createWindow();
  updateTimer = setInterval(() => runAutoUpdate(false), UPDATE_INTERVAL_MS);
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

function shutdown() {
  if (updateTimer) { clearInterval(updateTimer); updateTimer = null; }
  if (serverProc) {
    try { serverProc.kill("SIGTERM"); } catch (_) {}
    serverProc = null;
  }
}

app.on("window-all-closed", () => {
  shutdown();
  if (process.platform !== "darwin") app.quit();
});
app.on("before-quit", shutdown);
process.on("exit", shutdown);
