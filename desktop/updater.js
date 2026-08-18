// updater.js — git pull 기반 자동 업데이트.
//
// 이 앱은 백엔드(src.web)와 UI를 프로젝트 소스에서 직접 로드하므로, 기능 업데이트는
// 대부분 파이썬/HTML 변경이다. 따라서 저장소를 최신으로 당기면(git pull) 백엔드 재시작만으로
// 새 기능이 반영된다. 회사 보안 정책상 GitHub 자격증명은 원격 서버에만 있으므로,
// 릴레이 원격('relay')에서 fetch 하고, 없으면 origin을 시도한다.
"use strict";
const { execFile } = require("child_process");
const path = require("path");
const fs = require("fs");

// main.js와 동일 규칙으로 프로젝트 루트 해석 (패키징 시 번들 밖 저장소를 가리켜야 함).
function resolveProjectRoot() {
  if (process.env.INSPECT_K8S_PROJECT) return process.env.INSPECT_K8S_PROJECT;
  const devRoot = path.resolve(__dirname, "..");
  if (fs.existsSync(path.join(devRoot, "src", "web.py"))) return devRoot;
  return "/Users/shinhheejoon/PycharmProjects/inspect-k8s";
}
const PROJECT_ROOT = resolveProjectRoot();

function git(args, timeout = 30000) {
  return new Promise((resolve) => {
    execFile("git", args, { cwd: PROJECT_ROOT, timeout }, (err, stdout, stderr) => {
      resolve({ ok: !err, out: (stdout || "") + (stderr || ""), code: err ? err.code : 0 });
    });
  });
}

async function currentRev() {
  const r = await git(["rev-parse", "HEAD"]);
  return r.ok ? r.out.trim() : "";
}

// 원격에서 최신 main을 가져와 fast-forward 한다. 로컬 변경이 있으면 건드리지 않는다.
// 반환: { updated: bool, from, to, reason }
async function checkAndPull() {
  const before = await currentRev();

  // 로컬 커밋되지 않은 변경이 있으면 자동 업데이트를 건너뛴다(사용자 작업 보호).
  const status = await git(["status", "--porcelain"]);
  if (status.ok && status.out.trim()) {
    return { updated: false, reason: "로컬 변경 있음 — 자동 업데이트 건너뜀" };
  }

  // 릴레이 → origin 순으로 fetch 시도
  let remote = null;
  const remotes = await git(["remote"]);
  const list = remotes.ok ? remotes.out.split(/\s+/).filter(Boolean) : [];
  for (const cand of ["relay", "origin"]) {
    if (list.includes(cand)) {
      const f = await git(["fetch", cand, "main"], 60000);
      if (f.ok) { remote = cand; break; }
    }
  }
  if (!remote) return { updated: false, reason: "원격 fetch 실패" };

  // fast-forward only (히스토리 재작성 없이 안전하게)
  const ff = await git(["merge", "--ff-only", `${remote}/main`], 30000);
  if (!ff.ok) return { updated: false, reason: "fast-forward 불가 (분기됨)" };

  const after = await currentRev();
  return { updated: before !== after, from: before.slice(0, 8), to: after.slice(0, 8), remote };
}

module.exports = { checkAndPull, currentRev };
