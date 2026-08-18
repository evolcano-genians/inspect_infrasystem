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

  // 로컬 커밋되지 않은 *소스* 변경이 있으면 자동 업데이트를 건너뛴다(사용자 작업 보호).
  // 단, wiki/·logs/ 등 런타임 산출물은 에이전트가 조사할 때마다 바뀌므로 제외한다 —
  // 이걸 포함하면 조사 직후 항상 dirty가 되어 자동 업데이트가 영구히 스킵된다.
  const RUNTIME_PATHS = [":(exclude)wiki", ":(exclude)logs", ":(exclude).local", ":(exclude).checkpoints"];
  const status = await git(["status", "--porcelain", "--", ".", ...RUNTIME_PATHS]);
  if (status.ok && status.out.trim()) {
    const files = status.out.trim().split("\n").slice(0, 3).map(s => s.slice(3)).join(", ");
    return { updated: false, reason: `로컬 소스 변경 있음 — 자동 업데이트 건너뜀 (${files})` };
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

  // 위키(장기 기억)가 조사로 바뀐 상태면 잠시 stash 해 두고 ff 한 뒤 되돌린다.
  // (커밋하면 로컬이 앞서 diverge → ff 자체가 불가해지므로 stash 를 쓴다. pop 실패 시에도
  //  stash 에 그대로 남아 기억을 잃지 않는다.)
  const wikiDirty = await git(["status", "--porcelain", "--", "wiki"]);
  const stashed = wikiDirty.ok && wikiDirty.out.trim().length > 0;
  if (stashed) {
    const st = await git(["stash", "push", "-u", "-m", "inspect-k8s-auto-update", "--", "wiki"], 30000);
    if (!st.ok) return { updated: false, reason: "위키 임시 보관 실패 — 업데이트 건너뜀" };
  }

  // fast-forward only (히스토리 재작성 없이 안전하게)
  const ff = await git(["merge", "--ff-only", `${remote}/main`], 30000);
  if (stashed) {
    const pop = await git(["stash", "pop"], 30000);
    if (!pop.ok) {
      return { updated: ff.ok, reason: "위키 복원 충돌 — 'git stash list'에 보관됨(수동 병합 필요)" };
    }
  }
  if (!ff.ok) return { updated: false, reason: "fast-forward 불가 (분기됨)" };

  const after = await currentRev();
  return { updated: before !== after, from: before.slice(0, 8), to: after.slice(0, 8), remote };
}

module.exports = { checkAndPull, currentRev };
