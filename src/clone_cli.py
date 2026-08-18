"""dev 클러스터 → kind 복제 CLI (2계층: 실 클러스터 read-only, 샌드박스 write).

    # 정제 계획만 (실 클러스터 read만, 쓰기 없음)
    KUBE_CONTEXT=aws-seoul-clouddev .venv/bin/python -m src.clone_cli \
        --release adminer-shj-test --namespace nexus-shell --plan

    # kind 샌드박스에 실제 복제
    KUBE_CONTEXT=aws-seoul-clouddev .venv/bin/python -m src.clone_cli \
        --release adminer-shj-test --namespace nexus-shell \
        --target-namespace clone-adminer --load-images

실 클러스터에는 helm 읽기 부속명령만 나가고, 쓰기는 루프백(kind) 샌드박스로만 발생한다.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .tools.sandbox_ops import CloneService, SandboxCluster


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="dev 클러스터를 kind로 read-only 복제")
    parser.add_argument("--release", required=True, help="helm 릴리스 이름")
    parser.add_argument("--namespace", required=True, help="원본 네임스페이스")
    parser.add_argument("--target-namespace", default=None, help="샌드박스 대상 네임스페이스 (기본: 원본과 동일)")
    parser.add_argument("--context", default=None, help="실 클러스터 컨텍스트 (기본: $KUBE_CONTEXT)")
    parser.add_argument(
        "--sandbox-kubeconfig",
        default=os.environ.get("CLONE_SANDBOX_KUBECONFIG", ".local/kind-kubeconfig.yaml"),
        help="kind 샌드박스 kubeconfig (루프백 강제)",
    )
    parser.add_argument("--real-kubeconfig", default=os.path.expanduser("~/.kube/config"))
    parser.add_argument("--plan", action="store_true", help="적용 없이 정제 계획만 출력")
    parser.add_argument("--load-images", action="store_true", help="docker pull + kind load 로 이미지 사전 적재")
    parser.add_argument("--no-scale-to-one", action="store_true", help="replicas 를 1로 낮추지 않음")
    args = parser.parse_args(argv)

    context = args.context or os.environ.get("KUBE_CONTEXT")
    if not context:
        raise SystemExit("오류: 실 클러스터 컨텍스트를 --context 또는 KUBE_CONTEXT 로 지정하세요")

    sandbox = SandboxCluster(args.sandbox_kubeconfig)  # 루프백 아니면 여기서 즉시 실패
    svc = CloneService(args.real_kubeconfig, context, sandbox)
    scale = not args.no_scale_to_one

    if args.plan:
        sanitized, report = svc.plan_release(args.release, args.namespace, scale_to_one=scale)
        print(f"[정제 계획] {args.namespace}/{args.release}")
        print(f"  유지 {len(report.kept)}: {report.kept}")
        print(f"  제외 {len(report.dropped)}: {report.dropped}")
        print(f"  변경 {len(report.changes)}: {report.changes}")
        print(f"  이미지: {report.images}")
        print(f"  Secret 스텁: {json.dumps(report.secret_stubs, ensure_ascii=False)}")
        if report.warnings:
            print(f"  ⚠️  {report.warnings}")
        out = Path(args.sandbox_kubeconfig).parent / f"clone-{args.release}.yaml"
        out.write_text(sanitized, encoding="utf-8")
        print(f"  정제된 매니페스트 저장: {out}")
        return

    report = svc.clone_release(
        args.release, args.namespace,
        target_namespace=args.target_namespace, load_images=args.load_images, scale_to_one=scale,
    )
    print(report.summary())
    if report.warnings:
        print("경고:", report.warnings)
    if report.images_failed:
        print("이미지 적재 실패(파드가 직접 pull 시도):", report.images_failed)
    print("파드:", json.dumps(report.pods, ensure_ascii=False))


if __name__ == "__main__":
    main()
