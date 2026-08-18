// preload — 렌더러(웹 UI)에 최소 API만 노출. 웹 UI는 순수 HTTP로 백엔드와 통신하므로
// 현재 별도 브리지가 필요 없지만, 향후 네이티브 기능(파일 저장 등) 확장 지점으로 둔다.
"use strict";
const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("inspectK8s", {
  desktop: true,
  version: "0.1.0",
});
