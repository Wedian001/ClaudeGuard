#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
PROJECT_DIR="${SCRIPT_DIR:h}"
DIST_DIR="${PROJECT_DIR}/dist"
APP_SOURCE="${DIST_DIR}/ClaudeGuard.app"
HELPER_SCRIPT="${SCRIPT_DIR}/一键解除macOS警告.command"

VOLUME_NAME="Claude Guard"

if [[ ! -d "${APP_SOURCE}" ]]; then
  echo "==> ClaudeGuard.app not found in dist/, running bundle_app.sh first..."
  "${SCRIPT_DIR}/bundle_app.sh"
fi

APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${APP_SOURCE}/Contents/Info.plist" 2>/dev/null || echo "1.0.0")"
DMG_NAME="ClaudeGuard-${APP_VERSION}-macOS.dmg"
FINAL_DMG="${DIST_DIR}/${DMG_NAME}"

chmod +x "${HELPER_SCRIPT}"
# Also copy a standalone copy of the helper script into dist/ for convenience
/bin/cp -f "${HELPER_SCRIPT}" "${DIST_DIR}/一键解除macOS警告.command"
chmod +x "${DIST_DIR}/一键解除macOS警告.command"
/usr/bin/xattr -d com.apple.FinderInfo "${DIST_DIR}/一键解除macOS警告.command" 2>/dev/null || true

STAGE_DIR="/tmp/claudeguard_dmg_stage_$$"
TEMP_DMG="/tmp/claudeguard_temp_$$.dmg"
rm -rf "${STAGE_DIR}" "${TEMP_DMG}"
mkdir -p "${STAGE_DIR}"

echo "==> [1/3] Preparing DMG staging folder..."
/usr/bin/ditto --noextattr --norsrc "${APP_SOURCE}" "${STAGE_DIR}/ClaudeGuard.app"
/bin/ln -s /Applications "${STAGE_DIR}/Applications"
/bin/cp "${HELPER_SCRIPT}" "${STAGE_DIR}/一键解除macOS警告.command"
chmod +x "${STAGE_DIR}/一键解除macOS警告.command"

# Copy custom volume icon so the mounted DMG shows the Claude Guard shield icon
if [[ -f "${APP_SOURCE}/Contents/Resources/AppIcon.icns" ]]; then
  /bin/cp "${APP_SOURCE}/Contents/Resources/AppIcon.icns" "${STAGE_DIR}/.VolumeIcon.icns"
  /usr/bin/SetFile -a C "${STAGE_DIR}" 2>/dev/null || true
fi

cat > "${STAGE_DIR}/安装与去警告说明.txt" <<'EOF'
Claude Guard (macOS 26+ 原生版) — 安装与首次打开说明
==================================================

【标准安装步骤】
1. 将本窗口中的「ClaudeGuard.app」拖拽到「Applications（应用程序）」文件夹中。
2. 双击本窗口中的「一键解除macOS警告.command」脚本：
   - 你可以直接将「ClaudeGuard.app」（无论是从本 DMG 窗口里，还是从“应用程序”文件夹里）拖进弹出的终端窗口并按回车；
   - 或者如果已经拖进了“应用程序”文件夹，直接在终端窗口按一下【回车键】，脚本就会自动完成修复并询问是否立即启动！

【提示：如果在其他 Mac 上首次打开脚本提示“未验证开发者”】
- 按住键盘 Control 键点击「一键解除macOS警告.command」-> 选择「打开」；
- 或者在终端执行：
  xattr -rd com.apple.quarantine /Applications/ClaudeGuard.app

【命令行工具】
安装后内置 CLI 位于：
  /Applications/ClaudeGuard.app/Contents/MacOS/claude-guard
EOF

/usr/bin/xattr -cr "${STAGE_DIR}" 2>/dev/null || true

echo "==> [2/3] Creating compressed UDZO disk image..."
/usr/bin/hdiutil create \
  -volname "${VOLUME_NAME}" \
  -srcfolder "${STAGE_DIR}" \
  -ov \
  -format UDZO \
  -imagekey zlib-level=9 \
  "${TEMP_DMG}"

echo "==> [3/3] Finalizing ${FINAL_DMG} and root copies..."
mkdir -p "${DIST_DIR}"
rm -f "${FINAL_DMG}"
/bin/mv "${TEMP_DMG}" "${FINAL_DMG}"
/bin/cp -f "${FINAL_DMG}" "${PROJECT_DIR}/${DMG_NAME}"
rm -rf "${STAGE_DIR}"

echo "✅ DMG package ready:"
ls -lh "${PROJECT_DIR}/${DMG_NAME}" "${FINAL_DMG}" "${DIST_DIR}/一键解除macOS警告.command"
