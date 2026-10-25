#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
PROJECT_DIR="${SCRIPT_DIR:h}"
DIST_DIR="${PROJECT_DIR}/dist"
STAGE_ROOT="/tmp/claudeguard_stage_$$"
APP_BUNDLE="${STAGE_ROOT}/ClaudeGuard.app"
FINAL_APP="${DIST_DIR}/ClaudeGuard.app"
CONTENTS_DIR="${APP_BUNDLE}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-/tmp/cg-clang-cache}"
export SWIFTPM_MODULECACHE_OVERRIDE="${SWIFTPM_MODULECACHE_OVERRIDE:-/tmp/cg-swiftpm-cache}"

echo "==> [1/4] Building Release binaries (ClaudeGuardApp + claude-guard)..."
swift build -c release --disable-sandbox \
  --package-path "${PROJECT_DIR}" \
  --scratch-path /tmp/cg-release-build \
  --cache-path /tmp/cg-spm-cache \
  --config-path /tmp/cg-spm-config \
  --security-path /tmp/cg-spm-sec \
  -Xcc -fmodules-cache-path="${CLANG_MODULE_CACHE_PATH}" \
  -Xswiftc -module-cache-path -Xswiftc "${SWIFTPM_MODULECACHE_OVERRIDE}"

BIN_DIR="$(swift build -c release --disable-sandbox --package-path "${PROJECT_DIR}" --scratch-path /tmp/cg-release-build --show-bin-path --cache-path /tmp/cg-spm-cache --config-path /tmp/cg-spm-config --security-path /tmp/cg-spm-sec)"

echo "==> [2/4] Assembling ${APP_BUNDLE}..."
rm -rf "${APP_BUNDLE}"
mkdir -p "${MACOS_DIR}" "${RESOURCES_DIR}"

cp "${BIN_DIR}/ClaudeGuardApp" "${MACOS_DIR}/ClaudeGuardApp"
cp "${BIN_DIR}/claude-guard" "${MACOS_DIR}/claude-guard"
chmod +x "${MACOS_DIR}/ClaudeGuardApp" "${MACOS_DIR}/claude-guard"

echo "==> [3/4] Generating AppIcon.icns..."
ICON_WORK="/tmp/claudeguard_icon_$$"
ICONSET_DIR="${ICON_WORK}/AppIcon.iconset"
mkdir -p "${ICONSET_DIR}"

cat > "${ICON_WORK}/make_icon.swift" <<'EOF'
import AppKit
import CoreGraphics

let outPath = CommandLine.arguments[1]
let size = 1024
let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: size,
    pixelsHigh: size,
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .calibratedRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
)!

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext

// Rounded squircle background
let inset: CGFloat = 92
let bgRect = CGRect(x: inset, y: inset, width: CGFloat(size) - inset * 2, height: CGFloat(size) - inset * 2)
let bgPath = CGPath(roundedRect: bgRect, cornerWidth: 196, cornerHeight: 196, transform: nil)
ctx.saveGState()
ctx.addPath(bgPath)
ctx.clip()

let colors = [
    NSColor(calibratedRed: 0.08, green: 0.14, blue: 0.24, alpha: 1.0).cgColor,
    NSColor(calibratedRed: 0.11, green: 0.36, blue: 0.38, alpha: 1.0).cgColor,
    NSColor(calibratedRed: 0.16, green: 0.62, blue: 0.48, alpha: 1.0).cgColor
] as CFArray
let grad = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0.0, 0.55, 1.0])!
ctx.drawLinearGradient(grad, start: CGPoint(x: 120, y: 920), end: CGPoint(x: 900, y: 120), options: [])
ctx.restoreGState()

// Subtle glass rim border
ctx.saveGState()
ctx.addPath(bgPath)
ctx.setStrokeColor(NSColor(calibratedWhite: 1.0, alpha: 0.35).cgColor)
ctx.setLineWidth(10)
ctx.strokePath()
ctx.restoreGState()

// Original shield + check mark artwork (drawn with Core Graphics, no SF Symbols)
ctx.setAllowsAntialiasing(true)

let shield = CGMutablePath()
shield.move(to: CGPoint(x: 512, y: 226))
shield.addCurve(to: CGPoint(x: 772, y: 330), control1: CGPoint(x: 646, y: 248), control2: CGPoint(x: 726, y: 276))
shield.addLine(to: CGPoint(x: 772, y: 558))
shield.addCurve(to: CGPoint(x: 512, y: 838), control1: CGPoint(x: 772, y: 700), control2: CGPoint(x: 650, y: 798))
shield.addCurve(to: CGPoint(x: 252, y: 558), control1: CGPoint(x: 374, y: 798), control2: CGPoint(x: 252, y: 700))
shield.addLine(to: CGPoint(x: 252, y: 330))
shield.addCurve(to: CGPoint(x: 512, y: 226), control1: CGPoint(x: 298, y: 276), control2: CGPoint(x: 378, y: 248))
shield.closeSubpath()

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -14), blur: 30, color: NSColor.black.withAlphaComponent(0.35).cgColor)
ctx.addPath(shield)
ctx.setFillColor(NSColor.white.withAlphaComponent(0.96).cgColor)
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(shield)
ctx.clip()
ctx.setBlendMode(.normal)
let check = CGMutablePath()
check.move(to: CGPoint(x: 372, y: 505))
check.addLine(to: CGPoint(x: 474, y: 398))
check.addLine(to: CGPoint(x: 668, y: 592))
ctx.addPath(check)
ctx.setLineWidth(74)
ctx.setLineCap(.round)
ctx.setLineJoin(.round)
ctx.setStrokeColor(NSColor(calibratedRed: 0.045, green: 0.19, blue: 0.21, alpha: 1.0).cgColor)
ctx.strokePath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(shield)
ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.22).cgColor)
ctx.setLineWidth(4)
ctx.strokePath()
ctx.restoreGState()

NSGraphicsContext.restoreGraphicsState()

if let pngData = rep.representation(using: .png, properties: [:]) {
    try pngData.write(to: URL(fileURLWithPath: outPath))
}
EOF

swiftc "${ICON_WORK}/make_icon.swift" \
  -module-cache-path "${CLANG_MODULE_CACHE_PATH}" \
  -o "${ICON_WORK}/make_icon"
"${ICON_WORK}/make_icon" "${ICON_WORK}/master_1024.png"

for sz in 16 32 128 256 512; do
  /usr/bin/sips -z ${sz} ${sz} "${ICON_WORK}/master_1024.png" --out "${ICONSET_DIR}/icon_${sz}x${sz}.png" >/dev/null
  dbl=$(( sz * 2 ))
  /usr/bin/sips -z ${dbl} ${dbl} "${ICON_WORK}/master_1024.png" --out "${ICONSET_DIR}/icon_${sz}x${sz}@2x.png" >/dev/null
done

/usr/bin/iconutil -c icns "${ICONSET_DIR}" -o "${RESOURCES_DIR}/AppIcon.icns"
rm -rf "${ICON_WORK}"

cat > "${CONTENTS_DIR}/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>zh_CN</string>
    <key>CFBundleDisplayName</key>
    <string>Claude Guard</string>
    <key>CFBundleExecutable</key>
    <string>ClaudeGuardApp</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.claudeguard.app</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Claude Guard</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>100</string>
    <key>LSMinimumSystemVersion</key>
    <string>26.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticTermination</key>
    <false/>
</dict>
</plist>
EOF

echo "==> [4/4] Signing in clean staging directory and installing to ${FINAL_APP}..."
/usr/bin/xattr -cr "${APP_BUNDLE}"
/usr/bin/codesign --force --deep --sign - "${APP_BUNDLE}"
/usr/bin/codesign --verify --deep --strict "${APP_BUNDLE}"

mkdir -p "${DIST_DIR}"
rm -rf "${FINAL_APP}"
/usr/bin/ditto --noextattr --norsrc "${APP_BUNDLE}" "${FINAL_APP}"
/usr/bin/find "${FINAL_APP}" -exec /usr/bin/xattr -d com.apple.FinderInfo {} + 2>/dev/null || true
/usr/bin/codesign --verify --deep "${FINAL_APP}"
rm -rf "${STAGE_ROOT}"

echo "✅ Successfully packaged and verified: ${FINAL_APP}"
echo "   GUI App : ${FINAL_APP}"
echo "   CLI Tool: ${FINAL_APP}/Contents/MacOS/claude-guard"
