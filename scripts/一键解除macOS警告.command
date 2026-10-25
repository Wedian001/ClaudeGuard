#!/bin/zsh
# Claude Guard — 一键解除 macOS“无法验证开发者 / 已损坏”拦截警告工具
# 用法 1：双击运行本脚本 -> 将 ClaudeGuard.app 拖入终端窗口 -> 按回车
# 用法 2：先将 ClaudeGuard.app 拖入“应用程序”文件夹 -> 双击本脚本直接按回车自动修复
# 用法 3：命令行传参 ./一键解除macOS警告.command /Applications/ClaudeGuard.app
# 安全说明：本脚本只处理 ClaudeGuard.app，不会对任意第三方 .app 执行 xattr / codesign / sudo 操作。

set -u

clear
echo "════════════════════════════════════════════════════════════════"
echo "  🛡️  Claude Guard · macOS Gatekeeper 拦截警告一键解除工具"
echo "════════════════════════════════════════════════════════════════"
echo ""

unquote_dragged_path() {
  local raw="$1"
  # 去除首尾空白
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  # 利用 zsh 原生 (Q) 展开自动还原终端拖入时的反斜杠转义空格、单双引号及中文路径
  local unquoted="${(Q)raw}"
  # 去除末尾多余斜杠（保留 .app 完整路径）
  if [[ "$unquoted" != "/" ]]; then
    unquoted="${unquoted%/}"
  fi
  print -r -- "$unquoted"
}

fix_single_app() {
  local input_path="$1"
  local target_app
  target_app="$(unquote_dragged_path "$input_path")"

  if [[ -z "$target_app" ]]; then
    if [[ -d "/Applications/ClaudeGuard.app" ]]; then
      target_app="/Applications/ClaudeGuard.app"
      echo "📍 未输入路径，已自动定位到：${target_app}"
    else
      echo "❌ 未检测到输入路径，且 /Applications/ClaudeGuard.app 尚未安装。"
      echo "   请把 ClaudeGuard.app 直接拖入此窗口后再按回车！"
      return 1
    fi
  fi

  if [[ ! -e "$target_app" ]]; then
    echo "❌ 找不到目标路径：${target_app}"
    return 1
  fi

  if [[ "$target_app" != *.app || ! -d "$target_app" ]]; then
    echo "❌ 请拖入以 .app 结尾的 macOS 应用程序包（当前输入：${target_app}）"
    return 1
  fi

  local app_basename="${target_app:t}"

  # 安全边界：只允许处理本项目的 ClaudeGuard.app
  if [[ "${app_basename}" != "ClaudeGuard.app" ]]; then
    echo "❌ 本脚本仅用于修复 ClaudeGuard.app，当前输入为：${app_basename}"
    return 1
  fi
  local bundle_id
  bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${target_app}/Contents/Info.plist" 2>/dev/null || true)"
  if [[ "${bundle_id}" != "com.claudeguard.app" && "${bundle_id}" != "com.claudeguard.macos27" ]]; then
    echo "❌ 目标 .app 的 Bundle ID（${bundle_id:-unknown}）不是 Claude Guard，已拒绝处理。"
    return 1
  fi

  # 智能防呆：如果用户直接从只读 .dmg 挂载卷中把 .app 拖进来，自动先拷贝安装到 /Applications
  if [[ "$target_app" == /Volumes/* || ! -w "$target_app" ]]; then
    local dest_app="/Applications/${app_basename}"
    echo "📦 检测到您拖入的是只读磁盘映像中的 ${app_basename}"
    echo "   正在自动为您安装至 ${dest_app} ..."
    if /bin/rm -rf "$dest_app" 2>/dev/null && /usr/bin/ditto --noextattr --norsrc "$target_app" "$dest_app" 2>/dev/null; then
      target_app="$dest_app"
    else
      echo "🔐 写入 /Applications 需要管理员权限，请输入开机密码（输入时不显示星号）："
      sudo /bin/rm -rf "$dest_app"
      sudo /usr/bin/ditto --noextattr --norsrc "$target_app" "$dest_app"
      sudo /usr/sbin/chown -R "$(id -un):staff" "$dest_app"
      target_app="$dest_app"
    fi
    echo "✅ 已完成拷贝安装：${target_app}"
  fi

  echo "🔧 [1/3] 正在递归移除 macOS 隔离检疫属性 (com.apple.quarantine)..."
  if ! /usr/bin/xattr -rd com.apple.quarantine "$target_app" 2>/dev/null; then
    sudo /usr/bin/xattr -rd com.apple.quarantine "$target_app" 2>/dev/null || true
  fi
  /usr/bin/find "$target_app" -exec /usr/bin/xattr -d com.apple.FinderInfo {} + 2>/dev/null || true

  echo "🔧 [2/3] 正在校验并修复本地代码签名..."
  if ! /usr/bin/codesign --verify --deep --strict "$target_app" >/dev/null 2>&1; then
    echo "   检测到传输导致签名变动，正在重新执行本地 Ad-hoc 签名加固..."
    if ! /usr/bin/codesign --force --deep --sign - "$target_app" 2>/dev/null; then
      sudo /usr/bin/codesign --force --deep --sign - "$target_app"
    fi
  fi

  echo "🔧 [3/3] 正在注册系统 LaunchServices 启动信任状态..."
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$target_app" >/dev/null 2>&1 || true

  echo ""
  echo "🎉 修复完成！【${app_basename}】已彻底解除 macOS 自带拦截警告！"
  echo "   安装位置：${target_app}"
  echo ""

  if [[ -t 0 ]]; then
    printf "🚀 是否现在立即打开 %s ？[Y/n]: " "$app_basename"
    local open_choice=""
    read -r open_choice
    if [[ -z "$open_choice" || "$open_choice" == [Yy]* ]]; then
      /usr/bin/open "$target_app"
      echo "✅ 已启动 ${app_basename}！"
    fi
  fi
  return 0
}

# 如果通过命令行参数传入了 .app 路径，直接批量处理
if [[ $# -gt 0 ]]; then
  for arg in "$@"; do
    fix_single_app "$arg"
  done
  exit $?
fi

echo "请按以下任一方式操作："
echo "  1) 【推荐拖拽】将 ClaudeGuard.app（从 DMG 窗口或“应用程序”文件夹均可）直接拖入本窗口，按回车；"
if [[ -d "/Applications/ClaudeGuard.app" ]]; then
  echo "  2) 【一键直达】检测到 /Applications/ClaudeGuard.app 已存在，直接按【回车键】即可一键修复！"
fi
echo ""
printf "👉 请拖入软件图标到此处（或直接按回车）: "
dragged_input=""
read -r dragged_input
echo ""

fix_single_app "$dragged_input"
status_code=$?

echo ""
echo "════════════════════════════════════════════════════════════════"
printf "处理完毕，按回车键关闭本窗口..."
read -r _
exit $status_code
