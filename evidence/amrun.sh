# ============================================================================
# amrun.sh —— 人工基线的采集外壳。**必须 source，不能直接执行。**
#
# 为什么需要它：
#   README 里写的
#       AM_ALL=1 AM_JSON=1 sudo -E ./Agentmo $$ empty.conf > human1.jsonl
#       # ... 在这个 shell 里正常跑一遍 workflow ...
#   是跑不通的 —— Agentmo 在前台，这个 shell 被它占住了，根本没法再敲命令。
#   照着做的结果就是：起来、Ctrl-C、空文件。
#
#   另外一个坑：Agentmo 跑在 sudo 下，是 root 进程。普通用户 `kill -INT` 它会
#   EPERM，脚本会卡在 wait 上。停的时候必须 `sudo kill`。
#
# 用法（在你要干活的那个 shell 里）：
#       source evidence/amrun.sh
#       am_start human1          # 起监控，锚点 = 当前这个 shell
#       ... 正常把 1000genome 从头跑到提交完成 ...
#       am_stop                  # 收工，出 human1.jsonl + human1.err
#
# 纪律（照抄 NEXT_SESSION_BRIEF.md §3）：
#   * am_start 之后才 fork 出来的进程才会被登记。所以 **先 am_start，再动手**。
#     已经在跑的后台进程抓不到。
#   * 每一遍基线用不同的 tag（human1 / human2 / human3），mkpolicy.py 取并集。
#
# 另一种同样可以的做法（不想 source 就用这个，两个终端）：
#   终端 A:  echo $$              # 记下这个 PID，然后就在 A 里干活
#   终端 B:  AM_ALL=1 AM_JSON=1 sudo -E ./Agentmo <A的PID> empty.conf > human1.jsonl
#   干完:    终端 B 按 Ctrl-C
#   这个办法和 AI 轮次的形态是一样的（锚点是别的进程，Agentmo 单独一个终端），
#   所以其实更贴近正式实验。
# ============================================================================

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	echo "amrun.sh 要 source，不要直接跑：  source ${0}" >&2
	exit 2
fi

AM_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AM_BIN="${AM_BIN:-$AM_HOME/Agentmo}"
AM_EMPTY="${AM_EMPTY:-$AM_HOME/empty.conf}"
AM_PID=""
AM_TAG=""

am_start() {
	AM_TAG="${1:-human1}"
	local pol="${2:-$AM_EMPTY}"

	if [ -n "$AM_PID" ] && kill -0 "$AM_PID" 2>/dev/null; then
		echo "已经在跑了（pid $AM_PID, tag $AM_TAG）。先 am_stop。" >&2
		return 1
	fi
	[ -x "$AM_BIN" ] || { echo "没有 $AM_BIN，先 make" >&2; return 1; }
	[ -f "$pol" ] || : > "$pol"

	sudo -v || return 1

	# 锚点是 $$ —— source 进来的时候 $$ 就是你这个交互 shell 的 PID。
	AM_ALL=1 AM_JSON=1 sudo -E "$AM_BIN" "$$" "$pol" \
		> "$AM_HOME/$AM_TAG.jsonl" 2> "$AM_HOME/$AM_TAG.err" &
	AM_PID=$!

	local i
	for i in $(seq 1 60); do
		grep -q 'Agentmo running' "$AM_HOME/$AM_TAG.err" 2>/dev/null && break
		sleep 0.2
	done
	if ! grep -q 'Agentmo running' "$AM_HOME/$AM_TAG.err" 2>/dev/null; then
		echo "起不来：" >&2; cat "$AM_HOME/$AM_TAG.err" >&2
		AM_PID=""; return 1
	fi
	sleep 0.5
	echo ">> Agentmo 已附着  锚点=$$  tag=$AM_TAG  pid=$AM_PID"
	echo ">> 现在开始干活。完了敲 am_stop。"
}

am_stop() {
	[ -n "$AM_PID" ] || { echo "没在跑" >&2; return 1; }
	# root 进程，必须 sudo kill
	sudo kill -INT "$AM_PID" 2>/dev/null || kill -INT "$AM_PID" 2>/dev/null
	local i
	for i in $(seq 1 50); do
		kill -0 "$AM_PID" 2>/dev/null || break
		sleep 0.2
	done
	kill -0 "$AM_PID" 2>/dev/null && sudo kill -TERM "$AM_PID" 2>/dev/null
	wait "$AM_PID" 2>/dev/null
	echo ">> 停了。日志: $AM_HOME/$AM_TAG.jsonl"
	echo ">> 自检报告（盲区数字在这里）:"
	sed -n '/EXECUTION ATTESTATION/,$p' "$AM_HOME/$AM_TAG.err"
	AM_PID=""
}

am_status() {
	if [ -n "$AM_PID" ] && kill -0 "$AM_PID" 2>/dev/null; then
		echo "运行中  tag=$AM_TAG  pid=$AM_PID  事件数=$(grep -c '^{' "$AM_HOME/$AM_TAG.jsonl" 2>/dev/null || echo 0)"
	else
		echo "没在跑"
	fi
}

echo "amrun.sh 已载入。命令: am_start <tag>  /  am_stop  /  am_status"
