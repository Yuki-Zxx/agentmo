#!/usr/bin/env bash
# ============================================================================
# 人工基线 —— 监控窗口内执行的**全部**内容。三遍必须跑同一个脚本。
#
#   为什么要写成脚本而不是手敲：手敲三遍，命令顺序、拼写、多按的一次 ls、
#   看了一眼的 tail，都会进白名单，而且三遍各不相同。白名单是行为的快照，
#   快照糊了后面全糊。脚本保证三遍的动作序列逐字相同，唯一的差异只剩
#   「轮询了几次」—— 而 mkpolicy 只看规则种类，不看次数。
#
#   用法（在 am_start 之后）：
#       ./baseline_run.sh
#       STATIONS=40 READINGS=2000 POLL=20 ./baseline_run.sh
#
#   ⚠️ 这个脚本里**不包含**任何清理、挂载、chown、改配置。
#      那些都在窗口外，由 baseline_prep.sh 负责。理由见该脚本开头。
# ============================================================================
set -eu

BASE="${BASE:-/home/napkin/napkin-vibe-example}"
STATIONS="${STATIONS:-40}"
READINGS="${READINGS:-2000}"
POLL="${POLL:-20}"          # 轮询间隔（秒）。三遍必须用同一个值。

ts() { date +%s; }

cd "$BASE"

echo "== [$(ts)] 1/4 生成 workflow =="
python3 ./workflow_generator.py --stations "$STATIONS" --readings "$READINGS"

echo "== [$(ts)] 2/4 plan + submit =="
pegasus-plan --submit -s condorpool -o local workflow.yml 2>&1 | tee plan.out

# 从 plan 输出里取 run 目录和 condor cluster id。
# 用 awk 而不是 grep -P：pegasus 的提示行格式在 5.0.x 里是稳定的，
# 而且 awk 一个进程就够，少一种进入白名单的程序。
RUNDIR=$(awk '/pegasus-status -l/ {print $NF; exit}' plan.out)
CLUSTER=$(awk '/submitted to cluster/ {gsub(/[.:]/,"",$NF); print $NF; exit}' plan.out)
echo "RUNDIR=$RUNDIR"
echo "CLUSTER=$CLUSTER"
[ -n "$RUNDIR" ] || { echo "!! 没解析出 RUNDIR，看 plan.out"; exit 1; }

echo "== [$(ts)] 3/4 等 DAG 结束（每 ${POLL}s 轮询一次）=="
# 判定条件用 condor_q 的 cluster id，不解析 pegasus-status 的文字 ——
# 文字会随版本变，cluster 从队列里消失是确定性的。
POLLS=0
while [ -n "$(condor_q "$CLUSTER" -af ClusterId 2>/dev/null || true)" ]; do
    POLLS=$((POLLS + 1))
    sleep "$POLL"
done
echo "轮询次数 = $POLLS"

echo "== [$(ts)] 4/4 统计 =="
pegasus-status -l "$RUNDIR" || true
pegasus-statistics -s all "$RUNDIR"

echo "== [$(ts)] 完成 =="
echo "RUNDIR=$RUNDIR  CLUSTER=$CLUSTER  POLLS=$POLLS"
