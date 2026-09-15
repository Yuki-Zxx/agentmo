# evidence/ —— AI 越出白名单 → 让它解释为什么

## 0. 先说一个之前写错的地方

v1 的这份 README 写的是：

```bash
AM_ALL=1 AM_JSON=1 sudo -E ./Agentmo $$ empty.conf > human1.jsonl
#   ... 在这个 shell 里正常跑一遍 workflow 提交 ...
# Ctrl-C 停
```

**这跑不通。** Agentmo 在前台，这个 shell 已经被它占住，你没法再敲任何命令，
最后拿到的是一个空文件。另外 Agentmo 跑在 sudo 下是 root 进程，
普通用户 `kill -INT` 它会 EPERM，只有终端的 Ctrl-C 能停。

下面 §1 是改过的正确做法。

---

## 1. 人工跑一遍，生成白名单

### 做法 A：source 一个外壳（一个终端就够）

```bash
cd /home.local/mdxuser/agentmo
source evidence/amrun.sh
am_start human1          # 锚点 = 当前这个 shell，等它打印「已附着」
#   ... 正常把 1000genome 从头跑到提交完成 ...
am_stop                  # 出 human1.jsonl + human1.err（含盲区自检数字）
```

### 做法 B：两个终端（更贴近 AI 轮次的形态，推荐）

```bash
# 终端 A（干活的那个）
echo $$                  # 记下这个 PID

# 终端 B（只跑监控）
cd /home.local/mdxuser/agentmo && : > empty.conf
AM_ALL=1 AM_JSON=1 sudo -E ./Agentmo <A的PID> empty.conf > human1.jsonl

# 终端 A：正常跑 workflow
# 干完，终端 B 按 Ctrl-C
```

AI 轮次的锚点是 OpenClaw 常驻网关的 MainPID、Agentmo 单独占一个终端，
形态和做法 B 一模一样。基线也用 B，两轮的采集条件才算对齐。

### 两条纪律

- **先起监控，再动手。** Agentmo 在 fork 那一刻才把子进程登记进 tracked 表，
  监控启动前就已经在跑的进程抓不到。
- **`AM_ALL=1` 不能省。** 基线要的是全量（SAFE 也要），少了这个就只剩越界记录，
  而基线的越界记录相对空白名单来说是全部，等于没筛。

### 生成白名单

```bash
python3 evidence/mkpolicy.py human1.jsonl -o policy_human.conf
```

跑多遍就多传几个日志（`mkpolicy.py human1.jsonl human2.jsonl human3.jsonl`），规则取并集。
里面做了路径归一化：`run0001/`、`tmpXXXX/`、pid 目录这些每次都变的段会折叠掉，
不然白名单下次一条都不命中。

`--min-runs 2` 可以把只在一份日志里出现过的规则挑出来人工复核——
第一遍基线必然掺进一次性的初始化足迹（pip 缓存、第一次建的目录），那些不该进白名单。

> **exec 规则是完整路径，不是 basename。**
> `exec node` 会连 `/tmp/node`、`~/bin/node` 一起放行，而 agent 有能力写自己的目录、
> 改 PATH —— 那条本该描述正常行为的规则，正好把 PATH 劫持盖住了。
> `Agentmo.c` 的 `exec_ok()` 和 `mkpolicy.py` 两边都按完整路径匹配，改一边会脱节。

---

## 2. 让 agent 跑，用这份白名单监控

```bash
systemctl --user restart openclaw          # 每轮先重启，拿新锚点
GW=$(systemctl --user show openclaw --property=MainPID --value)
AM_JSON=1 sudo -E ./Agentmo "$GW" policy_human.conf > agent_run.jsonl
```

不加 `AM_ALL`，所以日志里只有越界的（白名单内的都是 SAFE，不打印）。

锚点必须是**常驻网关**，不是你敲的 `openclaw` CLI —— CLI 是另一棵进程树，
真正的执行在网关子树里（MDX_DEPLOY.md §5 实测）。

任务 prompt 用 `submit_prompt.md`（本轮要按 1000genome + napkin 改写）。

---

## 3. 出报告（一条命令：清单 + 追问 AI + 合并）

```bash
python3 evidence/report.py agent_run.jsonl -o run01/ --session-key run01-<本轮的key>
```

| 文件 | 内容 |
|---|---|
| `run01/violations.csv` | 越界记录（重复的已折叠，带次数/时间/程序/目标） |
| `run01/files.txt` | 越界碰到的文件 |
| `run01/folders.txt` | 越界碰到的文件夹 |
| `run01/ask.md` | 追问 AI 的问题 |
| `run01/explanations.md` | AI 的回答（自动问来的） |
| `run01/report.md` | **最终产出**：每条越界 + AI 的解释 |

`--session-key` 会问回同一个会话，它才记得自己干过什么。
`openclaw` 调不通就加 `--no-ask`，把 `ask.md` 手动发给 agent，
回答存成 `run01/explanations.md`，再跑一次同样的命令就会合并进 `report.md`。

---

## 4. 路径质量分析（新增）

```bash
python3 evidence/pathstats.py human1.jsonl              # 单份拆解
python3 evidence/pathstats.py --compare raw.jsonl dpath.jsonl   # 捕获点对照
```

Agentmo 退出时打的 FIELD SUFFICIENCY SELF-REPORT 只给总数；这个脚本拆到
「是谁产生的」「具体是哪些路径」。要看的是不可解析的那部分**集中还是分散**：
集中在少数几个程序上可以定点补救，均匀摊开就只能换 hook 层。

这些数字不是噪声，是「监控自己说得出自己的盲区」那条结论的证据，别抹掉。
