# space-search-collector

使用 Python 标准库从 FOFA、Hunter、Quake 按配置语法采集资产，合并已有 URL 并去重。Python 3.9 或以上，无第三方运行依赖。

## 使用

```sh
python3 space_search_collector.py                       # 全部已配置来源
python3 space_search_collector.py -s quake               # 仅 Quake
python3 space_search_collector.py -s fofa hunter         # 两个来源
python3 space_search_collector.py -s fofa,quake          # 支持逗号分隔
python3 space_search_collector.py -c config.json -o assets.txt -l assets.log
python3 space_search_collector.py -s fofa --new            # 强制新建 FOFA 任务
python3 space_search_collector.py -s fofa -q 'port="80"'    # 临时查询, 不写回配置
python3 space_search_collector.py -s quake --resume quake_cidr_state/具体运行目录
```

不存在配置时，脚本生成模板并退出，填写凭据和语法后再次运行。顶层 `sources` 默认 `"all"`，也支持 `"quake"` 或 `["fofa", "hunter"]`；命令行 `-s` / `--sources` / `--source` 优先。只校验和调用选中来源。所有相对路径基于启动时的工作目录。

来源选择只控制本轮请求，原输出中的历史 URL 仍会保留。需要单独查看某来源的结果时，请使用新的 `-o` 输出文件。

## Quake：默认使用 CIDR 二分

既有配置不必修改：`all=true` 且没有显式设置 `cidr=false` 时，使用新的 CIDR 主流程。原有 `adaptive` / `partition` 配置不再决定此流程的查询范围。原始语法始终放在括号内，与网段、端口条件取交集。

1. 分别从 IPv4 `0.0.0.0/0` 与 IPv6 `::/0` 开始查询。
2. 首屏返回的 `total` 大于窗口时，保留已有可用资产，将网段二分，继续处理子网。
3. `total` 在窗口内时，继续翻页直到取完；500 条一页不代表只取一页，短页也不自动视为结束。
4. 到单个地址 `/32` 或 `/128` 仍超限时，按返回端口拆分，并添加排除已见端口的 NOT 尾分区。尾分区还能发现未采样端口。
5. 单 IP、单端口仍超限时，保留已取得部分并记录为未完整，不无限拆分。

Quake 的[官方工具示例](https://github.com/360quake/quake_rs#readme)展示了 `ip:"网段/前缀"` 的查询语法。IPv6 CIDR 是否被当前接口/账号接受仍需实际运行确认；如果接口拒绝，会记录为未完整，不当作空结果。

可选配置（放在 `module.quake` 中，保留原有 URL、keys 和 query）：

```json
{
  "all": true,
  "cidr": true,
  "state_dir": "quake_cidr_state",
  "ip_versions": [4, 6],
  "window": 1000,
  "pageSize": 500,
  "interval": 3,
  "timeout": 30,
  "retries": 5,
  "min_page_size": 50,
  "masked_key_probes": 3,
  "max_partitions": 100000
}
```

- `window` 是单个查询的可翻页窗口，默认 1000，依据本次账号运行日志设置；更高权限账号可调整。
- `pageSize` 为单次请求条数，CIDR 流程最多请求 500。网络超时减小条数，默认不低于 min_page_size=50（初始 pageSize 更小时以初始值为准）；连续成功两次后逐步回升，避免长时间按1条翻页。接口实际首屏条数限制可进一步降低此目标。
- `ip_versions` 可选 `[4]`、`[6]` 或默认 `[4, 6]`。
- `max_partitions` 限制本轮断点中累计创建的任务数；达到上限会保留未完整任务，可提高参数后继续。
- `all=false` 时使用原来的限量采集流程，`size` 才会限制数量；`cidr=false` 可显式使用地域/端口采集流程。

CIDR 解决查询窗口问题，不能增加账号权限或额度，也不能还原隐藏 IP。多个 key 用于权限/额度失败后的同页接续，`full_keys` 优先用于尝试获得完整地址。内部节点仅需 total，超过窗口时直接二分，不为掩码在父节点测试所有 key。叶子全掩码页默认最多探测 masked_key_probes=3 个 key，未测试的 key 不判无效；剩余缺失保留待补采，下次恢复会推进探测位置。可提高该参数至 key 总数以穷尽本页权限探测，代价是增加请求和耗时。掩码 IP 带可用域名时保留域名 URL；无可用地址或格式异常的记录会计数并留下待补采任务。不根据某页掩码推断整个国家或其他网段均不可访问。

## 任务目录与恢复

默认 `run_mode="auto"`，FOFA 与 Quake CIDR 共用以下任务管理规则：

- `state_dir` 是任务父目录，默认分别为 `fofa_cidr_state`、`quake_cidr_state`。每次新任务创建独立时间戳子目录。
- 同查询、同接口、同数据范围有未完成任务时，自动选择已完成节点最多、累计请求数最多的任务恢复。其他旧候选通过旁边的 `run.json` 禁用自动恢复，状态和分片不删除。
- 已完成任务不会当成缓存反复复用；再次启动会创建新目录采集最新数据。`--new` 强制新建，旧任务及结果仍保留。
- `--resume DIR` 明确指定运行目录，需用 `-s` 选择 FOFA 或 Quake 单一来源；查询或已记录的数据范围不匹配会拒绝恢复，不会悄悄覆盖配置中的语法。新格式 FOFA 断点核对账号；旧格式未记录的账号/地址无法追溯核验。Quake 允许更换 keys 以补采未完整任务。`-q` 也要求选择单一来源。
- 兼容旧的固定目录断点：若父目录本身有匹配的未完成 `state.json`，可就地恢复，无需移动用户数据。旧 FOFA 任务只差 CSV 合并时，也可只恢复合并，不再次请求 API。
- `run.json` 保存来源、查询身份与运行状态，不含 API key；`state.json` 保存引擎断点；`parts/` 保存分片。
- 任务目录加非阻塞进程锁，三源合并输出及日志也分别加锁。第二个进程若使用同一任务或输出，会明确报错，不并发覆盖。锁文件保留在原位，进程退出后操作系统会释放锁，不需手动删锁文件。

Quake 每页保存可用资产分片、网段、页偏移及端口线索。调度按页轮换网段，新子网排到其他待处理任务之后，避免深度优先的慢分区长期占用队列。旧断点中相同范围的重叠补采任务合并为一个任务，从最早未完整页重试，原已获得资产仍保留。分片只新增未保存的资产，不反复保存父子网重复结果。网络故障或额度耗尽保留待处理任务；掩码、语法拒绝、不可再细分等情况保留未完整记录，下次恢复时重试。FOFA 每个完成网段保存原始字段 CSV 分片。查询变化创建独立任务，不混入旧分片。

显式设置引擎 `run_mode="fixed"` 可保留之前固定目录和完成缓存行为；此时 `--new`、`--resume` 不可用。缺失/损坏的断点和分片不会自动删除。

## FOFA 完整字段导出

每个 FOFA 任务完成后，按分片清单流式生成该目录下的 `fofa_merged.csv`，保留与单源项目相同的十个原生字段：

`link, host, ip, port, protocol, title, country, region, city, domain`

CSV 不经过资产 URL 去重，即使某行不能构造成可用 URL，原始字段也会保留。它代表这一轮 FOFA 原始结果；三源 `assets.txt` 则继续保留历史 URL 并合并去重，二者用途不同。采集已结束但 CSV 合并失败时，下次自动只补做合并，不再消耗请求。

FOFA 的 `timeout` 已实际传入请求层，默认 30 秒，`full` 默认 false，支持显式 true；分片上限固定 10000，成功后间隔默认 0.5 秒。单 IP 超限会保留已返回部分，并将任务标为 partial；纯 IPv4 二分无法保证取尽这类结果。

## 代码结构

- `fofa_api.py`：FOFA 请求参数和响应解析；传输函数可注入，便于离线验证。
- `collector_runs.py`：来源无关的任务选择、生命周期、原子存储和进程锁，供 FOFA 与 Quake 复用。
- `space_search_collector.py`：命令行和对外模块入口、引擎采集、标准化与三源合并。既有 `load_config` / `run_collect` 接口保留；并发调用的结果槽通过上下文隔离。

项目仍有进一步拆分 Hunter、Quake 引擎的空间；目前并未声称所有引擎都完成独立模块化。三源返回去重资产列表，内存需求仍高于单源只做磁盘分片与流式合并的模式。

## 实时状态与文件

Quake 请求前显示阶段、key 编号、网段/偏移、请求条数和超时设置；每 5 秒显示等待时长。收到响应后分类显示认证、权限、额度、限流及网络错误，不显示密钥值。每页显示新增、掩码、无效、重复、累计请求及可用资产数；结束时分别报告已完成、待处理和未完整任务。任务目录的 quake_urls.txt 在恢复后立即生成，每15秒或退出时原子更新，可在整个模块结束前查看部分结果。该文件是任务实时快照，最终三源 assets.txt 仍在模块结束/中断后合并。

采样（旧流程）、翻页、切换网段及换 key 重试均共享请求间隔；限流后延长跨 key 的间隔。超时不判定 key 无效，持续失败会停止并保留断点。

URL 输出、资产详情日志、状态和分片均以同目录临时文件写完后原子替换，单文件失败不截断原文件。两个输出文件不构成跨文件事务。HTTPS 默认验证证书。

## 验证

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile space_search_collector.py
```

测试使用临时目录和模拟响应，不调用真实平台、不消耗 API 额度。包括二分、叶子翻页、IPv6、端口尾分区、精确断点恢复、权限切换、网络错误、掩码及部分结果抢救等场景。
