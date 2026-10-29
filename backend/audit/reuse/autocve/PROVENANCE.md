# AutoCVE 复用边界与来源说明

- 参考仓库：<https://github.com/larlarua/AutoCVE>
- 固定提交：`b26025f27199ba2d93145e4a08fc9015e8d846e4`
- 本地只读调查：`/home/luchitong/work/AutoCVE`

## 许可状态（未决）

该仓库的 `pyproject.toml` 声明 MIT，但仓库同时带有 AGPL-3.0 许可文本。两者冲突，
在维护者澄清或法律确认前，本目录**不复制上游源码**，也不把上游代码当作可再许可的
先例引用。

## 本目录实现

`knowledge.py`、`finding_contract.py`、`recon.py`、`candidates.py` 是按上游接口形状
重新实现的适配层：

- 知识路由：按语言、框架、检查点做确定性选择；资源带版本、SHA-256 与字节上限；
  资源缺失、哈希不符、越界都产生可诊断结果。知识正文为本项目原创方法提示。
- 发现合同：按结论状态分层要求字段；逐字段拒绝；`confirmed`/`is_verified` 等宿主
  状态字段被忽略并留诊断，模型不能直通动态验证。
- Recon 归一化：只保留冻结项目图中的路径，行号按文件长度夹取；丢弃项留诊断；输出
  明确标注为导航线索而非证据。
- 候选排序：只排序、不合并；同一路径同一类型仍是两个候选。

## 未复用的上游部分

- Orchestrator、Finding runtime、文件队列、token/成本核算。
- `confirmed`/`is_verified` 到“已验证”的映射。
- 推理内容持久化、扫描流水线、写源码根目录的产物。
