# 快速开始

## 环境

- Python 3.10+（建议与团队一致）
- 可选：本仓库根目录创建虚拟环境

```bash
cd /path/to/ReBind_Demo
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 依赖说明

`requirements.txt` 覆盖主流程与测试常用第三方库。Ghidra、IDA 的安装路径在**仓库根目录** `config.yaml` 的 `platforms.<系统>.ghidra` / `platforms.<系统>.ida`（及 `semantics.runtime`）中配置，不在 pip 范围内。

## 运行主脚本

查看全部子命令与参数：

```bash
python rebind_demo.py -h
```

典型用法（需按本机修改 `config.yaml` 中的工具路径）：

```bash
python rebind_demo.py /path/to/sample.bin
```

仅语义对齐或深路径等模式请直接阅读 `rebind_demo.py` 的 `--help` 输出；底层也可单独调用 `tools/Semantics_Alignment/` 下的脚本（需在对应目录或配置好 `PYTHONPATH`）。

## 运行测试

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
python -m pytest -q
```

## 文档索引

- [目录说明](./directory-layout.md)
- [流水线架构](./architecture.md)
- [Goal Deep Engine / Phase7.5](./goal-deep-engine.md)
- [可观测与断点续跑](./observability.md)
