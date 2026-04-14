# FirmGFuzz Static Analyzer
FirmGFuzz 项目的静态分析核心模块，集成固件解析、反汇编、MMIO 分析、控制流分析、符号恢复、数据流分析、符号执行等能力，为固件模糊测试提供全面的静态分析支撑。

## 一、模块概述
该模块（`FirmGFuzz/static_analyzer.py`）是 FirmGFuzz 静态分析的核心入口，将多个细分分析组件（ELF/BIN 解析、反汇编、MMIO 检测、控制流分析等）封装为统一的 `StaticAnalyzer` 类，支持一键执行全流程静态分析，并可输出结构化分析结果。

核心目标：
- 解析固件架构（ELF/BIN 格式、CPU 架构、位宽/字节序）；
- 反汇编固件代码并提取指令；
- 识别 MMIO（内存映射 I/O）访问行为；
- 分析控制流并提取函数/基本块信息；
- 恢复外设符号信息；
- （可选）通过数据流分析+符号执行提升 MMIO 地址解析覆盖率。

## 二、目录结构
```
FirmGFuzz/
├── static_analyzer.py       # 静态分析核心入口（封装所有分析逻辑）
└── analysis/                # 细分分析组件目录（被static_analyzer依赖）
    ├── file_parser.py       # ELF/BIN 文件解析 + 架构信息提取（ELFParser/BINParser/ArchInfo）
    ├── disasm.py            # 通用反汇编器（UniversalDisassembler）
    ├── mmio_analyzer.py     # MMIO 访问模式分析（MMIOPatternAnalyzer/MMIOAccess）
    ├── control_flow.py      # 控制流分析（ControlFlowAnalyzer/Function）
    ├── symbol_recovery.py   # 外设符号恢复（SymbolRecovery/IdentifiedPeripheral）
    ├── dataflow.py          # 数据流分析（DataFlowAnalyzer）
    └── symbolic.py          # 符号执行+混合分析（HybridAnalyzer/ANGR_AVAILABLE）
```

## 三、快速开始
### 1. 依赖说明
- 基础依赖：`capstone`（反汇编）、`pyelftools`（ELF 解析）、`logging`（日志）、`dataclasses`（数据结构）；
- 高级分析依赖（符号执行）：`angr`（需手动安装，未安装则自动禁用符号执行）。

### 2. 基础使用示例
```python
import logging
from FirmGFuzz.static_analyzer import StaticAnalyzer

# 配置日志（可选，便于查看分析过程）
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 1. 初始化静态分析器（启用高级分析：数据流+符号执行）
analyzer = StaticAnalyzer(
    firmware_path="./firmware.bin",  # 固件文件路径（ELF/BIN 均可）
    enable_advanced=True             # 开启高级分析（需安装angr）
)

# 2. 执行全流程分析（最大反汇编指令数限制为10000）
analysis_result = analyzer.analyze(max_instructions=10000)

# 3. 打印分析摘要
analyzer.print_summary()

# 4. 导出分析结果到指定目录（生成JSON文件）
analyzer.export_results(output_dir="./analysis_results")
```

## 四、核心类说明
### 1. StaticAnalyzer（核心分析器）
封装全流程静态分析的主类，核心方法如下：

| 方法 | 入参 | 出参 | 功能说明 |
|------|------|------|----------|
| `__init__` | `firmware_path`（固件路径）、`enable_advanced`（是否启用高级分析） | - | 初始化分析器，指定固件路径和高级分析开关 |
| `analyze` | `max_instructions`（最大反汇编指令数） | `StaticAnalysisResult` | 执行全流程静态分析，返回结构化结果 |
| `print_summary` | - | - | 打印分析摘要（架构、指令数、MMIO、外设等） |
| `export_results` | `output_dir`（输出目录） | - | 将分析结果导出为JSON文件（函数、MMIO、外设、高级分析结果） |

### 2. StaticAnalysisResult（分析结果容器）
存储所有静态分析结果的结构化数据类，核心字段如下：

| 字段 | 类型 | 说明 |
|------|------|------|
| `arch_info` | `ArchInfo` | 固件架构信息（架构、字节序、位宽） |
| `functions` | `Dict[int, Function]` | 识别的函数（key：函数起始地址，value：Function对象） |
| `mmio_accesses` | `List[MMIOAccess]` | 识别的MMIO访问记录 |
| `peripherals` | `List[IdentifiedPeripheral]` | 恢复的外设符号信息 |
| `total_instructions` | `int` | 反汇编总指令数 |
| `total_basic_blocks` | `int` | 总基本块数 |
| `resolved_mmio_addresses` | `Dict[int, int]` | 高级分析解析的MMIO地址映射 |
| `dataflow_coverage` | `float` | 数据流分析覆盖率（MMIO） |
| `symbolic_coverage` | `float` | 符号执行覆盖率（MMIO） |

## 五、分析流程详解
`StaticAnalyzer.analyze()` 方法会按以下步骤执行全流程分析：

### 步骤1：固件架构解析
- 优先尝试 ELF 格式解析（`ELFParser`），失败则降级为 BIN 格式启发式解析（`BINParser`）；
- 输出架构（如ARM/MIPS）、字节序（大/小端）、位宽（32/64位）。

### 步骤2：反汇编
- 通过 `UniversalDisassembler` 对固件代码段（BIN 从 0x0800010c 起始）进行反汇编；
- 限制最大指令数（`max_instructions`），避免分析耗时过长。

### 步骤3：MMIO 访问分析
- `MMIOPatternAnalyzer` 扫描反汇编指令，识别 MMIO 读/写操作；
- 统计 MMIO 访问总数、读/写操作数。

### 步骤4：控制流分析
- `ControlFlowAnalyzer` 分析指令流，提取函数、基本块、函数调用关系；
- 输出识别的函数总数、总基本块数。

### 步骤5：符号恢复
- `SymbolRecovery` 结合 MMIO 访问和函数信息，恢复外设类型、基地址、寄存器等符号信息；
- 输出识别的外设总数及置信度。

### 步骤6：高级分析（可选）
- 仅当 `enable_advanced=True` 时执行；
- 初始化 `HybridAnalyzer`，结合数据流分析（`DataFlowAnalyzer`）和符号执行（angr）解析 MMIO 地址；
- 计算数据流/符号执行对 MMIO 访问的覆盖率。

## 六、结果导出说明
执行 `export_results()` 后，输出目录会生成以下 JSON 文件：

| 文件 | 说明 |
|------|------|
| `functions.json` | 函数信息（起始/结束地址、大小、是否叶子函数、调用目标） |
| `mmio_accesses.json` | MMIO 访问记录（地址、操作类型、指令、读/写标记） |
| `peripherals.json` | 外设信息（类型、基地址、置信度、访问的寄存器） |
| `advanced_analysis.json` | 高级分析结果（解析的MMIO地址、数据流/符号执行覆盖率） |

## 七、注意事项
1. BIN 固件解析：BIN 格式无结构化信息，反汇编起始地址（0x0800010c）和读取长度（100KB）为硬编码，需根据实际固件调整 `_disassemble` 方法中的 `f.seek()` 和 `f.read()` 参数；
2. 符号执行依赖：高级分析需安装 `angr`，未安装时 `ANGR_AVAILABLE` 为 False，仅执行数据流分析；
3. 指令数限制：`max_instructions` 建议根据固件大小调整，过大会导致分析耗时过长，过小会丢失关键代码；
4. 架构支持：当前仅支持常见嵌入式架构（ARM/MIPS等），需确认 `ArchInfo` 枚举包含目标架构。
