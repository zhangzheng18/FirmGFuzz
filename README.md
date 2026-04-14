# FirmGFuzz Static Analyzer
FirmGFuzz 项目的静态分析核心模块，集成固件解析、反汇编、MMIO 分析、控制流分析、符号恢复、数据流分析、符号执行等能力，为固件模糊测试提供全面的静态分析支撑。

## 一、模块概述
该模块的核心入口为 `FirmGFuzz/static_analyzer.py`，封装了 `analysis/` 目录下所有细分分析组件，提供一键式全流程静态分析能力，支持 ELF/BIN 格式固件的架构解析、反汇编、MMIO 访问识别、控制流提取、外设符号恢复，并可选启用数据流分析+符号执行（基于 angr）提升 MMIO 地址解析覆盖率。

核心目标：
- 自动识别固件架构（CPU 架构、位宽、字节序）；
- 反汇编固件代码并提取指令序列；
- 精准识别 MMIO（内存映射 I/O）读/写操作；
- 分析控制流，提取函数、基本块及调用关系；
- 恢复外设符号（类型、基地址、寄存器）；
- （可选）通过数据流+符号执行提升 MMIO 地址解析覆盖率；
- 输出结构化分析结果（JSON 导出/控制台摘要）。

## 二、完整目录结构
```
FirmGFuzz/
├── static_analyzer.py               # 静态分析核心入口（封装所有分析逻辑）
├── tools/                           # 辅助工具目录
│   └── export_static_analysis.py    # 静态分析结果批量导出辅助工具
└── analysis/                        # 细分分析组件根目录
    ├── README.md                    # 分析组件说明文档
    ├── __init__.py                  # 分析模块初始化（使analysis成为Python包）
    ├── __pycache__/                 # Python编译缓存（可忽略）
    ├── control_flow/                # 控制流分析子模块（函数/基本块提取）
    ├── dataflow/                    # 数据流分析子模块（MMIO地址依赖分析）
    ├── disasm/                      # 通用反汇编子模块（基于capstone）
    ├── dynamic_mmio_monitor.py      # 动态MMIO监控工具（补充静态分析）
    ├── file_parser/                 # 文件解析子模块（ELF/BIN格式+架构识别）
    ├── mmio_analyzer/               # MMIO分析子模块（访问模式识别）
    ├── symbol_recovery/             # 符号恢复子模块（外设符号匹配）
    ├── symbolic/                    # 符号执行子模块（基于angr的混合分析）
    └── test_dynamic_monitor.py      # 动态MMIO监控工具测试用例
```

## 三、核心模块详解
### 3.1 主入口：static_analyzer.py
封装全流程静态分析的核心文件，包含两个核心类：

#### 1. StaticAnalyzer（核心分析器）
| 方法 | 入参 | 出参 | 功能说明 |
|------|------|------|----------|
| `__init__` | `firmware_path`（固件路径）、`enable_advanced`（是否启用高级分析） | - | 初始化分析器，指定固件路径和高级分析开关（数据流+符号执行） |
| `analyze` | `max_instructions`（最大反汇编指令数，默认10000） | `StaticAnalysisResult` | 执行全流程静态分析（6个步骤），返回结构化结果 |
| `print_summary` | - | - | 打印分析摘要（架构、指令数、MMIO、外设、高级分析覆盖率等） |
| `export_results` | `output_dir`（输出目录） | - | 导出分析结果为JSON文件（函数、MMIO、外设、高级分析结果） |

#### 2. StaticAnalysisResult（分析结果容器）
结构化存储所有分析结果，核心字段：
| 字段 | 类型 | 说明 |
|------|------|------|
| `arch_info` | `ArchInfo` | 固件架构信息（架构、字节序、位宽） |
| `functions` | `Dict[int, Function]` | 识别的函数（key：起始地址，value：Function对象） |
| `mmio_accesses` | `List[MMIOAccess]` | MMIO访问记录（地址、操作类型、指令等） |
| `peripherals` | `List[IdentifiedPeripheral]` | 恢复的外设符号（类型、基地址、置信度等） |
| `total_instructions` | `int` | 反汇编总指令数 |
| `total_basic_blocks` | `int` | 总基本块数（所有函数基本块之和） |
| `resolved_mmio_addresses` | `Dict[int, int]` | 高级分析解析的MMIO地址映射 |
| `dataflow_coverage` | `float` | 数据流分析对MMIO的覆盖率 |
| `symbolic_coverage` | `float` | 符号执行对MMIO的覆盖率 |

### 3.2 分析组件：analysis/ 子模块
| 子模块/文件 | 核心功能 | 依赖 |
|-------------|----------|------|
| `file_parser/` | ELF/BIN 格式解析、架构信息（ArchInfo）提取 | pyelftools（ELF）、二进制文件操作 |
| `disasm/` | 基于capstone的通用反汇编器（UniversalDisassembler） | capstone |
| `mmio_analyzer/` | 扫描反汇编指令，识别MMIO读/写操作（MMIOPatternAnalyzer） | capstone指令解析 |
| `control_flow/` | 分析指令流，提取函数、基本块、调用关系（ControlFlowAnalyzer） | 反汇编指令序列 |
| `symbol_recovery/` | 结合MMIO访问和函数信息，恢复外设符号（SymbolRecovery） | MMIOAccess、Function对象 |
| `dataflow/` | 数据流分析，解析MMIO地址依赖（DataFlowAnalyzer） | 控制流分析结果 |
| `symbolic/` | 混合分析（数据流+angr符号执行），提升MMIO解析覆盖率（HybridAnalyzer） | angr（可选）、dataflow模块 |
| `dynamic_mmio_monitor.py` | 动态监控MMIO访问（补充静态分析） | - |
| `test_dynamic_monitor.py` | 动态MMIO监控工具的测试用例 | - |

### 3.3 辅助工具：tools/ 目录
| 工具文件 | 功能 |
|----------|------|
| `export_static_analysis.py` | 批量导出多个固件的静态分析结果、格式化输出、结果对比 | static_analyzer模块 |

## 四、快速开始
### 4.1 依赖安装
```bash
# 基础依赖
pip install capstone pyelftools logging dataclasses-json

# 高级分析依赖（符号执行，可选）
pip install angr
```

### 4.2 基础使用示例
```python
import logging
from FirmGFuzz.static_analyzer import StaticAnalyzer

# 配置日志（查看分析过程）
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 1. 初始化分析器（指定固件路径，启用高级分析）
analyzer = StaticAnalyzer(
    firmware_path="./target_firmware.bin",  # 支持ELF/BIN格式
    enable_advanced=True  # 启用数据流+符号执行（需安装angr）
)

# 2. 执行全流程分析（最大反汇编指令数限制为10000）
analysis_result = analyzer.analyze(max_instructions=10000)

# 3. 打印分析摘要（控制台输出关键信息）
analyzer.print_summary()

# 4. 导出分析结果到指定目录（生成JSON文件）
analyzer.export_results(output_dir="./firmware_analysis_results")
```

## 五、核心分析流程
`StaticAnalyzer.analyze()` 方法按以下6个步骤执行全流程分析，与代码逻辑完全对齐：

### 步骤1：固件架构解析
- 优先尝试 ELF 格式解析（`ELFParser`），失败则降级为 BIN 格式启发式解析（`BINParser`）；
- 输出：架构（ARM/MIPS等）、字节序（大/小端）、位宽（32/64位）。

### 步骤2：反汇编
- 通过 `UniversalDisassembler` 读取固件代码（BIN 格式默认从 `0x01010c` 偏移读取100KB，ELF 从.text段读取）；
- 限制最大指令数（`max_instructions`），避免分析耗时过长；
- 输出：反汇编指令列表。

### 步骤3：MMIO 访问分析
- `MMIOPatternAnalyzer` 扫描指令，识别 MMIO 读/写操作；
- 统计：总MMIO访问数、读操作数、写操作数。

### 步骤4：控制流分析
- `ControlFlowAnalyzer` 分析指令流，提取函数（起始/结束地址、大小、是否叶子函数）、基本块、调用关系；
- 输出：函数字典（key=起始地址）、总基本块数。

### 步骤5：符号恢复
- `SymbolRecovery` 结合 MMIO 访问和函数信息，匹配外设类型、基地址、寄存器；
- 输出：识别的外设列表（含置信度）。

### 步骤6：高级分析（可选）
- 仅 `enable_advanced=True` 时执行，初始化 `HybridAnalyzer`；
- 结合 `DataFlowAnalyzer`（数据流）和 angr（符号执行）解析 MMIO 地址；
- 计算：数据流覆盖率、符号执行覆盖率（基于总MMIO访问数）。

## 六、结果导出说明
执行 `export_results(output_dir)` 后，输出目录会生成以下 JSON 文件（无高级分析结果时，advanced_analysis.json 不生成）：

| 文件 | 内容说明 |
|------|----------|
| `functions.json` | 函数信息（起始/结束地址、大小、是否叶子函数、调用目标） |
| `mmio_accesses.json` | MMIO访问记录（地址、操作模式、指令、读/写标记、目标地址） |
| `peripherals.json` | 外设信息（类型、基地址、置信度、访问的寄存器） |
| `advanced_analysis.json` | 高级分析结果（解析的MMIO地址、数据流/符号执行覆盖率） |

## 七、注意事项
1. **BIN 固件解析**：BIN 格式无结构化信息，反汇编默认从 `0x01010c` 偏移读取100KB代码，需根据实际固件调整 `static_analyzer.py` 中 `_disassemble` 方法的 `f.seek(0x01010c)` 和 `f.read(100000)` 参数；
2. **符号执行依赖**：高级分析需安装 angr，未安装时 `ANGR_AVAILABLE=False`，仅执行数据流分析；
3. **指令数限制**：`max_instructions` 建议根据固件大小调整（默认10000），过大会导致分析耗时过长，过小会丢失关键代码；
4. **架构支持**：当前支持常见嵌入式架构（ARM/MIPS等），需确保 `ArchInfo` 枚举包含目标架构；
5. **动态补充**：静态分析存在局限性，可结合 `analysis/dynamic_mmio_monitor.py` 动态监控MMIO访问，补充分析结果。

## 八、扩展开发
### 8.1 新增架构支持
修改 `analysis/file_parser/` 下的 `ArchInfo` 枚举，扩展 `UniversalDisassembler` 对新架构的反汇编适配。

### 8.2 扩展MMIO分析规则
修改 `analysis/mmio_analyzer/` 下的 `MMIOPatternAnalyzer`，新增MMIO访问模式识别规则。

### 8.3 自定义结果导出
基于 `static_analyzer.py` 的 `export_results` 方法，扩展支持CSV/Excel格式，或集成到FirmGFuzz的模糊测试流程中。

### 8.4 动态+静态分析融合
结合 `analysis/dynamic_mmio_monitor.py` 的动态结果，补充 `StaticAnalysisResult` 的MMIO解析覆盖率。
