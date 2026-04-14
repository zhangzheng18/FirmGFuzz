#!/usr/bin/env python3
"""
静态分析集成模块

将ELF解析、反汇编、MMIO分析、控制流分析、符号恢复集成到一起
"""

import sys
import os
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analysis'))

from analysis.file_parser import ELFParser, BINParser, ArchInfo
from analysis.disasm import UniversalDisassembler
from analysis.mmio_analyzer import MMIOPatternAnalyzer, MMIOAccess
from analysis.control_flow import ControlFlowAnalyzer, Function
from analysis.symbol_recovery import SymbolRecovery, IdentifiedPeripheral
from analysis.dataflow import DataFlowAnalyzer  # 新增
from analysis.symbolic import HybridAnalyzer, ANGR_AVAILABLE  # 新增

logger = logging.getLogger(__name__)


@dataclass
class StaticAnalysisResult:
    """静态分析结果"""
    arch_info: ArchInfo
    functions: Dict[int, Function]
    mmio_accesses: List[MMIOAccess]
    peripherals: List[IdentifiedPeripheral]

    # 统计信息
    total_instructions: int = 0
    total_basic_blocks: int = 0

    # 新增：高级分析结果
    resolved_mmio_addresses: Dict[int, int] = field(default_factory=dict)  # 数据流/符号执行解析的地址
    dataflow_coverage: float = 0.0  # 数据流分析覆盖率
    symbolic_coverage: float = 0.0  # 符号执行覆盖率


class StaticAnalyzer:
    """静态分析器 - 集成所有静态分析功能"""

    def __init__(self, firmware_path: str, enable_advanced: bool = False):
        """
        初始化静态分析器

        Args:
            firmware_path: 固件文件路径
            enable_advanced: 是否启用高级分析（数据流+符号执行）
        """
        self.firmware_path = firmware_path
        self.enable_advanced = enable_advanced
        self.result: Optional[StaticAnalysisResult] = None

    def analyze(self, max_instructions: int = 10000) -> StaticAnalysisResult:
        """
        执行完整的静态分析

        Args:
            max_instructions: 最大反汇编指令数

        Returns:
            StaticAnalysisResult对象
        """
        logger.info("\n" + "=" * 80)
        logger.info("开始静态分析")
        logger.info("=" * 80)

        # 步骤1: 解析文件格式和架构
        logger.info("\n[步骤1] 解析文件格式和架构")
        arch_info = self._parse_architecture()
        logger.info(f"  架构: {arch_info.architecture.value}")
        logger.info(f"  字节序: {arch_info.endianness.value}")
        logger.info(f"  位宽: {arch_info.bits}位")

        # 步骤2: 反汇编
        logger.info("\n[步骤2] 反汇编代码")
        instructions = self._disassemble(arch_info, max_instructions)
        logger.info(f"  反汇编了 {len(instructions)} 条指令")

        # 步骤3: MMIO访问分析
        logger.info("\n[步骤3] MMIO访问模式分析")
        mmio_accesses = self._analyze_mmio(arch_info, instructions)
        logger.info(f"  识别了 {len(mmio_accesses)} 个MMIO访问")

        # 步骤4: 控制流分析
        logger.info("\n[步骤4] 控制流分析")
        functions = self._analyze_control_flow(arch_info, instructions)
        logger.info(f"  识别了 {len(functions)} 个函数")

        # 步骤5: 符号恢复
        logger.info("\n[步骤5] 符号恢复")
        peripherals = self._recover_symbols(arch_info, mmio_accesses, functions)
        logger.info(f"  识别了 {len(peripherals)} 个外设")

        # 步骤6: 高级分析（可选）
        resolved_mmio = {}
        dataflow_cov = 0.0
        symbolic_cov = 0.0

        if self.enable_advanced:
            logger.info("\n[步骤6] 高级分析（数据流+符号执行）")
            try:
                hybrid = HybridAnalyzer(self.firmware_path)
                resolved_mmio = hybrid.analyze(
                    instructions,
                    functions,
                    use_symbolic=ANGR_AVAILABLE
                )

                # 计算覆盖率
                total_mmio = len(mmio_accesses)
                if total_mmio > 0:
                    dataflow_cov = len(hybrid.dataflow_results) / total_mmio
                    symbolic_cov = len(hybrid.symbolic_results) / total_mmio

                logger.info(f"  数据流覆盖率: {dataflow_cov:.2%}")
                logger.info(f"  符号执行覆盖率: {symbolic_cov:.2%}")
            except Exception as e:
                logger.warning(f"  高级分析失败: {e}")

        # 创建结果
        self.result = StaticAnalysisResult(
            arch_info=arch_info,
            functions=functions,
            mmio_accesses=mmio_accesses,
            peripherals=peripherals,
            total_instructions=len(instructions),
            total_basic_blocks=sum(len(f.basic_blocks) for f in functions.values()),
            resolved_mmio_addresses=resolved_mmio,
            dataflow_coverage=dataflow_cov,
            symbolic_coverage=symbolic_cov
        )

        logger.info("\n" + "=" * 80)
        logger.info("静态分析完成")
        logger.info("=" * 80)

        return self.result

    def _parse_architecture(self) -> ArchInfo:
        """解析架构"""
        # 尝试ELF解析
        try:
            parser = ELFParser(self.firmware_path)
            if parser.is_elf():
                return parser.parse()
        except Exception as e:
            logger.debug(f"ELF解析失败: {e}")

        # 尝试BIN解析（启发式）
        try:
            parser = BINParser(self.firmware_path)
            return parser.parse_heuristic()
        except Exception as e:
            logger.error(f"BIN解析失败: {e}")
            raise

    def _disassemble(self, arch_info: ArchInfo, max_instructions: int) -> List:
        """反汇编"""
        disasm = UniversalDisassembler(arch_info)

        # 读取代码
        with open(self.firmware_path, 'rb') as f:
            # 对于ELF，从.text段开始
            # 简化：从0x1000开始读取
            f.seek(0x01010c)  # 根据实际情况调整
            code = f.read(100000)  # 读取100KB

        # 反汇编
        instructions = []
        for insn in disasm.disassemble(code, 0x0800010c):
            instructions.append(insn)
            if max_instructions is not None and len(instructions) >= max_instructions:
                break

        return instructions

    def _analyze_mmio(self, arch_info: ArchInfo, instructions: List) -> List[MMIOAccess]:
        """MMIO分析"""
        analyzer = MMIOPatternAnalyzer(arch_info)
        return analyzer.analyze_instructions(instructions)

    def _analyze_control_flow(self, arch_info: ArchInfo, instructions: List) -> Dict:
        """控制流分析"""
        analyzer = ControlFlowAnalyzer(arch_info)
        return analyzer.analyze(instructions)

    def _recover_symbols(self, arch_info: ArchInfo, mmio_accesses: List,
                        functions: Dict) -> List[IdentifiedPeripheral]:
        """符号恢复"""
        recovery = SymbolRecovery(arch_info)
        return recovery.analyze(mmio_accesses, functions)

    def print_summary(self):
        """打印分析摘要"""
        if not self.result:
            logger.warning("尚未执行分析")
            return

        logger.info("\n" + "=" * 80)
        logger.info("静态分析摘要")
        logger.info("=" * 80)

        r = self.result

        logger.info(f"\n[架构信息]")
        logger.info(f"  架构: {r.arch_info.architecture.value}")
        logger.info(f"  字节序: {r.arch_info.endianness.value}")
        logger.info(f"  位宽: {r.arch_info.bits}位")

        logger.info(f"\n[代码统计]")
        logger.info(f"  总指令数: {r.total_instructions}")
        logger.info(f"  函数数: {len(r.functions)}")
        logger.info(f"  基本块数: {r.total_basic_blocks}")

        logger.info(f"\n[MMIO访问]")
        logger.info(f"  总访问数: {len(r.mmio_accesses)}")
        read_count = sum(1 for a in r.mmio_accesses if a.is_read)
        write_count = sum(1 for a in r.mmio_accesses if a.is_write)
        logger.info(f"  读操作: {read_count}")
        logger.info(f"  写操作: {write_count}")

        logger.info(f"\n[识别的外设]")
        logger.info(f"  总数: {len(r.peripherals)}")
        for periph in r.peripherals:
            logger.info(f"    - {periph.peripheral_type} @ 0x{periph.base_addr:08x} "
                       f"(置信度: {periph.confidence:.2%})")

        # 新增：高级分析结果
        if r.resolved_mmio_addresses:
            logger.info(f"\n[高级分析]")
            logger.info(f"  解析的MMIO地址: {len(r.resolved_mmio_addresses)}")
            logger.info(f"  数据流覆盖率: {r.dataflow_coverage:.2%}")
            logger.info(f"  符号执行覆盖率: {r.symbolic_coverage:.2%}")

        logger.info("\n" + "=" * 80)

    def export_results(self, output_dir: str):
        """导出分析结果"""
        import json
        import os

        if not self.result:
            logger.warning("尚未执行分析")
            return

        os.makedirs(output_dir, exist_ok=True)

        # 导出函数列表
        functions_data = {
            hex(addr): {
                'start': hex(func.start_addr),
                'end': hex(func.end_addr) if func.end_addr else None,
                'size': func.size,
                'is_leaf': func.is_leaf,
                'calls_to': [hex(c) for c in func.calls_to],
            }
            for addr, func in self.result.functions.items()
        }

        with open(os.path.join(output_dir, 'functions.json'), 'w') as f:
            json.dump(functions_data, f, indent=2)

        # 导出MMIO访问
        mmio_data = [
            {
                'address': hex(access.address),
                'pattern': access.pattern.value,
                'instruction': access.instruction,
                'is_read': access.is_read,
                'is_write': access.is_write,
                'target_addr': hex(access.target_addr) if access.target_addr else None,
            }
            for access in self.result.mmio_accesses
        ]

        with open(os.path.join(output_dir, 'mmio_accesses.json'), 'w') as f:
            json.dump(mmio_data, f, indent=2)

        # 导出外设信息
        peripherals_data = [
            {
                'type': p.peripheral_type,
                'base_addr': hex(p.base_addr),
                'confidence': p.confidence,
                'registers': {hex(k): v for k, v in p.accessed_registers.items()},
            }
            for p in self.result.peripherals
        ]

        with open(os.path.join(output_dir, 'peripherals.json'), 'w') as f:
            json.dump(peripherals_data, f, indent=2)

        # 导出高级分析结果（新增）
        if self.result.resolved_mmio_addresses:
            advanced_data = {
                'resolved_addresses': {
                    hex(k): hex(v) for k, v in self.result.resolved_mmio_addresses.items()
                },
                'dataflow_coverage': self.result.dataflow_coverage,
                'symbolic_coverage': self.result.symbolic_coverage,
            }

            with open(os.path.join(output_dir, 'advanced_analysis.json'), 'w') as f:
                json.dump(advanced_data, f, indent=2)

        logger.info(f"分析结果已导出到 {output_dir}")
