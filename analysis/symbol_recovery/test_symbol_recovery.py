#!/usr/bin/env python3
"""
符号恢复测试
"""

import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser import ELFParser
from disasm import UniversalDisassembler
from mmio_analyzer import MMIOPatternAnalyzer
from control_flow import ControlFlowAnalyzer
from symbol_recovery import SymbolRecovery

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_symbol_recovery():
    """测试符号恢复"""
    logger.info("\n" + "=" * 80)
    logger.info("测试: 符号恢复")
    logger.info("=" * 80)

    elf_path = '/home/zhangzheng/MCUdatabase/uEmu-real_world_firmware-pre-publication/P2IM.Gateway.elf'

    # 解析ELF
    parser = ELFParser(elf_path)
    arch_info = parser.parse()

    # 反汇编
    disasm = UniversalDisassembler(arch_info)

    with open(elf_path, 'rb') as f:
        f.seek(0x01010c)
        code = f.read(50000)

        instructions = []
        for insn in disasm.disassemble(code, 0x0800010c):
            instructions.append(insn)
            if len(instructions) >= 5000:
                break

        logger.info(f"反汇编了 {len(instructions)} 条指令")

        # MMIO分析
        mmio_analyzer = MMIOPatternAnalyzer(arch_info)
        mmio_accesses = mmio_analyzer.analyze_instructions(instructions)
        logger.info(f"识别了 {len(mmio_accesses)} 个MMIO访问")

        # 控制流分析
        cfg_analyzer = ControlFlowAnalyzer(arch_info)
        functions = cfg_analyzer.analyze(instructions)
        logger.info(f"识别了 {len(functions)} 个函数")

        # 符号恢复
        symbol_recovery = SymbolRecovery(arch_info)
        peripherals = symbol_recovery.analyze(mmio_accesses, functions)

        logger.info(f"\n识别了 {len(peripherals)} 个外设")

        # 打印报告
        symbol_recovery.print_report()

        # 导出符号
        symbol_recovery.export_symbols('/tmp/symbols.json')

    logger.info("✓ 测试通过")


def main():
    """运行所有测试"""
    logger.info("\n" + "#" * 80)
    logger.info("# 符号恢复测试")
    logger.info("#" * 80)

    try:
        test_symbol_recovery()
    except Exception as e:
        logger.error(f"测试失败: {e}")
        import traceback
        traceback.print_exc()

    logger.info("\n" + "#" * 80)
    logger.info("# 测试完成")
    logger.info("#" * 80)


if __name__ == '__main__':
    main()
