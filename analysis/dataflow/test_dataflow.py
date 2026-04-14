#!/usr/bin/env python3
"""
数据流分析测试
"""

import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser import ELFParser
from disasm import UniversalDisassembler
from dataflow import DataFlowAnalyzer

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_dataflow():
    """测试数据流分析"""
    logger.info("\n" + "=" * 80)
    logger.info("测试: 数据流分析")
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
            if len(instructions) >= 1000:  # 只分析前1000条
                break

        logger.info(f"反汇编了 {len(instructions)} 条指令")

        # 数据流分析
        df_analyzer = DataFlowAnalyzer(instructions)
        resolved = df_analyzer.analyze()

        # 打印摘要
        df_analyzer.print_summary()

    logger.info("✓ 测试通过")


def main():
    """运行所有测试"""
    logger.info("\n" + "#" * 80)
    logger.info("# 数据流分析测试")
    logger.info("#" * 80)

    try:
        test_dataflow()
    except Exception as e:
        logger.error(f"测试失败: {e}")
        import traceback
        traceback.print_exc()

    logger.info("\n" + "#" * 80)
    logger.info("# 测试完成")
    logger.info("#" * 80)


if __name__ == '__main__':
    main()
