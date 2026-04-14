#!/usr/bin/env python3
"""
控制流分析测试
"""

import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser import ELFParser
from disasm import UniversalDisassembler
from control_flow import ControlFlowAnalyzer

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_control_flow():
    """测试控制流分析"""
    logger.info("\n" + "=" * 80)
    logger.info("测试: 控制流分析")
    logger.info("=" * 80)

    elf_path = '/home/zhangzheng/MCUdatabase/uEmu-real_world_firmware-pre-publication/P2IM.Gateway.elf'

    # 解析ELF
    parser = ELFParser(elf_path)
    if not parser.is_elf():
        logger.error("不是ELF文件")
        return

    arch_info = parser.parse()

    # 反汇编
    disasm = UniversalDisassembler(arch_info)

    # 读取代码段
    with open(elf_path, 'rb') as f:
        f.seek(0x01010c)
        code = f.read(50000)

        logger.info(f"\n从.text段开始反汇编")

        # 反汇编
        instructions = []
        for insn in disasm.disassemble(code, 0x0800010c):
            instructions.append(insn)
            if len(instructions) >= 5000:
                break

        logger.info(f"反汇编了 {len(instructions)} 条指令")

        # 控制流分析
        cfg_analyzer = ControlFlowAnalyzer(arch_info)
        functions = cfg_analyzer.analyze(instructions)

        logger.info(f"\n识别了 {len(functions)} 个函数")

        # 打印摘要
        cfg_analyzer.print_summary()

    logger.info("✓ 测试通过")


def main():
    """运行所有测试"""
    logger.info("\n" + "#" * 80)
    logger.info("# 控制流分析测试")
    logger.info("#" * 80)

    try:
        test_control_flow()
    except Exception as e:
        logger.error(f"测试失败: {e}")
        import traceback
        traceback.print_exc()

    logger.info("\n" + "#" * 80)
    logger.info("# 测试完成")
    logger.info("#" * 80)


if __name__ == '__main__':
    main()
