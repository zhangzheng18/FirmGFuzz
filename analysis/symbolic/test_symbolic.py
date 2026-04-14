#!/usr/bin/env python3
"""
符号执行测试
"""

import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser import ELFParser
from disasm import UniversalDisassembler
from control_flow import ControlFlowAnalyzer
from symbolic import SymbolicExecutor, SymbolicExecutionConfig, HybridAnalyzer, ANGR_AVAILABLE

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_symbolic_execution():
    """测试符号执行"""
    if not ANGR_AVAILABLE:
        logger.warning("angr不可用，跳过符号执行测试")
        return

    logger.info("\n" + "=" * 80)
    logger.info("测试: 符号执行")
    logger.info("=" * 80)

    elf_path = '/home/zhangzheng/MCUdatabase/uEmu-real_world_firmware-pre-publication/P2IM.Gateway.elf'

    # 配置：保守参数
    config = SymbolicExecutionConfig(
        max_paths=20,
        max_depth=20,
        max_steps=1000,
        timeout=10,
        exploration_technique='dfs'
    )

    # 创建符号执行器
    executor = SymbolicExecutor(elf_path, config)

    if not executor.load_binary():
        logger.error("加载失败")
        return

    # 分析入口函数
    entry_addr = 0x0800010c
    resolved = executor.analyze_function(entry_addr)

    # 打印摘要
    executor.print_summary()

    logger.info("✓ 测试通过")


def test_hybrid_analysis():
    """测试混合分析"""
    logger.info("\n" + "=" * 80)
    logger.info("测试: 混合分析")
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
            if len(instructions) >= 1000:
                break

        logger.info(f"反汇编了 {len(instructions)} 条指令")

        # 控制流分析
        cfg_analyzer = ControlFlowAnalyzer(arch_info)
        functions = cfg_analyzer.analyze(instructions)
        logger.info(f"识别了 {len(functions)} 个函数")

        # 混合分析
        hybrid = HybridAnalyzer(elf_path)
        all_resolved = hybrid.analyze(
            instructions,
            functions,
            use_symbolic=ANGR_AVAILABLE
        )

        logger.info(f"\n最终解析了 {len(all_resolved)} 个MMIO地址")

    logger.info("✓ 测试通过")


def main():
    """运行所有测试"""
    logger.info("\n" + "#" * 80)
    logger.info("# 符号执行测试")
    logger.info("#" * 80)

    try:
        test_symbolic_execution()
        test_hybrid_analysis()
    except Exception as e:
        logger.error(f"测试失败: {e}")
        import traceback
        traceback.print_exc()

    logger.info("\n" + "#" * 80)
    logger.info("# 测试完成")
    logger.info("#" * 80)


if __name__ == '__main__':
    main()
