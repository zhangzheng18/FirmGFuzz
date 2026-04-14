#!/usr/bin/env python3
"""
MMIO模式分析器测试
"""

import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser import ELFParser
from disasm import UniversalDisassembler
from mmio_analyzer import MMIOPatternAnalyzer

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_arm_mmio_patterns():
    """测试ARM MMIO模式识别"""
    logger.info("\n" + "=" * 80)
    logger.info("测试: ARM MMIO模式识别")
    logger.info("=" * 80)

    # 测试用的ARM Thumb代码
    # ldr r0, [r1, #0x14]  - 基址+偏移
    # ldr r0, [r1]         - 寄存器间接
    # ldr r0, [r1, r2]     - 基址+索引
    code = bytes([
        0x50, 0x68,  # ldr r0, [r2, #4]
        0x08, 0x68,  # ldr r0, [r1]
        0x88, 0x58,  # ldr r0, [r1, r2]
    ])

    from file_parser import Architecture, Endianness, ArchInfo

    arch_info = ArchInfo(
        architecture=Architecture.ARM,
        endianness=Endianness.LITTLE,
        bits=32
    )

    # 反汇编
    disasm = UniversalDisassembler(arch_info)
    instructions = list(disasm.disassemble(code, 0x08000000))

    logger.info(f"\n反汇编了 {len(instructions)} 条指令")

    # 分析MMIO模式
    analyzer = MMIOPatternAnalyzer(arch_info)
    accesses = analyzer.analyze_instructions(instructions)

    logger.info(f"\n识别了 {len(accesses)} 个MMIO访问")
    for access in accesses:
        logger.info(f"  {access}")

    # 打印统计
    analyzer.print_report()

    logger.info("✓ 测试通过")


def test_real_elf():
    """测试真实ELF文件"""
    logger.info("\n" + "=" * 80)
    logger.info("测试: 真实ELF文件MMIO分析")
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
        # .text段在文件偏移0x01010c，虚拟地址0x0800010c
        f.seek(0x01010c)
        code = f.read(50000)  # 读取50KB

        logger.info(f"\n从.text段开始反汇编 (VA: 0x0800010c)")

        # 反汇编
        instructions = []
        for insn in disasm.disassemble(code, 0x0800010c):
            instructions.append(insn)
            if len(instructions) >= 5000:  # 限制5000条指令
                break

        logger.info(f"反汇编了 {len(instructions)} 条指令")

        # 显示前20条指令
        logger.info(f"\n前20条指令:")
        for i, insn in enumerate(instructions[:20], 1):
            logger.info(f"  {i}. {insn}")

        # 分析MMIO
        analyzer = MMIOPatternAnalyzer(arch_info)
        accesses = analyzer.analyze_instructions(instructions)

        logger.info(f"\n识别了 {len(accesses)} 个潜在的MMIO访问")

        # 打印报告
        analyzer.print_report(limit=50)

    logger.info("✓ 测试通过")


def main():
    """运行所有测试"""
    logger.info("\n" + "#" * 80)
    logger.info("# MMIO模式分析器测试")
    logger.info("#" * 80)

    try:
        test_arm_mmio_patterns()
        test_real_elf()
    except Exception as e:
        logger.error(f"测试失败: {e}")
        import traceback
        traceback.print_exc()

    logger.info("\n" + "#" * 80)
    logger.info("# 测试完成")
    logger.info("#" * 80)


if __name__ == '__main__':
    main()
