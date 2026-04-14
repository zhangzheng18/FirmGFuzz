#!/usr/bin/env python3
"""
反汇编器测试
"""

import sys
import os
import logging

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser import ELFParser, Architecture, Endianness, ArchInfo
from disasm import UniversalDisassembler

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_arm_disassembly():
    """测试ARM反汇编"""
    logger.info("\n" + "=" * 80)
    logger.info("测试1: ARM Thumb反汇编")
    logger.info("=" * 80)

    # ARM Thumb代码示例
    # push {r4-r7, lr}
    # mov r0, #0
    # pop {r4-r7, pc}
    code = bytes([
        0xf0, 0xb5,  # push {r4-r7, lr}
        0x00, 0x20,  # movs r0, #0
        0xf0, 0xbd,  # pop {r4-r7, pc}
    ])

    arch_info = ArchInfo(
        architecture=Architecture.ARM,
        endianness=Endianness.LITTLE,
        bits=32
    )

    disasm = UniversalDisassembler(arch_info)

    logger.info("\n反汇编结果:")
    for insn in disasm.disassemble(code, 0x08000000):
        logger.info(f"  {insn}")
        logger.info(f"    分支: {insn.is_branch()}, 调用: {insn.is_call()}, 返回: {insn.is_return()}")

    logger.info("✓ 测试通过")


def test_x86_disassembly():
    """测试x86反汇编"""
    logger.info("\n" + "=" * 80)
    logger.info("测试2: x86反汇编")
    logger.info("=" * 80)

    # x86代码示例
    # push ebp
    # mov ebp, esp
    # pop ebp
    # ret
    code = bytes([
        0x55,        # push ebp
        0x89, 0xe5,  # mov ebp, esp
        0x5d,        # pop ebp
        0xc3,        # ret
    ])

    arch_info = ArchInfo(
        architecture=Architecture.X86,
        endianness=Endianness.LITTLE,
        bits=32
    )

    disasm = UniversalDisassembler(arch_info)

    logger.info("\n反汇编结果:")
    for insn in disasm.disassemble(code, 0x08000000):
        logger.info(f"  {insn}")

    logger.info("✓ 测试通过")


def test_mips_disassembly():
    """测试MIPS反汇编"""
    logger.info("\n" + "=" * 80)
    logger.info("测试3: MIPS反汇编")
    logger.info("=" * 80)

    # MIPS代码示例 (小端)
    # addiu $sp, $sp, -8
    # sw $ra, 4($sp)
    code = bytes([
        0xf8, 0xff, 0xbd, 0x27,  # addiu $sp, $sp, -8
        0x04, 0x00, 0xbf, 0xaf,  # sw $ra, 4($sp)
    ])

    arch_info = ArchInfo(
        architecture=Architecture.MIPS,
        endianness=Endianness.LITTLE,
        bits=32
    )

    disasm = UniversalDisassembler(arch_info)

    logger.info("\n反汇编结果:")
    for insn in disasm.disassemble(code, 0x00400000):
        logger.info(f"  {insn}")

    logger.info("✓ 测试通过")


def test_real_elf():
    """测试真实ELF文件反汇编"""
    logger.info("\n" + "=" * 80)
    logger.info("测试4: 真实ELF文件反汇编")
    logger.info("=" * 80)

    elf_path = '/home/zhangzheng/MCUdatabase/uEmu-real_world_firmware-pre-publication/P2IM.Gateway.elf'

    # 解析ELF
    parser = ELFParser(elf_path)
    if not parser.is_elf():
        logger.error("不是ELF文件")
        return

    arch_info = parser.parse()

    # 创建反汇编器
    disasm = UniversalDisassembler(arch_info)

    # 读取代码段
    with open(elf_path, 'rb') as f:
        # 跳过ELF头，读取一些代码
        f.seek(0x1000)
        code = f.read(100)

    logger.info(f"\n反汇编前10条指令:")
    count = 0
    for insn in disasm.disassemble(code, 0x08001000):
        logger.info(f"  {insn}")
        count += 1
        if count >= 10:
            break

    logger.info("✓ 测试通过")


def main():
    """运行所有测试"""
    logger.info("\n" + "#" * 80)
    logger.info("# 通用反汇编器测试")
    logger.info("#" * 80)

    try:
        test_arm_disassembly()
        test_x86_disassembly()
        test_mips_disassembly()
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
