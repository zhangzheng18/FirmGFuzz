#!/usr/bin/env python3
"""
文件解析器测试
"""

import sys
import os
import logging
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser.architecture import Architecture, Endianness
from file_parser.elf_parser import ELFParser
from file_parser.bin_parser import BINParser

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_elf_parser():
    """测试ELF解析器"""
    logger.info("\n" + "=" * 80)
    logger.info("测试ELF解析器")
    logger.info("=" * 80)

    # 查找测试文件
    test_files = [
        '/home/zhangzheng/MCUdatabase/uEmu-real_world_firmware-pre-publication/P2IM.Gateway.elf',
        '/home/zhangzheng/MCUdatabase/uEmu-real_world_firmware-pre-publication/Console.elf',
    ]

    for test_file in test_files:
        if not Path(test_file).exists():
            logger.warning(f"测试文件不存在: {test_file}")
            continue

        logger.info(f"\n测试文件: {test_file}")
        logger.info("-" * 80)

        try:
            parser = ELFParser(test_file)

            # 检查是否是ELF
            if not parser.is_elf():
                logger.error("不是ELF文件")
                continue

            # 解析
            arch_info = parser.parse()

            # 打印信息
            logger.info("\n架构信息:")
            logger.info(str(arch_info))

            # 打印ELF头
            logger.info("")
            parser.print_header()

            logger.info("✓ 测试通过")

        except Exception as e:
            logger.error(f"✗ 测试失败: {e}")
            import traceback
            traceback.print_exc()


def test_bin_parser():
    """测试BIN解析器"""
    logger.info("\n" + "=" * 80)
    logger.info("测试BIN解析器")
    logger.info("=" * 80)

    # 测试用户指定模式
    logger.info("\n测试1: 用户指定架构")
    logger.info("-" * 80)

    # 创建一个临时测试文件
    test_file = '/tmp/test.bin'
    with open(test_file, 'wb') as f:
        f.write(b'\x00' * 1024)

    try:
        parser = BINParser(test_file)
        arch_info = parser.parse_with_hint(
            architecture=Architecture.ARM,
            endianness=Endianness.LITTLE,
            bits=32
        )

        logger.info("\n架构信息:")
        logger.info(str(arch_info))
        logger.info("✓ 测试通过")

    except Exception as e:
        logger.error(f"✗ 测试失败: {e}")

    # 测试启发式识别
    logger.info("\n测试2: 启发式识别")
    logger.info("-" * 80)

    # 创建一个包含ARM Thumb指令的测试文件
    test_file = '/tmp/test_thumb.bin'
    with open(test_file, 'wb') as f:
        # push {r4-r7, lr}
        f.write(b'\xf0\xb5')
        # 一些填充
        f.write(b'\x00' * 100)
        # pop {r4-r7, pc}
        f.write(b'\xf0\xbd')

    try:
        parser = BINParser(test_file)
        arch_info = parser.parse_heuristic()

        logger.info("\n架构信息:")
        logger.info(str(arch_info))

        if arch_info.architecture == Architecture.ARM:
            logger.info("✓ 正确识别为ARM")
        else:
            logger.warning(f"识别为: {arch_info.architecture.value}")

    except Exception as e:
        logger.error(f"✗ 测试失败: {e}")


def main():
    """运行所有测试"""
    logger.info("\n" + "#" * 80)
    logger.info("# 文件解析器测试套件")
    logger.info("#" * 80)

    test_elf_parser()
    test_bin_parser()

    logger.info("\n" + "#" * 80)
    logger.info("# 测试完成")
    logger.info("#" * 80)


if __name__ == '__main__':
    main()
