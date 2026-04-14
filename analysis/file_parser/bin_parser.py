#!/usr/bin/env python3
"""
BIN文件解析器

对于没有ELF头的原始二进制文件，使用启发式方法识别架构
"""

import logging
from pathlib import Path
from typing import Optional

from .architecture import Architecture, Endianness, ArchInfo

logger = logging.getLogger(__name__)


class BINParser:
    """BIN文件解析器"""

    def __init__(self, file_path: str):
        """
        初始化BIN解析器

        Args:
            file_path: BIN文件路径
        """
        self.file_path = Path(file_path)
        self.arch_info: Optional[ArchInfo] = None

        if not self.file_path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")

    def parse_with_hint(self,
                       architecture: Architecture,
                       endianness: Endianness = Endianness.LITTLE,
                       bits: int = 32) -> ArchInfo:
        """
        使用提示信息解析BIN文件

        Args:
            architecture: 架构类型
            endianness: 字节序
            bits: 位宽

        Returns:
            ArchInfo对象
        """
        self.arch_info = ArchInfo(
            architecture=architecture,
            endianness=endianness,
            bits=bits,
            machine_type='Binary (user specified)'
        )

        logger.info(f"BIN文件解析（用户指定）: {self.file_path.name}")
        logger.info(f"  架构: {architecture.value}")
        logger.info(f"  字节序: {endianness.value}")
        logger.info(f"  位宽: {bits}位")

        return self.arch_info

    def parse_heuristic(self) -> ArchInfo:
        """
        使用启发式方法识别架构

        基于常见的指令模式识别架构

        Returns:
            ArchInfo对象
        """
        with open(self.file_path, 'rb') as f:
            data = f.read(1024)  # 读取前1KB用于分析

        # 启发式规则
        architecture = Architecture.UNKNOWN
        endianness = Endianness.LITTLE
        bits = 32

        # ARM Thumb指令特征检测
        if self._is_arm_thumb(data):
            architecture = Architecture.ARM
            endianness = Endianness.LITTLE
            bits = 32
            logger.info("启发式识别: ARM Thumb")

        # ARM指令特征检测
        elif self._is_arm(data):
            architecture = Architecture.ARM
            endianness = Endianness.LITTLE
            bits = 32
            logger.info("启发式识别: ARM")

        # MIPS指令特征检测
        elif self._is_mips(data):
            architecture = Architecture.MIPS
            # MIPS可能是大端或小端，需要进一步检测
            endianness = self._detect_mips_endianness(data)
            bits = 32
            logger.info(f"启发式识别: MIPS ({endianness.value})")

        # x86指令特征检测
        elif self._is_x86(data):
            architecture = Architecture.X86
            endianness = Endianness.LITTLE
            bits = 32
            logger.info("启发式识别: x86")

        else:
            logger.warning("无法通过启发式方法识别架构")

        self.arch_info = ArchInfo(
            architecture=architecture,
            endianness=endianness,
            bits=bits,
            machine_type='Binary (heuristic)'
        )

        return self.arch_info

    def _is_arm_thumb(self, data: bytes) -> bool:
        """检测是否是ARM Thumb指令"""
        # Thumb指令特征：
        # - 16位指令
        # - 常见的push/pop模式
        # - 分支指令模式

        if len(data) < 4:
            return False

        # 检查常见的Thumb指令模式
        # push {r4-r7, lr} = 0xb5f0
        # pop {r4-r7, pc} = 0xbdf0
        thumb_patterns = [
            b'\xf0\xb5',  # push {r4-r7, lr}
            b'\xf0\xbd',  # pop {r4-r7, pc}
            b'\x00\xb5',  # push {lr}
            b'\x00\xbd',  # pop {pc}
        ]

        for pattern in thumb_patterns:
            if pattern in data[:100]:
                return True

        return False

    def _is_arm(self, data: bytes) -> bool:
        """检测是否是ARM指令"""
        # ARM指令特征：
        # - 32位指令
        # - 条件码在高4位
        # - 常见的指令模式

        if len(data) < 4:
            return False

        # 检查是否有ARM条件码模式
        # ARM指令的高4位通常是条件码 (0xE = always)
        count = 0
        for i in range(0, min(len(data) - 3, 100), 4):
            word = int.from_bytes(data[i:i+4], 'little')
            cond = (word >> 28) & 0xF
            # 常见的条件码: 0xE (AL), 0x0 (EQ), 0x1 (NE), etc.
            if cond in [0x0, 0x1, 0xE]:
                count += 1

        # 如果超过50%的指令有有效条件码，可能是ARM
        return count > 10

    def _is_mips(self, data: bytes) -> bool:
        """检测是否是MIPS指令"""
        # MIPS指令特征：
        # - 32位指令
        # - 常见的操作码模式

        if len(data) < 4:
            return False

        # 检查MIPS常见指令
        # addiu, lw, sw等
        mips_opcodes = [0x24, 0x8C, 0xAC, 0x27]  # addiu, lw, sw, addiu

        count = 0
        for i in range(0, min(len(data) - 3, 100), 4):
            word = int.from_bytes(data[i:i+4], 'big')
            opcode = (word >> 26) & 0x3F
            if opcode in mips_opcodes:
                count += 1

        return count > 5

    def _detect_mips_endianness(self, data: bytes) -> Endianness:
        """检测MIPS的字节序"""
        # 尝试两种字节序解析，看哪种更合理
        # 这是一个简化的实现
        return Endianness.LITTLE  # 默认小端

    def _is_x86(self, data: bytes) -> bool:
        """检测是否是x86指令"""
        # x86指令特征：
        # - 变长指令
        # - 常见的指令前缀和操作码

        if len(data) < 4:
            return False

        # 检查常见的x86指令
        # push ebp = 0x55
        # mov ebp, esp = 0x89 0xe5
        # ret = 0xc3
        x86_patterns = [
            b'\x55',        # push ebp
            b'\x89\xe5',    # mov ebp, esp
            b'\xc3',        # ret
            b'\x90',        # nop
        ]

        for pattern in x86_patterns:
            if pattern in data[:100]:
                return True

        return False
