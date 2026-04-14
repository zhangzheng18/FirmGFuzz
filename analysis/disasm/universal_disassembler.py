#!/usr/bin/env python3
"""
通用反汇编器 - 支持多架构

基于Capstone，支持ARM/ARM64/MIPS/MIPS64/PPC/x86等架构
"""

import logging
from typing import List, Optional, Iterator, Any
from dataclasses import dataclass

import capstone
from capstone import Cs, CsInsn  # 移除 CsOp，兼容旧版

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser.architecture import Architecture, Endianness, ArchInfo

logger = logging.getLogger(__name__)


@dataclass
class Instruction:
    """指令信息"""
    address: int
    mnemonic: str
    op_str: str
    size: int
    bytes: bytes

    # Capstone详细信息
    groups: List[int]
    operands: List[Any]  # 替换 CsOp 为 Any，兼容所有版本

    def __str__(self):
        return f"0x{self.address:08x}: {self.mnemonic:8s} {self.op_str}"

    def is_branch(self) -> bool:
        """是否是分支指令"""
        try:
            return capstone.CS_GRP_JUMP in self.groups
        except:
            return False

    def is_call(self) -> bool:
        """是否是调用指令"""
        try:
            return capstone.CS_GRP_CALL in self.groups
        except:
            return False

    def is_return(self) -> bool:
        """是否是返回指令"""
        try:
            return capstone.CS_GRP_RET in self.groups
        except:
            return False

    def is_memory_access(self) -> bool:
        """是否访问内存"""
        for op in self.operands:
            if op.type == capstone.CS_OP_MEM:
                return True
        return False


class UniversalDisassembler:
    """通用反汇编器"""

    def __init__(self, arch_info: ArchInfo):
        """
        初始化反汇编器

        Args:
            arch_info: 架构信息
        """
        self.arch_info = arch_info
        self.cs: Optional[Cs] = None
        self._setup_capstone()

    def _setup_capstone(self):
        """设置Capstone反汇编器"""
        arch = self.arch_info.architecture
        endian = self.arch_info.endianness
        bits = self.arch_info.bits

        # 只用字符串匹配，彻底避开枚举坑
        arch_val = arch.value

        if arch_val == 'ARM':
            cs_arch = capstone.CS_ARCH_ARM
            cs_mode = capstone.CS_MODE_THUMB
            if endian == Endianness.BIG:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

        elif arch_val == 'ARM64':
            cs_arch = capstone.CS_ARCH_ARM64
            cs_mode = capstone.CS_MODE_ARM
            if endian == Endianness.BIG:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

        elif arch_val in ('MIPS', 'MIPS64'):
            cs_arch = capstone.CS_ARCH_MIPS
            cs_mode = capstone.CS_MODE_MIPS64 if bits == 64 else capstone.CS_MODE_MIPS32
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN if endian == Endianness.BIG else capstone.CS_MODE_LITTLE_ENDIAN

        elif arch_val in ('PowerPC', 'PowerPC64'):
            cs_arch = capstone.CS_ARCH_PPC
            cs_mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN if endian == Endianness.BIG else capstone.CS_MODE_LITTLE_ENDIAN

        elif arch_val == 'x86':
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_32

        elif arch_val == 'x86-64':
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64

        else:
            raise ValueError(f"不支持的架构: {arch_val}")

        self.cs = Cs(cs_arch, cs_mode)
        self.cs.detail = True

        logger.info(f"Capstone初始化: {arch.value}, {endian.value}, {bits}位")

    def disassemble(self, code: bytes, address: int = 0) -> Iterator[Instruction]:
        """
        反汇编代码

        Args:
            code: 二进制代码
            address: 起始地址

        Yields:
            Instruction对象
        """
        if not self.cs:
            raise RuntimeError("Capstone未初始化")

        try:
            for insn in self.cs.disasm(code, address):
                yield Instruction(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    size=insn.size,
                    bytes=insn.bytes,
                    groups=list(insn.groups) if hasattr(insn, 'groups') else [],
                    operands=list(insn.operands) if hasattr(insn, 'operands') else []
                )
        except capstone.CsError as e:
            logger.error(f"反汇编失败: {e}")

    def disassemble_one(self, code: bytes, address: int = 0) -> Optional[Instruction]:
        """
        反汇编单条指令

        Args:
            code: 二进制代码
            address: 起始地址

        Returns:
            Instruction对象，如果失败返回None
        """
        for insn in self.disassemble(code, address):
            return insn
        return None

    def disassemble_range(self, code: bytes, start: int, end: int) -> List[Instruction]:
        """
        反汇编指定范围的代码

        Args:
            code: 二进制代码
            start: 起始地址
            end: 结束地址

        Returns:
            Instruction列表
        """
        instructions = []
        for insn in self.disassemble(code, start):
            if insn.address >= end:
                break
            instructions.append(insn)
        return instructions

    def switch_to_arm_mode(self):
        """切换到ARM模式（仅ARM架构）"""
        if self.arch_info.architecture == Architecture.ARM:
            cs_mode = capstone.CS_MODE_ARM
            if self.arch_info.endianness == Endianness.BIG:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

            self.cs = Cs(capstone.CS_ARCH_ARM, cs_mode)
            self.cs.detail = True
            logger.info("切换到ARM模式")

    def switch_to_thumb_mode(self):
        """切换到Thumb模式（仅ARM架构）"""
        if self.arch_info.architecture == Architecture.ARM:
            cs_mode = capstone.CS_MODE_THUMB
            if self.arch_info.endianness == Endianness.BIG:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN
            else:
                cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

            self.cs = Cs(capstone.CS_ARCH_ARM, cs_mode)
            self.cs.detail = True
            logger.info("切换到Thumb模式")