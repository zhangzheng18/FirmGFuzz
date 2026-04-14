#!/usr/bin/env python3
"""
架构定义和识别
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional


class Architecture(Enum):
    """支持的CPU架构枚举（与反汇编器完全兼容）"""
    ARM = 'ARM'
    ARM64 = 'ARM64'
    MIPS = 'MIPS'
    MIPS64 = 'MIPS64'
    PPC = 'PowerPC'        # 32位PowerPC
    PPC64 = 'PowerPC64'     # 64位PowerPC
    X86 = 'x86'             # 32位x86
    X86_64 = 'x86-64'       # 64位x86
    UNKNOWN = 'Unknown'


class Endianness(Enum):
    """字节序枚举"""
    LITTLE = 'Little Endian'
    BIG = 'Big Endian'
    UNKNOWN = 'Unknown'


@dataclass
class ArchInfo:
    """架构信息数据类"""
    architecture: Architecture
    endianness: Endianness
    bits: int  # 仅支持 32 / 64
    machine_type: str = 'Unknown'
    machine_code: int = 0

    def __str__(self):
        return (f"Architecture: {self.architecture.value}\n"
                f"Endianness: {self.endianness.value}\n"
                f"Bits: {self.bits}\n"
                f"Machine: {self.machine_type} (0x{self.machine_code:04x})")

    # 架构快速判断方法
    def is_arm(self) -> bool:
        return self.architecture in [Architecture.ARM, Architecture.ARM64]

    def is_mips(self) -> bool:
        return self.architecture in [Architecture.MIPS, Architecture.MIPS64]

    def is_x86(self) -> bool:
        return self.architecture in [Architecture.X86, Architecture.X86_64]

    def is_ppc(self) -> bool:
        return self.architecture in [Architecture.PPC, Architecture.PPC64]

    def is_64bit(self) -> bool:
        return self.bits == 64

    def is_little_endian(self) -> bool:
        return self.endianness == Endianness.LITTLE


# ELF e_machine 映射表（修复重复键，完善架构对应）
ELF_MACHINE_MAP = {
    0x00: ('None', Architecture.UNKNOWN),
    0x03: ('Intel 80386', Architecture.X86),
    0x08: ('MIPS', Architecture.MIPS),
    0x14: ('PowerPC 32bit', Architecture.PPC),
    0x15: ('PowerPC 64bit', Architecture.PPC64),
    0x28: ('ARM 32bit', Architecture.ARM),
    0x3E: ('AMD x86-64', Architecture.X86_64),
    0xB7: ('AArch64', Architecture.ARM64),
    0xF3: ('RISC-V', Architecture.UNKNOWN),
}


def identify_architecture_from_elf_machine(e_machine: int, ei_class: int) -> Architecture:
    """
    从ELF文件头识别CPU架构
    Args:
        e_machine: ELF 机器码字段
        ei_class: 1=32位, 2=64位
    Returns:
        架构枚举
    """
    if e_machine not in ELF_MACHINE_MAP:
        return Architecture.UNKNOWN

    _, arch = ELF_MACHINE_MAP[e_machine]

    # 自动升级为64位架构（根据ELF位宽）
    if arch == Architecture.MIPS and ei_class == 2:
        return Architecture.MIPS64
    if arch == Architecture.PPC and ei_class == 2:
        return Architecture.PPC64

    return arch


def get_machine_name(e_machine: int) -> str:
    """获取ELF机器类型名称"""
    if e_machine in ELF_MACHINE_MAP:
        return ELF_MACHINE_MAP[e_machine][0]
    return f'Unknown (0x{e_machine:04x})'