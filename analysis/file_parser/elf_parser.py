#!/usr/bin/env python3
"""
ELF文件解析器

支持解析ELF文件头，识别架构、大小端、位宽等信息
"""

import struct
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from .architecture import (
    Architecture, Endianness, ArchInfo,
    identify_architecture_from_elf_machine,
    get_machine_name
)

logger = logging.getLogger(__name__)


class ELFParser:
    """ELF文件解析器"""

    # ELF魔数
    ELF_MAGIC = b'\x7fELF'

    # ELF头偏移
    EI_CLASS = 4      # 文件类别 (32/64位)
    EI_DATA = 5       # 数据编码 (大小端)
    EI_VERSION = 6    # 文件版本
    EI_OSABI = 7      # OS/ABI标识

    # EI_CLASS值
    ELFCLASS32 = 1    # 32位
    ELFCLASS64 = 2    # 64位

    # EI_DATA值
    ELFDATA2LSB = 1   # 小端
    ELFDATA2MSB = 2   # 大端

    def __init__(self, file_path: str):
        """
        初始化ELF解析器

        Args:
            file_path: ELF文件路径
        """
        self.file_path = Path(file_path)
        self.elf_header: Optional[Dict[str, Any]] = None
        self.arch_info: Optional[ArchInfo] = None

        if not self.file_path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")

    def is_elf(self) -> bool:
        """检查是否是ELF文件"""
        try:
            with open(self.file_path, 'rb') as f:
                magic = f.read(4)
                return magic == self.ELF_MAGIC
        except Exception as e:
            logger.error(f"读取文件失败: {e}")
            return False

    def parse(self) -> ArchInfo:
        """
        解析ELF文件

        Returns:
            ArchInfo对象，包含架构信息
        """
        if not self.is_elf():
            raise ValueError(f"不是有效的ELF文件: {self.file_path}")

        with open(self.file_path, 'rb') as f:
            # 读取ELF标识（前16字节）
            e_ident = f.read(16)

            # 解析基本信息
            ei_class = e_ident[self.EI_CLASS]
            ei_data = e_ident[self.EI_DATA]
            ei_version = e_ident[self.EI_VERSION]
            ei_osabi = e_ident[self.EI_OSABI]

            # 确定位宽
            if ei_class == self.ELFCLASS32:
                bits = 32
                is_64bit = False
            elif ei_class == self.ELFCLASS64:
                bits = 64
                is_64bit = True
            else:
                raise ValueError(f"未知的ELF类别: {ei_class}")

            # 确定字节序
            if ei_data == self.ELFDATA2LSB:
                endianness = Endianness.LITTLE
                endian_char = '<'
            elif ei_data == self.ELFDATA2MSB:
                endianness = Endianness.BIG
                endian_char = '>'
            else:
                raise ValueError(f"未知的字节序: {ei_data}")

            # 根据位宽和字节序读取ELF头的其余部分
            if is_64bit:
                # 64位ELF头格式
                fmt = f'{endian_char}HHIQQQIHHHHHH'
                header_size = struct.calcsize(fmt)
                header_data = f.read(header_size)

                (e_type, e_machine, e_version,
                 e_entry, e_phoff, e_shoff,
                 e_flags, e_ehsize, e_phentsize, e_phnum,
                 e_shentsize, e_shnum, e_shstrndx) = struct.unpack(fmt, header_data)
            else:
                # 32位ELF头格式
                fmt = f'{endian_char}HHIIIIIHHHHHH'
                header_size = struct.calcsize(fmt)
                header_data = f.read(header_size)

                (e_type, e_machine, e_version,
                 e_entry, e_phoff, e_shoff,
                 e_flags, e_ehsize, e_phentsize, e_phnum,
                 e_shentsize, e_shnum, e_shstrndx) = struct.unpack(fmt, header_data)

            # 保存ELF头信息
            self.elf_header = {
                'ei_class': ei_class,
                'ei_data': ei_data,
                'ei_version': ei_version,
                'ei_osabi': ei_osabi,
                'e_type': e_type,
                'e_machine': e_machine,
                'e_version': e_version,
                'e_entry': e_entry,
                'e_phoff': e_phoff,
                'e_shoff': e_shoff,
                'e_flags': e_flags,
                'e_ehsize': e_ehsize,
                'e_phentsize': e_phentsize,
                'e_phnum': e_phnum,
                'e_shentsize': e_shentsize,
                'e_shnum': e_shnum,
                'e_shstrndx': e_shstrndx,
            }

            # 识别架构
            architecture = identify_architecture_from_elf_machine(e_machine, ei_class)
            machine_name = get_machine_name(e_machine)

            # 创建架构信息对象
            self.arch_info = ArchInfo(
                architecture=architecture,
                endianness=endianness,
                bits=bits,
                machine_type=machine_name,
                machine_code=e_machine
            )

            logger.info(f"ELF解析成功: {self.file_path.name}")
            logger.info(f"  架构: {architecture.value}")
            logger.info(f"  字节序: {endianness.value}")
            logger.info(f"  位宽: {bits}位")
            logger.info(f"  机器类型: {machine_name}")
            logger.info(f"  入口点: 0x{e_entry:08x}")

            return self.arch_info

    def get_entry_point(self) -> Optional[int]:
        """获取入口点地址"""
        if self.elf_header:
            return self.elf_header['e_entry']
        return None

    def get_sections(self) -> list:
        """获取节区信息（简化版）"""
        # TODO: 实现完整的节区解析
        return []

    def get_segments(self) -> list:
        """获取段信息（简化版）"""
        # TODO: 实现完整的段解析
        return []

    def print_header(self):
        """打印ELF头信息"""
        if not self.elf_header:
            print("ELF头未解析")
            return

        print("=" * 60)
        print("ELF头信息")
        print("=" * 60)

        h = self.elf_header

        print(f"类别:       {'64位' if h['ei_class'] == 2 else '32位'}")
        print(f"字节序:     {'小端' if h['ei_data'] == 1 else '大端'}")
        print(f"版本:       {h['ei_version']}")
        print(f"OS/ABI:     {h['ei_osabi']}")
        print(f"类型:       {h['e_type']}")
        print(f"机器:       0x{h['e_machine']:04x}")
        print(f"入口点:     0x{h['e_entry']:08x}")
        print(f"程序头偏移: 0x{h['e_phoff']:08x}")
        print(f"节头偏移:   0x{h['e_shoff']:08x}")
        print(f"标志:       0x{h['e_flags']:08x}")
        print(f"程序头数量: {h['e_phnum']}")
        print(f"节头数量:   {h['e_shnum']}")
        print("=" * 60)
