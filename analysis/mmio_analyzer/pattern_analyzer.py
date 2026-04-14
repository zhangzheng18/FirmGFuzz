#!/usr/bin/env python3
"""
MMIO访问模式识别器

从反汇编的指令中识别10种MMIO访问模式
"""

import sys
import os
import logging
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

import capstone
import capstone.arm

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser.architecture import Architecture, ArchInfo
from disasm import Instruction

logger = logging.getLogger(__name__)


class AccessPattern(Enum):
    """MMIO访问模式"""
    BASE_OFFSET = 'base_offset'           # [r1, #0x14]
    REGISTER_INDIRECT = 'register_indirect'  # [r1]
    BASE_INDEX = 'base_index'             # [r1, r2]
    PRE_INDEXED = 'pre_indexed'           # [r1, #4]!
    POST_INDEXED = 'post_indexed'         # [r1], #4
    PC_RELATIVE = 'pc_relative'           # [pc, #offset]
    IMMEDIATE = 'immediate'               # 直接地址 (movw/movt)
    BIT_BAND = 'bit_band'                 # 位带寻址 (0x42000000-0x43FFFFFF)
    STACK_ACCESS = 'stack_access'         # [sp, #offset]
    DMA_CONFIG = 'dma_config'             # DMA配置寄存器访问
    UNKNOWN = 'unknown'


@dataclass
class MMIOAccess:
    """MMIO访问信息"""
    address: int                    # 指令地址
    pattern: AccessPattern          # 访问模式
    instruction: str                # 指令文本

    # 访问详情
    base_reg: Optional[str] = None  # 基址寄存器
    offset: Optional[int] = None    # 偏移量
    index_reg: Optional[str] = None # 索引寄存器
    target_addr: Optional[int] = None  # 目标地址（如果可计算）

    is_read: bool = True            # 是否是读操作
    is_write: bool = False          # 是否是写操作

    def __str__(self):
        access_type = 'R' if self.is_read else 'W'
        target = f" -> 0x{self.target_addr:08x}" if self.target_addr else ""
        return (f"0x{self.address:08x}: [{access_type}] {self.pattern.value:20s} "
                f"{self.instruction:30s}{target}")


class MMIOPatternAnalyzer:
    """MMIO访问模式分析器"""

    # 常见的MMIO地址范围（可配置）
    MMIO_RANGES = [
        (0x40000000, 0x60000000),  # ARM Cortex-M 外设
        (0x42000000, 0x44000000),  # ARM Cortex-M 位带区域
        (0x1F000000, 0x20000000),  # 其他MCU外设
        (0xE0000000, 0xE0100000),  # ARM Cortex-M 系统外设
        (0xA0000000, 0xC0000000),  # 其他外设区域
    ]

    # 位带区域定义
    BIT_BAND_REGION = (0x42000000, 0x44000000)
    BIT_BAND_ALIAS = (0x22000000, 0x24000000)

    def __init__(self, arch_info: ArchInfo):
        """
        初始化分析器

        Args:
            arch_info: 架构信息
        """
        self.arch_info = arch_info
        self.mmio_accesses: List[MMIOAccess] = []

    def analyze_instruction(self, insn: Instruction) -> Optional[MMIOAccess]:
        """
        分析单条指令，识别MMIO访问模式

        Args:
            insn: 指令对象

        Returns:
            MMIOAccess对象，如果不是MMIO访问则返回None
        """
        # 根据架构选择分析方法
        if self.arch_info.is_arm():
            return self._analyze_arm_instruction(insn)
        elif self.arch_info.is_mips():
            return self._analyze_mips_instruction(insn)
        elif self.arch_info.is_x86():
            return self._analyze_x86_instruction(insn)
        else:
            return None

    def _analyze_arm_instruction(self, insn: Instruction) -> Optional[MMIOAccess]:
        """分析ARM指令"""
        import capstone.arm as arm

        mnemonic = insn.mnemonic.lower()

        # 判断是读还是写
        is_read = mnemonic.startswith('ldr')
        is_write = mnemonic.startswith('str')

        if not (is_read or is_write):
            # 检查是否是movw/movt（立即数加载，可能用于MMIO地址）
            if mnemonic in ['movw', 'movt']:
                return self._analyze_arm_immediate_load(insn)
            return None

        # 分析操作数
        if not insn.operands or len(insn.operands) < 2:
            return None

        # 第二个操作数应该是内存操作数
        mem_op = None
        for op in insn.operands:
            if op.type == capstone.CS_OP_MEM:
                mem_op = op
                break

        if not mem_op:
            return None

        # 提取内存访问信息
        base_reg = self._get_reg_name(mem_op.mem.base)
        index_reg = self._get_reg_name(mem_op.mem.index) if mem_op.mem.index != 0 else None
        offset = mem_op.mem.disp

        # 检查是否是前/后索引模式
        # 通过检查指令字符串中的'!'和'],'来判断
        op_str = insn.op_str.lower()
        is_pre_indexed = ']!' in op_str
        is_post_indexed = '], #' in op_str or '], r' in op_str

        # 识别访问模式
        pattern = self._identify_arm_pattern(
            insn, base_reg, index_reg, offset,
            is_pre_indexed, is_post_indexed
        )

        # 尝试计算目标地址
        target_addr = self._calculate_target_address(insn, base_reg, offset)

        # 检查是否是位带访问
        if target_addr and self._is_bit_band_address(target_addr):
            pattern = AccessPattern.BIT_BAND

        access = MMIOAccess(
            address=insn.address,
            pattern=pattern,
            instruction=f"{insn.mnemonic} {insn.op_str}",
            base_reg=base_reg,
            offset=offset,
            index_reg=index_reg,
            target_addr=target_addr,
            is_read=is_read,
            is_write=is_write
        )

        return access

    def _analyze_arm_immediate_load(self, insn: Instruction) -> Optional[MMIOAccess]:
        """分析ARM立即数加载指令（movw/movt）"""
        # movw/movt通常用于构造32位地址
        # 这可能是MMIO地址的加载
        mnemonic = insn.mnemonic.lower()

        # 提取立即数
        if insn.operands and len(insn.operands) >= 2:
            if insn.operands[1].type == capstone.CS_OP_IMM:
                imm_value = insn.operands[1].imm

                # 检查是否在MMIO范围内
                if self.is_mmio_address(imm_value):
                    return MMIOAccess(
                        address=insn.address,
                        pattern=AccessPattern.IMMEDIATE,
                        instruction=f"{insn.mnemonic} {insn.op_str}",
                        target_addr=imm_value,
                        is_read=False,
                        is_write=False
                    )

        return None

    def _identify_arm_pattern(self, insn: Instruction, base_reg: str,
                             index_reg: Optional[str], offset: int,
                             is_pre_indexed: bool = False,
                             is_post_indexed: bool = False) -> AccessPattern:
        """识别ARM访问模式"""

        # 前索引模式 [r1, #4]!
        if is_pre_indexed:
            return AccessPattern.PRE_INDEXED

        # 后索引模式 [r1], #4
        if is_post_indexed:
            return AccessPattern.POST_INDEXED

        # PC相对寻址
        if base_reg == 'pc':
            return AccessPattern.PC_RELATIVE

        # 栈访问
        if base_reg == 'sp':
            return AccessPattern.STACK_ACCESS

        # 基址 + 索引
        if index_reg:
            return AccessPattern.BASE_INDEX

        # 基址 + 偏移
        if offset != 0:
            return AccessPattern.BASE_OFFSET

        # 寄存器间接
        return AccessPattern.REGISTER_INDIRECT

    def _analyze_mips_instruction(self, insn: Instruction) -> Optional[MMIOAccess]:
        """分析MIPS指令"""
        mnemonic = insn.mnemonic.lower()

        # MIPS的load/store指令
        is_read = mnemonic in ['lw', 'lh', 'lb', 'lwu', 'lhu', 'lbu']
        is_write = mnemonic in ['sw', 'sh', 'sb']

        if not (is_read or is_write):
            return None

        # MIPS格式: lw $t0, offset($base)
        # 需要解析op_str
        # 简化实现

        return MMIOAccess(
            address=insn.address,
            pattern=AccessPattern.BASE_OFFSET,
            instruction=f"{insn.mnemonic} {insn.op_str}",
            is_read=is_read,
            is_write=is_write
        )

    def _analyze_x86_instruction(self, insn: Instruction) -> Optional[MMIOAccess]:
        """分析x86指令"""
        mnemonic = insn.mnemonic.lower()

        # x86的内存访问指令
        is_read = mnemonic in ['mov', 'movzx', 'movsx'] and '[' in insn.op_str
        is_write = mnemonic in ['mov'] and '[' in insn.op_str

        if not (is_read or is_write):
            return None

        return MMIOAccess(
            address=insn.address,
            pattern=AccessPattern.BASE_OFFSET,
            instruction=f"{insn.mnemonic} {insn.op_str}",
            is_read=is_read,
            is_write=is_write
        )

    def _get_reg_name(self, reg_id: int) -> str:
        """获取寄存器名称"""
        if reg_id == 0:
            return None

        # ARM寄存器
        if self.arch_info.is_arm():
            import capstone.arm as arm
            reg_names = {
                arm.ARM_REG_R0: 'r0', arm.ARM_REG_R1: 'r1',
                arm.ARM_REG_R2: 'r2', arm.ARM_REG_R3: 'r3',
                arm.ARM_REG_R4: 'r4', arm.ARM_REG_R5: 'r5',
                arm.ARM_REG_R6: 'r6', arm.ARM_REG_R7: 'r7',
                arm.ARM_REG_R8: 'r8', arm.ARM_REG_R9: 'r9',
                arm.ARM_REG_R10: 'r10', arm.ARM_REG_R11: 'r11',
                arm.ARM_REG_R12: 'r12', arm.ARM_REG_SP: 'sp',
                arm.ARM_REG_LR: 'lr', arm.ARM_REG_PC: 'pc',
            }
            return reg_names.get(reg_id, f'r{reg_id}')

        return f'reg{reg_id}'

    def _calculate_target_address(self, insn: Instruction, base_reg: str,
                                  offset: int) -> Optional[int]:
        """尝试计算目标地址"""
        # PC相对寻址可以直接计算
        if base_reg == 'pc':
            # ARM Thumb: PC = 当前地址 + 4 (对齐)
            pc_value = (insn.address + 4) & ~3
            return pc_value + offset

        # 其他情况需要运行时信息，无法静态计算
        return None

    def _is_bit_band_address(self, addr: int) -> bool:
        """检查是否是位带地址"""
        start, end = self.BIT_BAND_REGION
        if start <= addr < end:
            return True

        start, end = self.BIT_BAND_ALIAS
        if start <= addr < end:
            return True

        return False

    def is_mmio_address(self, addr: int) -> bool:
        """检查地址是否在MMIO范围内"""
        for start, end in self.MMIO_RANGES:
            if start <= addr < end:
                return True
        return False

    def analyze_instructions(self, instructions: List[Instruction]) -> List[MMIOAccess]:
        """
        批量分析指令

        Args:
            instructions: 指令列表

        Returns:
            MMIO访问列表
        """
        self.mmio_accesses = []

        for insn in instructions:
            access = self.analyze_instruction(insn)
            if access:
                # 如果能计算出目标地址，检查是否在MMIO范围
                if access.target_addr:
                    if self.is_mmio_address(access.target_addr):
                        self.mmio_accesses.append(access)
                else:
                    # 无法静态确定地址，但可能是MMIO访问
                    # 保守地添加所有内存访问（后续可以过滤）
                    self.mmio_accesses.append(access)

        return self.mmio_accesses

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        pattern_counts = {}
        for access in self.mmio_accesses:
            pattern = access.pattern.value
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        read_count = sum(1 for a in self.mmio_accesses if a.is_read)
        write_count = sum(1 for a in self.mmio_accesses if a.is_write)

        return {
            'total_accesses': len(self.mmio_accesses),
            'read_count': read_count,
            'write_count': write_count,
            'pattern_counts': pattern_counts,
        }

    def print_report(self, limit: int = 20):
        """打印分析报告"""
        logger.info("\n" + "=" * 80)
        logger.info("MMIO访问模式分析报告")
        logger.info("=" * 80)

        stats = self.get_statistics()

        logger.info(f"\n[总体统计]")
        logger.info(f"  总访问数: {stats['total_accesses']}")
        logger.info(f"  读操作: {stats['read_count']}")
        logger.info(f"  写操作: {stats['write_count']}")

        logger.info(f"\n[访问模式分布]")
        for pattern, count in sorted(stats['pattern_counts'].items(),
                                     key=lambda x: x[1], reverse=True):
            logger.info(f"  {pattern:20s}: {count:5d}")

        logger.info(f"\n[MMIO访问详情 (前{limit}个)]")
        for i, access in enumerate(self.mmio_accesses[:limit], 1):
            logger.info(f"  {i:3d}. {access}")

        logger.info("\n" + "=" * 80)
