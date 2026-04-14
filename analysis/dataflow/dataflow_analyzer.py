#!/usr/bin/env python3
"""
数据流分析器 - 追踪寄存器值的传播

功能：
1. 追踪寄存器值的定义和使用
2. 常量传播分析
3. 指针分析（用于解析MMIO地址）
4. 到达定义分析
"""

import sys
import os
import logging
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from disasm import Instruction

logger = logging.getLogger(__name__)


class ValueType(Enum):
    """值类型"""
    CONSTANT = 'constant'      # 常量
    REGISTER = 'register'      # 寄存器
    MEMORY = 'memory'          # 内存
    UNKNOWN = 'unknown'        # 未知
    TOP = 'top'               # 顶部（可能是任何值）
    BOTTOM = 'bottom'         # 底部（不可达）


@dataclass
class AbstractValue:
    """抽象值"""
    value_type: ValueType
    value: Optional[int] = None  # 对于常量
    register: Optional[str] = None  # 对于寄存器
    base: Optional[str] = None  # 对于内存：基址寄存器
    offset: Optional[int] = None  # 对于内存：偏移

    def __str__(self):
        if self.value_type == ValueType.CONSTANT:
            return f"const(0x{self.value:x})"
        elif self.value_type == ValueType.REGISTER:
            return f"reg({self.register})"
        elif self.value_type == ValueType.MEMORY:
            return f"mem([{self.base}+{self.offset}])"
        else:
            return self.value_type.value

    def is_constant(self) -> bool:
        return self.value_type == ValueType.CONSTANT

    def is_mmio_address(self) -> bool:
        """检查是否是MMIO地址"""
        if self.value_type == ValueType.CONSTANT and self.value:
            # ARM Cortex-M MMIO范围
            return 0x40000000 <= self.value < 0x60000000 or \
                   0xE0000000 <= self.value < 0xE0100000
        return False


@dataclass
class RegisterState:
    """寄存器状态"""
    values: Dict[str, AbstractValue] = field(default_factory=dict)

    def get(self, reg: str) -> AbstractValue:
        """获取寄存器值"""
        return self.values.get(reg, AbstractValue(ValueType.UNKNOWN))

    def set(self, reg: str, value: AbstractValue):
        """设置寄存器值"""
        self.values[reg] = value

    def copy(self) -> 'RegisterState':
        """复制状态"""
        new_state = RegisterState()
        new_state.values = self.values.copy()
        return new_state

    def merge(self, other: 'RegisterState') -> 'RegisterState':
        """合并两个状态（用于控制流汇合点）"""
        merged = RegisterState()
        all_regs = set(self.values.keys()) | set(other.values.keys())

        for reg in all_regs:
            val1 = self.get(reg)
            val2 = other.get(reg)

            # 如果两个值相同，保留
            if val1.value_type == val2.value_type and val1.value == val2.value:
                merged.set(reg, val1)
            else:
                # 否则标记为TOP（可能是任何值）
                merged.set(reg, AbstractValue(ValueType.TOP))

        return merged


class DataFlowAnalyzer:
    """数据流分析器"""

    def __init__(self, instructions: List[Instruction]):
        """
        初始化数据流分析器

        Args:
            instructions: 指令列表
        """
        self.instructions = instructions
        self.insn_map = {insn.address: insn for insn in instructions}

        # 分析结果
        self.states_before: Dict[int, RegisterState] = {}  # 指令前的状态
        self.states_after: Dict[int, RegisterState] = {}   # 指令后的状态
        self.resolved_addresses: Dict[int, int] = {}  # 解析的MMIO地址

    def analyze(self) -> Dict[int, int]:
        """
        执行数据流分析

        Returns:
            解析的MMIO地址字典 {指令地址: MMIO地址}
        """
        logger.info("开始数据流分析...")

        # 初始化入口状态
        entry_state = RegisterState()
        # ARM Cortex-M常见初始值
        entry_state.set('sp', AbstractValue(ValueType.CONSTANT, 0x20007800))
        entry_state.set('pc', AbstractValue(ValueType.CONSTANT, self.instructions[0].address))

        # 工作列表算法
        worklist = [self.instructions[0].address]
        visited = set()

        while worklist:
            addr = worklist.pop(0)

            if addr in visited:
                continue
            visited.add(addr)

            if addr not in self.insn_map:
                continue

            insn = self.insn_map[addr]

            # 获取指令前的状态
            if addr == self.instructions[0].address:
                state_before = entry_state
            else:
                state_before = self.states_after.get(addr, RegisterState())

            self.states_before[addr] = state_before

            # 执行指令，得到指令后的状态
            state_after = self._execute_instruction(insn, state_before)
            self.states_after[addr] = state_after

            # 添加后继指令到工作列表
            successors = self._get_successors(insn)
            for succ_addr in successors:
                if succ_addr not in visited:
                    worklist.append(succ_addr)

        logger.info(f"  分析了 {len(visited)} 条指令")
        logger.info(f"  解析了 {len(self.resolved_addresses)} 个MMIO地址")

        return self.resolved_addresses

    def _execute_instruction(self, insn: Instruction, state: RegisterState) -> RegisterState:
        """执行单条指令，更新状态"""
        new_state = state.copy()
        mnemonic = insn.mnemonic.lower()

        # MOV指令
        if mnemonic in ['mov', 'movs']:
            self._handle_mov(insn, new_state)

        # MOVW/MOVT指令（立即数加载）
        elif mnemonic in ['movw', 'movt']:
            self._handle_movw_movt(insn, new_state)

        # ADD/SUB指令
        elif mnemonic in ['add', 'adds', 'sub', 'subs']:
            self._handle_add_sub(insn, new_state)

        # LDR指令（可能加载MMIO地址）
        elif mnemonic.startswith('ldr'):
            self._handle_ldr(insn, new_state)

        # STR指令
        elif mnemonic.startswith('str'):
            self._handle_str(insn, new_state)

        # 其他指令：保守处理，标记目标寄存器为UNKNOWN
        else:
            dest_reg = self._get_dest_register(insn)
            if dest_reg:
                new_state.set(dest_reg, AbstractValue(ValueType.UNKNOWN))

        return new_state

    def _handle_mov(self, insn: Instruction, state: RegisterState):
        """处理MOV指令"""
        if len(insn.operands) < 2:
            return

        dest = self._get_operand_name(insn.operands[0])
        src = insn.operands[1]

        if src.type == 1:  # CS_OP_IMM
            # mov r0, #0x40000000
            state.set(dest, AbstractValue(ValueType.CONSTANT, src.imm))
        elif src.type == 2:  # CS_OP_REG
            # mov r0, r1
            src_reg = self._get_operand_name(src)
            state.set(dest, state.get(src_reg))

    def _handle_movw_movt(self, insn: Instruction, state: RegisterState):
        """处理MOVW/MOVT指令（构造32位立即数）"""
        if len(insn.operands) < 2:
            return

        dest = self._get_operand_name(insn.operands[0])
        imm = insn.operands[1].imm

        mnemonic = insn.mnemonic.lower()

        if mnemonic == 'movw':
            # movw r0, #0x1234  -> r0 = 0x00001234
            state.set(dest, AbstractValue(ValueType.CONSTANT, imm & 0xFFFF))
        elif mnemonic == 'movt':
            # movt r0, #0x4000  -> r0 = (r0 & 0xFFFF) | (0x4000 << 16)
            current = state.get(dest)
            if current.is_constant():
                new_val = (current.value & 0xFFFF) | ((imm & 0xFFFF) << 16)
                state.set(dest, AbstractValue(ValueType.CONSTANT, new_val))
            else:
                state.set(dest, AbstractValue(ValueType.UNKNOWN))

    def _handle_add_sub(self, insn: Instruction, state: RegisterState):
        """处理ADD/SUB指令"""
        if len(insn.operands) < 3:
            return

        dest = self._get_operand_name(insn.operands[0])
        src1 = insn.operands[1]
        src2 = insn.operands[2]

        mnemonic = insn.mnemonic.lower()
        is_add = 'add' in mnemonic

        # 获取操作数值
        val1 = None
        if src1.type == 2:  # REG
            reg1 = self._get_operand_name(src1)
            abs_val1 = state.get(reg1)
            if abs_val1.is_constant():
                val1 = abs_val1.value

        val2 = None
        if src2.type == 1:  # IMM
            val2 = src2.imm
        elif src2.type == 2:  # REG
            reg2 = self._get_operand_name(src2)
            abs_val2 = state.get(reg2)
            if abs_val2.is_constant():
                val2 = abs_val2.value

        # 如果两个操作数都是常量，计算结果
        if val1 is not None and val2 is not None:
            if is_add:
                result = (val1 + val2) & 0xFFFFFFFF
            else:
                result = (val1 - val2) & 0xFFFFFFFF
            state.set(dest, AbstractValue(ValueType.CONSTANT, result))
        else:
            state.set(dest, AbstractValue(ValueType.UNKNOWN))

    def _handle_ldr(self, insn: Instruction, state: RegisterState):
        """处理LDR指令"""
        if len(insn.operands) < 2:
            return

        dest = self._get_operand_name(insn.operands[0])

        # 检查是否是从常量地址加载
        mem_op = insn.operands[1]
        if mem_op.type == 3:  # CS_OP_MEM
            base_reg = self._get_reg_name(mem_op.mem.base)
            offset = mem_op.mem.disp

            # 如果基址是常量，计算目标地址
            base_val = state.get(base_reg)
            if base_val.is_constant():
                target_addr = (base_val.value + offset) & 0xFFFFFFFF

                # 记录解析的地址
                if 0x40000000 <= target_addr < 0x60000000:
                    self.resolved_addresses[insn.address] = target_addr

        # 保守处理：标记为UNKNOWN
        state.set(dest, AbstractValue(ValueType.UNKNOWN))

    def _handle_str(self, insn: Instruction, state: RegisterState):
        """处理STR指令"""
        if len(insn.operands) < 2:
            return

        # 检查是否是写入常量地址
        mem_op = insn.operands[1]
        if mem_op.type == 3:  # CS_OP_MEM
            base_reg = self._get_reg_name(mem_op.mem.base)
            offset = mem_op.mem.disp

            # 如果基址是常量，计算目标地址
            base_val = state.get(base_reg)
            if base_val.is_constant():
                target_addr = (base_val.value + offset) & 0xFFFFFFFF

                # 记录解析的地址
                if 0x40000000 <= target_addr < 0x60000000:
                    self.resolved_addresses[insn.address] = target_addr

    def _get_successors(self, insn: Instruction) -> List[int]:
        """获取指令的后继"""
        successors = []

        # 默认后继：下一条指令
        next_addr = insn.address + insn.size
        if next_addr in self.insn_map:
            successors.append(next_addr)

        # 如果是分支指令，添加跳转目标
        if insn.is_branch():
            for op in insn.operands:
                if op.type == 1:  # CS_OP_IMM
                    target = op.imm
                    if target in self.insn_map:
                        successors.append(target)

        return successors

    def _get_dest_register(self, insn: Instruction) -> Optional[str]:
        """获取目标寄存器"""
        if insn.operands and len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == 2:  # CS_OP_REG
                return self._get_operand_name(op)
        return None

    def _get_operand_name(self, operand) -> str:
        """获取操作数名称"""
        import capstone.arm as arm
        if operand.type == 2:  # CS_OP_REG
            return self._get_reg_name(operand.reg)
        return "unknown"

    def _get_reg_name(self, reg_id: int) -> str:
        """获取寄存器名称"""
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
        return reg_names.get(reg_id, f"reg_{reg_id}")

    def print_summary(self):
        """打印分析摘要"""
        logger.info("\n" + "=" * 80)
        logger.info("数据流分析摘要")
        logger.info("=" * 80)

        logger.info(f"\n[分析统计]")
        logger.info(f"  分析的指令数: {len(self.states_after)}")
        logger.info(f"  解析的MMIO地址: {len(self.resolved_addresses)}")

        if self.resolved_addresses:
            logger.info(f"\n[解析的MMIO地址 (前20个)]")
            for i, (insn_addr, mmio_addr) in enumerate(
                sorted(self.resolved_addresses.items())[:20], 1
            ):
                insn = self.insn_map.get(insn_addr)
                insn_str = f"{insn.mnemonic} {insn.op_str}" if insn else "?"
                logger.info(f"  {i:3d}. 0x{insn_addr:08x}: {insn_str:30s} -> 0x{mmio_addr:08x}")

        logger.info("\n" + "=" * 80)
