#!/usr/bin/env python3
"""
控制流分析器

识别函数边界、调用关系、基本块
"""

import sys
import os
import logging
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser.architecture import Architecture, ArchInfo
from disasm import Instruction

logger = logging.getLogger(__name__)


@dataclass
class Function:
    """函数信息"""
    start_addr: int
    name: Optional[str] = None
    end_addr: Optional[int] = None
    size: int = 0

    # 调用关系
    calls_to: Set[int] = field(default_factory=set)  # 调用的函数
    called_by: Set[int] = field(default_factory=set)  # 被谁调用

    # 基本块
    basic_blocks: List[int] = field(default_factory=list)

    # 特征
    is_leaf: bool = False  # 叶子函数（不调用其他函数）
    is_recursive: bool = False

    def __str__(self):
        name = self.name or f"sub_{self.start_addr:08x}"
        size_str = f"{self.size}" if self.size > 0 else "?"
        return f"{name} @ 0x{self.start_addr:08x} (size: {size_str})"


@dataclass
class BasicBlock:
    """基本块信息"""
    start_addr: int
    end_addr: int
    instructions: List[Instruction] = field(default_factory=list)

    # 控制流
    successors: List[int] = field(default_factory=list)  # 后继块
    predecessors: List[int] = field(default_factory=list)  # 前驱块

    # 特征
    is_entry: bool = False
    is_exit: bool = False

    def __str__(self):
        return f"BB 0x{self.start_addr:08x}-0x{self.end_addr:08x} ({len(self.instructions)} insns)"


class ControlFlowAnalyzer:
    """控制流分析器"""

    def __init__(self, arch_info: ArchInfo):
        """
        初始化控制流分析器

        Args:
            arch_info: 架构信息
        """
        self.arch_info = arch_info
        self.functions: Dict[int, Function] = {}
        self.basic_blocks: Dict[int, BasicBlock] = {}
        self.call_graph: Dict[int, Set[int]] = defaultdict(set)

    def analyze(self, instructions: List[Instruction]) -> Dict[int, Function]:
        """
        分析指令序列，识别函数和控制流

        Args:
            instructions: 指令列表

        Returns:
            函数字典 {地址: Function}
        """
        logger.info("开始控制流分析...")

        # 第1步：识别函数入口点
        function_starts = self._identify_function_starts(instructions)
        logger.info(f"  识别了 {len(function_starts)} 个函数入口点")

        # 第2步：识别基本块边界
        bb_starts = self._identify_basic_block_starts(instructions)
        logger.info(f"  识别了 {len(bb_starts)} 个基本块")

        # 第3步：构建基本块
        self._build_basic_blocks(instructions, bb_starts)

        # 第4步：构建函数
        self._build_functions(function_starts, instructions)

        # 第5步：分析调用关系
        self._analyze_call_graph(instructions)

        logger.info(f"控制流分析完成: {len(self.functions)} 个函数, {len(self.basic_blocks)} 个基本块")

        return self.functions

    def _identify_function_starts(self, instructions: List[Instruction]) -> Set[int]:
        """识别函数入口点"""
        function_starts = set()

        # 第一条指令通常是函数入口
        if instructions:
            function_starts.add(instructions[0].address)

        for i, insn in enumerate(instructions):
            # 函数入口特征：
            # 1. 被call指令调用的目标
            if insn.is_call():
                target = self._get_branch_target(insn)
                if target:
                    function_starts.add(target)

            # 2. push {lr} 或 push {r4-r7, lr} 等保存返回地址的指令
            if self._is_function_prologue(insn):
                function_starts.add(insn.address)

            # 3. 跳转目标（可能是函数）
            # 如果前一条指令是return，这条可能是新函数
            if i > 0 and instructions[i-1].is_return():
                function_starts.add(insn.address)

        return function_starts

    def _is_function_prologue(self, insn: Instruction) -> bool:
        """检查是否是函数序言"""
        mnemonic = insn.mnemonic.lower()
        op_str = insn.op_str.lower()

        # ARM: push {r4, lr} 或类似
        if mnemonic == 'push' and 'lr' in op_str:
            return True

        # ARM: stmdb sp!, {r4, lr}
        if mnemonic == 'stmdb' and 'sp' in op_str and 'lr' in op_str:
            return True

        return False

    def _identify_basic_block_starts(self, instructions: List[Instruction]) -> Set[int]:
        """识别基本块起始地址"""
        bb_starts = set()

        # 第一条指令是基本块开始
        if instructions:
            bb_starts.add(instructions[0].address)

        for i, insn in enumerate(instructions):
            # 基本块开始的条件：
            # 1. 分支/跳转目标
            if insn.is_branch() or insn.is_call():
                target = self._get_branch_target(insn)
                if target:
                    bb_starts.add(target)

                # 分支后的下一条指令也是新块开始
                if i + 1 < len(instructions):
                    bb_starts.add(instructions[i + 1].address)

            # 2. 返回指令后的下一条
            if insn.is_return() and i + 1 < len(instructions):
                bb_starts.add(instructions[i + 1].address)

        return bb_starts

    def _get_branch_target(self, insn: Instruction) -> Optional[int]:
        """获取分支目标地址"""
        # 检查操作数中的立即数（跳转目标）
        for op in insn.operands:
            if op.type == 1:  # CS_OP_IMM
                return op.imm
        return None

    def _build_basic_blocks(self, instructions: List[Instruction], bb_starts: Set[int]):
        """构建基本块"""
        sorted_starts = sorted(bb_starts)
        insn_map = {insn.address: insn for insn in instructions}

        for i, start in enumerate(sorted_starts):
            # 确定块的结束地址
            if i + 1 < len(sorted_starts):
                end = sorted_starts[i + 1]
            else:
                end = instructions[-1].address + instructions[-1].size

            # 收集块内的指令
            block_insns = []
            addr = start
            while addr < end and addr in insn_map:
                insn = insn_map[addr]
                block_insns.append(insn)
                addr += insn.size

            if block_insns:
                bb = BasicBlock(
                    start_addr=start,
                    end_addr=block_insns[-1].address + block_insns[-1].size,
                    instructions=block_insns
                )

                # 检查是否是退出块
                last_insn = block_insns[-1]
                if last_insn.is_return():
                    bb.is_exit = True

                self.basic_blocks[start] = bb

    def _build_functions(self, function_starts: Set[int], instructions: List[Instruction]):
        """构建函数"""
        sorted_starts = sorted(function_starts)

        for i, start in enumerate(sorted_starts):
            # 确定函数结束地址（简化：到下一个函数开始）
            if i + 1 < len(sorted_starts):
                end = sorted_starts[i + 1]
            else:
                end = instructions[-1].address + instructions[-1].size

            func = Function(
                start_addr=start,
                end_addr=end,
                size=end - start
            )

            # 找到属于这个函数的基本块
            for bb_addr, bb in self.basic_blocks.items():
                if start <= bb_addr < end:
                    func.basic_blocks.append(bb_addr)

            self.functions[start] = func

    def _analyze_call_graph(self, instructions: List[Instruction]):
        """分析调用图"""
        for insn in instructions:
            if insn.is_call():
                caller = self._find_function_for_address(insn.address)
                target = self._get_branch_target(insn)

                if caller and target:
                    callee = self._find_function_for_address(target)

                    if caller in self.functions:
                        self.functions[caller].calls_to.add(target)

                    if callee and callee in self.functions:
                        self.functions[callee].called_by.add(caller)

                        # 检查递归
                        if caller == callee:
                            self.functions[caller].is_recursive = True

        # 标记叶子函数
        for addr, func in self.functions.items():
            if len(func.calls_to) == 0:
                func.is_leaf = True

    def _find_function_for_address(self, addr: int) -> Optional[int]:
        """找到包含给定地址的函数"""
        for func_addr, func in self.functions.items():
            if func.start_addr <= addr < func.end_addr:
                return func_addr
        return None

    def get_function_at(self, addr: int) -> Optional[Function]:
        """获取指定地址的函数"""
        return self.functions.get(addr)

    def get_call_graph(self) -> Dict[int, Set[int]]:
        """获取调用图"""
        graph = {}
        for addr, func in self.functions.items():
            graph[addr] = func.calls_to
        return graph

    def print_summary(self):
        """打印分析摘要"""
        logger.info("\n" + "=" * 80)
        logger.info("控制流分析摘要")
        logger.info("=" * 80)

        logger.info(f"\n[函数统计]")
        logger.info(f"  总函数数: {len(self.functions)}")

        leaf_funcs = [f for f in self.functions.values() if f.is_leaf]
        logger.info(f"  叶子函数: {len(leaf_funcs)}")

        recursive_funcs = [f for f in self.functions.values() if f.is_recursive]
        logger.info(f"  递归函数: {len(recursive_funcs)}")

        logger.info(f"\n[基本块统计]")
        logger.info(f"  总基本块数: {len(self.basic_blocks)}")

        entry_blocks = [bb for bb in self.basic_blocks.values() if bb.is_entry]
        exit_blocks = [bb for bb in self.basic_blocks.values() if bb.is_exit]
        logger.info(f"  入口块: {len(entry_blocks)}")
        logger.info(f"  退出块: {len(exit_blocks)}")

        logger.info(f"\n[函数列表 (前20个)]")
        for i, (addr, func) in enumerate(sorted(self.functions.items())[:20], 1):
            calls = len(func.calls_to)
            called = len(func.called_by)
            logger.info(f"  {i:3d}. {func} | calls: {calls}, called_by: {called}")

        logger.info("\n" + "=" * 80)
