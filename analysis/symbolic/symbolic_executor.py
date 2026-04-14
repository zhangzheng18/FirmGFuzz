#!/usr/bin/env python3
"""
符号执行分析器 - 使用angr进行符号执行

功能：
1. 符号执行解析MMIO地址
2. 路径爆炸防护
3. 超时控制
4. 目标导向的符号执行
"""

import sys
import os
import logging
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

# 尝试导入angr
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    logger.warning("angr不可用，符号执行功能将被禁用")


@dataclass
class SymbolicExecutionConfig:
    """符号执行配置"""
    # 路径爆炸防护
    max_paths: int = 100              # 最大路径数
    max_depth: int = 50               # 最大深度
    max_steps: int = 10000            # 最大步数
    timeout: int = 60                 # 超时（秒）

    # 探索策略
    exploration_technique: str = 'dfs'  # dfs, bfs, or targeted

    # 内存模型
    symbolic_memory: bool = False     # 是否符号化内存
    concrete_mmio: bool = True        # MMIO地址使用具体值

    # 优化
    use_unicorn: bool = True          # 使用Unicorn加速
    lazy_solves: bool = True          # 延迟求解


class SymbolicExecutor:
    """符号执行器"""

    def __init__(self, firmware_path: str, config: Optional[SymbolicExecutionConfig] = None):
        """
        初始化符号执行器

        Args:
            firmware_path: 固件文件路径
            config: 配置
        """
        if not ANGR_AVAILABLE:
            raise RuntimeError("angr不可用")

        self.firmware_path = firmware_path
        self.config = config or SymbolicExecutionConfig()

        # 加载二进制
        self.project = None
        self.resolved_addresses: Dict[int, int] = {}
        self.explored_paths: int = 0
        self.start_time: float = 0

    def load_binary(self) -> bool:
        """加载二进制文件"""
        try:
            logger.info(f"加载固件: {self.firmware_path}")

            # 加载选项
            load_options = {
                'auto_load_libs': False,  # 不加载库
                'main_opts': {
                    'backend': 'blob',    # 使用blob后端（原始二进制）
                    'arch': 'arm',
                    'base_addr': 0x08000000,  # ARM Cortex-M Flash基址
                }
            }

            self.project = angr.Project(
                self.firmware_path,
                load_options=load_options,
                auto_load_libs=False
            )

            logger.info(f"  架构: {self.project.arch.name}")
            logger.info(f"  入口: 0x{self.project.entry:08x}")

            return True

        except Exception as e:
            logger.error(f"加载失败: {e}")
            return False

    def analyze_function(self, func_addr: int, target_addrs: Optional[Set[int]] = None) -> Dict[int, int]:
        """
        分析单个函数

        Args:
            func_addr: 函数地址
            target_addrs: 目标地址集合（用于目标导向探索）

        Returns:
            解析的MMIO地址字典
        """
        if not self.project:
            logger.error("项目未加载")
            return {}

        logger.info(f"\n符号执行函数 0x{func_addr:08x}")

        self.start_time = time.time()
        self.explored_paths = 0
        self.resolved_addresses = {}

        try:
            # 创建初始状态
            state = self.project.factory.blank_state(
                addr=func_addr,
                add_options={
                    angr.options.LAZY_SOLVES if self.config.lazy_solves else angr.options.SYMBOLIC,
                }
            )

            # 设置初始寄存器值
            state.regs.sp = 0x20007800  # ARM Cortex-M栈指针

            # 创建模拟管理器
            simgr = self.project.factory.simulation_manager(state)

            # 添加探索技术
            self._add_exploration_techniques(simgr, target_addrs)

            # 执行符号执行
            self._explore(simgr)

            # 提取结果
            self._extract_mmio_addresses(simgr)

        except Exception as e:
            logger.error(f"符号执行失败: {e}")

        elapsed = time.time() - self.start_time
        logger.info(f"  探索了 {self.explored_paths} 条路径")
        logger.info(f"  解析了 {len(self.resolved_addresses)} 个MMIO地址")
        logger.info(f"  耗时: {elapsed:.2f}s")

        return self.resolved_addresses

    def _add_exploration_techniques(self, simgr, target_addrs: Optional[Set[int]]):
        """添加探索技术"""

        # 1. DFS探索器（防止路径爆炸）
        if self.config.exploration_technique == 'dfs':
            simgr.use_technique(angr.exploration_techniques.DFS())

        # 2. 路径数限制
        simgr.use_technique(
            angr.exploration_techniques.LengthLimiter(
                max_length=self.config.max_depth
            )
        )

        # 3. 超时控制
        simgr.use_technique(
            angr.exploration_techniques.Threading(
                threads=1  # 单线程，避免资源竞争
            )
        )

        # 4. 目标导向探索（如果提供了目标地址）
        if target_addrs and self.config.exploration_technique == 'targeted':
            simgr.use_technique(
                angr.exploration_techniques.Explorer(
                    find=list(target_addrs),
                    num_find=len(target_addrs)
                )
            )

    def _explore(self, simgr):
        """执行探索"""
        step_count = 0
        max_steps = self.config.max_steps

        while simgr.active and step_count < max_steps:
            # 检查超时
            if time.time() - self.start_time > self.config.timeout:
                logger.warning("  符号执行超时")
                break

            # 检查路径数
            total_paths = len(simgr.active) + len(simgr.deadended)
            if total_paths > self.config.max_paths:
                logger.warning(f"  路径数超限 ({total_paths} > {self.config.max_paths})")
                break

            # 执行一步
            try:
                simgr.step()
                step_count += 1

                # 定期报告
                if step_count % 100 == 0:
                    logger.debug(f"  步数: {step_count}, 活跃路径: {len(simgr.active)}, "
                               f"结束路径: {len(simgr.deadended)}")

            except Exception as e:
                logger.warning(f"  探索步骤失败: {e}")
                break

        self.explored_paths = len(simgr.active) + len(simgr.deadended)

    def _extract_mmio_addresses(self, simgr):
        """从状态中提取MMIO地址"""

        # 检查所有状态（活跃的和结束的）
        all_states = simgr.active + simgr.deadended

        for state in all_states:
            try:
                # 检查内存访问历史
                if hasattr(state, 'history') and hasattr(state.history, 'actions'):
                    for action in state.history.actions:
                        if action.type in ['mem_read', 'mem_write']:
                            # 尝试具体化地址
                            if action.addr.symbolic:
                                # 符号地址，尝试求解
                                try:
                                    concrete_addr = state.solver.eval(action.addr, cast_to=int)
                                    if self._is_mmio_address(concrete_addr):
                                        self.resolved_addresses[action.ins_addr] = concrete_addr
                                except:
                                    pass
                            else:
                                # 具体地址
                                concrete_addr = state.solver.eval(action.addr, cast_to=int)
                                if self._is_mmio_address(concrete_addr):
                                    self.resolved_addresses[action.ins_addr] = concrete_addr

            except Exception as e:
                logger.debug(f"  提取地址失败: {e}")
                continue

    def _is_mmio_address(self, addr: int) -> bool:
        """检查是否是MMIO地址"""
        # ARM Cortex-M MMIO范围
        return (0x40000000 <= addr < 0x60000000) or \
               (0xE0000000 <= addr < 0xE0100000)

    def analyze_multiple_functions(self, func_addrs: List[int],
                                   max_funcs: int = 10) -> Dict[int, int]:
        """
        分析多个函数（带限制）

        Args:
            func_addrs: 函数地址列表
            max_funcs: 最大分析函数数

        Returns:
            所有解析的MMIO地址
        """
        all_resolved = {}

        for i, func_addr in enumerate(func_addrs[:max_funcs], 1):
            logger.info(f"\n[{i}/{min(len(func_addrs), max_funcs)}] 分析函数 0x{func_addr:08x}")

            resolved = self.analyze_function(func_addr)
            all_resolved.update(resolved)

            # 检查总超时
            if time.time() - self.start_time > self.config.timeout * max_funcs:
                logger.warning("总超时，停止分析")
                break

        return all_resolved

    def print_summary(self):
        """打印分析摘要"""
        logger.info("\n" + "=" * 80)
        logger.info("符号执行分析摘要")
        logger.info("=" * 80)

        logger.info(f"\n[配置]")
        logger.info(f"  最大路径数: {self.config.max_paths}")
        logger.info(f"  最大深度: {self.config.max_depth}")
        logger.info(f"  超时: {self.config.timeout}s")

        logger.info(f"\n[结果]")
        logger.info(f"  探索的路径: {self.explored_paths}")
        logger.info(f"  解析的MMIO地址: {len(self.resolved_addresses)}")

        if self.resolved_addresses:
            logger.info(f"\n[解析的MMIO地址 (前20个)]")
            for i, (insn_addr, mmio_addr) in enumerate(
                sorted(self.resolved_addresses.items())[:20], 1
            ):
                logger.info(f"  {i:3d}. 0x{insn_addr:08x} -> 0x{mmio_addr:08x}")

        logger.info("\n" + "=" * 80)


class HybridAnalyzer:
    """混合分析器 - 结合数据流分析和符号执行"""

    def __init__(self, firmware_path: str):
        """
        初始化混合分析器

        Args:
            firmware_path: 固件文件路径
        """
        self.firmware_path = firmware_path
        self.dataflow_results: Dict[int, int] = {}
        self.symbolic_results: Dict[int, int] = {}

    def analyze(self, instructions: List, functions: Dict,
                use_symbolic: bool = True) -> Dict[int, int]:
        """
        执行混合分析

        Args:
            instructions: 指令列表
            functions: 函数字典
            use_symbolic: 是否使用符号执行

        Returns:
            所有解析的MMIO地址
        """
        logger.info("\n" + "=" * 80)
        logger.info("混合分析")
        logger.info("=" * 80)

        # 第1步：数据流分析（快速）
        logger.info("\n[步骤1] 数据流分析")
        from dataflow import DataFlowAnalyzer

        df_analyzer = DataFlowAnalyzer(instructions)
        self.dataflow_results = df_analyzer.analyze()
        df_analyzer.print_summary()

        # 第2步：符号执行（针对未解析的函数）
        if use_symbolic and ANGR_AVAILABLE:
            logger.info("\n[步骤2] 符号执行（针对性）")

            # 找出数据流分析未覆盖的函数
            covered_funcs = set()
            for insn_addr in self.dataflow_results.keys():
                for func_addr, func in functions.items():
                    if func.start_addr <= insn_addr < func.end_addr:
                        covered_funcs.add(func_addr)

            uncovered_funcs = set(functions.keys()) - covered_funcs
            logger.info(f"  数据流已覆盖: {len(covered_funcs)} 个函数")
            logger.info(f"  待符号执行: {len(uncovered_funcs)} 个函数")

            if uncovered_funcs:
                # 配置：更保守的参数
                config = SymbolicExecutionConfig(
                    max_paths=50,
                    max_depth=30,
                    max_steps=5000,
                    timeout=30,
                    exploration_technique='dfs'
                )

                sym_executor = SymbolicExecutor(self.firmware_path, config)
                if sym_executor.load_binary():
                    self.symbolic_results = sym_executor.analyze_multiple_functions(
                        list(uncovered_funcs),
                        max_funcs=5  # 只分析前5个
                    )
                    sym_executor.print_summary()

        # 合并结果
        all_results = {}
        all_results.update(self.dataflow_results)
        all_results.update(self.symbolic_results)

        logger.info("\n[混合分析总结]")
        logger.info(f"  数据流解析: {len(self.dataflow_results)} 个地址")
        logger.info(f"  符号执行解析: {len(self.symbolic_results)} 个地址")
        logger.info(f"  总计: {len(all_results)} 个地址")

        return all_results
