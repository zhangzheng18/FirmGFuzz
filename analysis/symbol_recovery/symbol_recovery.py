#!/usr/bin/env python3
"""
符号恢复 - 基于MMIO访问模式推断外设类型
"""

import sys
import os
import logging
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_parser.architecture import ArchInfo
from mmio_analyzer import MMIOAccess, AccessPattern

logger = logging.getLogger(__name__)


@dataclass
class PeripheralSignature:
    """外设特征签名"""
    name: str
    base_addr: int
    registers: Dict[int, str]  # offset -> register_name
    access_patterns: List[str]  # 典型的访问模式


# ARM Cortex-M常见外设签名库
PERIPHERAL_SIGNATURES = {
    # UART/USART
    'UART': PeripheralSignature(
        name='UART',
        base_addr=0x40013800,  # USART1 on STM32
        registers={
            0x00: 'SR',    # Status Register
            0x04: 'DR',    # Data Register
            0x08: 'BRR',   # Baud Rate Register
            0x0C: 'CR1',   # Control Register 1
            0x10: 'CR2',   # Control Register 2
            0x14: 'CR3',   # Control Register 3
        },
        access_patterns=['read_DR', 'write_DR', 'check_SR']
    ),

    # GPIO
    'GPIO': PeripheralSignature(
        name='GPIO',
        base_addr=0x40010800,  # GPIOA on STM32
        registers={
            0x00: 'CRL',   # Port Configuration Register Low
            0x04: 'CRH',   # Port Configuration Register High
            0x08: 'IDR',   # Input Data Register
            0x0C: 'ODR',   # Output Data Register
            0x10: 'BSRR',  # Bit Set/Reset Register
            0x14: 'BRR',   # Bit Reset Register
        },
        access_patterns=['write_ODR', 'read_IDR', 'write_BSRR']
    ),

    # Timer
    'TIM': PeripheralSignature(
        name='Timer',
        base_addr=0x40000000,  # TIM2 on STM32
        registers={
            0x00: 'CR1',   # Control Register 1
            0x04: 'CR2',   # Control Register 2
            0x0C: 'DIER',  # DMA/Interrupt Enable Register
            0x10: 'SR',    # Status Register
            0x24: 'CNT',   # Counter
            0x28: 'PSC',   # Prescaler
            0x2C: 'ARR',   # Auto-Reload Register
        },
        access_patterns=['write_CNT', 'read_CNT', 'write_ARR']
    ),

    # SPI
    'SPI': PeripheralSignature(
        name='SPI',
        base_addr=0x40013000,  # SPI1 on STM32
        registers={
            0x00: 'CR1',   # Control Register 1
            0x04: 'CR2',   # Control Register 2
            0x08: 'SR',    # Status Register
            0x0C: 'DR',    # Data Register
        },
        access_patterns=['write_DR', 'read_DR', 'check_SR']
    ),

    # I2C
    'I2C': PeripheralSignature(
        name='I2C',
        base_addr=0x40005400,  # I2C1 on STM32
        registers={
            0x00: 'CR1',   # Control Register 1
            0x04: 'CR2',   # Control Register 2
            0x08: 'OAR1',  # Own Address Register 1
            0x0C: 'OAR2',  # Own Address Register 2
            0x10: 'DR',    # Data Register
            0x14: 'SR1',   # Status Register 1
            0x18: 'SR2',   # Status Register 2
        },
        access_patterns=['write_DR', 'read_DR', 'check_SR1']
    ),
}


@dataclass
class IdentifiedPeripheral:
    """识别出的外设"""
    peripheral_type: str
    base_addr: int
    confidence: float  # 0.0 - 1.0
    accessed_registers: Dict[int, int]  # offset -> access_count
    functions_using: Set[int]  # 使用此外设的函数地址


class SymbolRecovery:
    """符号恢复器"""

    def __init__(self, arch_info: ArchInfo):
        """
        初始化符号恢复器

        Args:
            arch_info: 架构信息
        """
        self.arch_info = arch_info
        self.identified_peripherals: List[IdentifiedPeripheral] = []
        self.mmio_clusters: Dict[int, List[MMIOAccess]] = defaultdict(list)

    def analyze(self, mmio_accesses: List[MMIOAccess],
                functions: Dict = None) -> List[IdentifiedPeripheral]:
        """
        分析MMIO访问，识别外设

        Args:
            mmio_accesses: MMIO访问列表
            functions: 函数字典（可选）

        Returns:
            识别出的外设列表
        """
        logger.info("开始符号恢复...")

        # 第1步：聚类MMIO访问（按基址）
        self._cluster_mmio_accesses(mmio_accesses)
        logger.info(f"  识别了 {len(self.mmio_clusters)} 个MMIO访问簇")

        # 第2步：匹配外设签名
        self._match_peripheral_signatures()
        logger.info(f"  识别了 {len(self.identified_peripherals)} 个外设")

        # 第3步：关联函数
        if functions:
            self._associate_functions(mmio_accesses, functions)

        return self.identified_peripherals

    def _cluster_mmio_accesses(self, mmio_accesses: List[MMIOAccess]):
        """将MMIO访问按基址聚类"""
        # 简化：按4KB页对齐聚类
        PAGE_SIZE = 0x400  # 1KB

        for access in mmio_accesses:
            if access.target_addr:
                # 按页对齐
                base = (access.target_addr // PAGE_SIZE) * PAGE_SIZE
                self.mmio_clusters[base].append(access)
            elif access.base_reg and access.offset is not None:
                # 无法确定绝对地址，但可以记录访问模式
                pass

    def _match_peripheral_signatures(self):
        """匹配外设签名"""
        for base_addr, accesses in self.mmio_clusters.items():
            # 统计访问的寄存器偏移
            register_accesses = defaultdict(int)
            for access in accesses:
                if access.target_addr:
                    offset = access.target_addr - base_addr
                    if 0 <= offset < 0x400:  # 在合理范围内
                        register_accesses[offset] += 1

            # 尝试匹配已知外设
            best_match = None
            best_score = 0.0

            for periph_name, signature in PERIPHERAL_SIGNATURES.items():
                score = self._calculate_match_score(
                    register_accesses,
                    signature.registers
                )

                if score > best_score and score > 0.3:  # 阈值
                    best_score = score
                    best_match = periph_name

            if best_match:
                peripheral = IdentifiedPeripheral(
                    peripheral_type=best_match,
                    base_addr=base_addr,
                    confidence=best_score,
                    accessed_registers=dict(register_accesses),
                    functions_using=set()
                )
                self.identified_peripherals.append(peripheral)

    def _calculate_match_score(self, accessed: Dict[int, int],
                               signature: Dict[int, str]) -> float:
        """计算匹配分数"""
        if not signature:
            return 0.0

        # 计算重叠度
        accessed_offsets = set(accessed.keys())
        signature_offsets = set(signature.keys())

        if not signature_offsets:
            return 0.0

        overlap = len(accessed_offsets & signature_offsets)
        score = overlap / len(signature_offsets)

        return score

    def _associate_functions(self, mmio_accesses: List[MMIOAccess],
                            functions: Dict):
        """关联使用外设的函数"""
        # 为每个MMIO访问找到所属函数
        for access in mmio_accesses:
            func_addr = self._find_function_for_address(access.address, functions)
            if func_addr:
                # 找到对应的外设
                if access.target_addr:
                    for peripheral in self.identified_peripherals:
                        if peripheral.base_addr <= access.target_addr < peripheral.base_addr + 0x400:
                            peripheral.functions_using.add(func_addr)

    def _find_function_for_address(self, addr: int, functions: Dict) -> Optional[int]:
        """找到包含给定地址的函数"""
        for func_addr, func in functions.items():
            if hasattr(func, 'start_addr') and hasattr(func, 'end_addr'):
                if func.start_addr <= addr < func.end_addr:
                    return func_addr
        return None

    def print_report(self):
        """打印符号恢复报告"""
        logger.info("\n" + "=" * 80)
        logger.info("符号恢复报告")
        logger.info("=" * 80)

        logger.info(f"\n[识别的外设]")
        logger.info(f"  总数: {len(self.identified_peripherals)}")

        for i, periph in enumerate(self.identified_peripherals, 1):
            logger.info(f"\n  {i}. {periph.peripheral_type} @ 0x{periph.base_addr:08x}")
            logger.info(f"     置信度: {periph.confidence:.2%}")
            logger.info(f"     访问的寄存器: {len(periph.accessed_registers)}")

            # 显示访问最多的寄存器
            top_regs = sorted(periph.accessed_registers.items(),
                            key=lambda x: x[1], reverse=True)[:5]
            logger.info(f"     热点寄存器:")
            for offset, count in top_regs:
                logger.info(f"       +0x{offset:02x}: {count} 次访问")

            if periph.functions_using:
                logger.info(f"     使用的函数: {len(periph.functions_using)} 个")

        logger.info("\n" + "=" * 80)

    def export_symbols(self, output_path: str):
        """导出符号信息"""
        import json

        data = {
            'peripherals': [
                {
                    'type': p.peripheral_type,
                    'base_addr': hex(p.base_addr),
                    'confidence': p.confidence,
                    'registers': {hex(k): v for k, v in p.accessed_registers.items()},
                    'functions': [hex(f) for f in p.functions_using]
                }
                for p in self.identified_peripherals
            ]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"符号信息已导出到 {output_path}")
