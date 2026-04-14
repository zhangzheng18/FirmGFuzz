#!/usr/bin/env python3
"""
动态MMIO监测器 - 完整实现

在Unicorn仿真中拦截所有内存访问，记录MMIO操作
"""

import json
import logging
from collections import defaultdict
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


class AccessType(Enum):
    """访问类型"""
    READ = 'read'
    WRITE = 'write'


@dataclass
class MMIOAccess:
    """单次MMIO访问记录"""
    address: int
    value: int
    operation: AccessType
    pc: int
    size: int = 4
    timestamp: int = 0


@dataclass
class MMIOAddress:
    """MMIO地址统计信息"""
    address: int
    module: str = 'UNKNOWN'
    offset: int = 0
    read_count: int = 0
    write_count: int = 0
    values: Set[int] = field(default_factory=set)
    access_points: List[Dict] = field(default_factory=list)

    @property
    def total_accesses(self) -> int:
        return self.read_count + self.write_count

    @property
    def access_type(self) -> str:
        if self.read_count > 0 and self.write_count == 0:
            return 'read-only'
        elif self.write_count > 0 and self.read_count == 0:
            return 'write-only'
        else:
            return 'read-write'


class DynamicMMIOMonitor:
    """真正的动态MMIO监测器"""

    # STM32F1 MMIO模块定义
    MMIO_MODULES = {
        'UART1': (0x40011000, 0x40011100),
        'UART2': (0x40004400, 0x40004500),
        'UART3': (0x40004800, 0x40004900),
        'GPIO_A': (0x40010800, 0x40010900),
        'GPIO_B': (0x40010C00, 0x40010D00),
        'GPIO_C': (0x40013800, 0x40013900),
        'GPIO_D': (0x40014400, 0x40014500),
        'GPIO_E': (0x40014800, 0x40014900),
        'TIM1': (0x40012C00, 0x40012D00),
        'TIM2': (0x40000000, 0x40000100),
        'TIM3': (0x40000400, 0x40000500),
        'TIM4': (0x40000800, 0x40000900),
        'RCC': (0x40021000, 0x40021100),
        'ADC1': (0x40012400, 0x40012500),
        'SPI1': (0x40013000, 0x40013100),
        'SPI2': (0x40003800, 0x40003900),
        'I2C1': (0x40005400, 0x40005500),
        'I2C2': (0x40005800, 0x40005900),
        'DMA1': (0x40020000, 0x40020C00),
        'DMA2': (0x40020400, 0x40020800),
        'AFIO': (0x40010000, 0x40010100),
        'EXTI': (0x40010400, 0x40010500),
    }

    # MMIO范围
    MMIO_START = 0x40000000
    MMIO_END = 0x60000000

    def __init__(self):
        """初始化监测器"""
        self.accesses: List[MMIOAccess] = []  # 所有访问记录
        self.addresses: Dict[int, MMIOAddress] = {}  # 按地址统计
        self.access_count = 0

    def is_mmio(self, address: int) -> bool:
        """检查是否是MMIO地址"""
        return self.MMIO_START <= address < self.MMIO_END

    def get_module_name(self, address: int) -> str:
        """获取地址对应的模块名"""
        for module, (start, end) in self.MMIO_MODULES.items():
            if start <= address < end:
                return module
        return 'UNKNOWN'

    def record_access(self, address: int, value: int, operation: str, pc: int, size: int = 4):
        """
        记录一次MMIO访问

        Args:
            address: 访问地址
            value: 读/写的值
            operation: 'read' 或 'write'
            pc: 指令地址
            size: 访问大小（字节）
        """
        if not self.is_mmio(address):
            return

        # 转换操作类型
        op = AccessType.READ if operation == 'read' else AccessType.WRITE

        # 创建访问记录
        access = MMIOAccess(
            address=address,
            value=value,
            operation=op,
            pc=pc,
            size=size,
            timestamp=self.access_count
        )

        self.accesses.append(access)
        self.access_count += 1

        # 按地址统计
        if address not in self.addresses:
            module = self.get_module_name(address)
            offset = address & 0xFFFF  # 模块内的偏移
            self.addresses[address] = MMIOAddress(
                address=address,
                module=module,
                offset=offset
            )

        addr_info = self.addresses[address]

        if op == AccessType.READ:
            addr_info.read_count += 1
        else:
            addr_info.write_count += 1

        addr_info.values.add(value)

        # 记录访问点
        addr_info.access_points.append({
            'pc': hex(pc),
            'op': operation,
            'value': hex(value),
            'size': size
        })

    def get_summary(self) -> Dict:
        """获取摘要统计"""
        by_module = defaultdict(lambda: {
            'count': 0,
            'reads': 0,
            'writes': 0,
            'addresses': 0
        })

        for addr_info in self.addresses.values():
            module = addr_info.module
            by_module[module]['count'] += addr_info.total_accesses
            by_module[module]['reads'] += addr_info.read_count
            by_module[module]['writes'] += addr_info.write_count
            by_module[module]['addresses'] += 1

        return {
            'total_accesses': len(self.accesses),
            'total_addresses': len(self.addresses),
            'by_module': dict(sorted(by_module.items())),
        }

    def get_addresses(self) -> List[Dict]:
        """获取MMIO地址列表（按访问频率排序）"""
        addresses = list(self.addresses.values())
        addresses.sort(key=lambda x: x.total_accesses, reverse=True)

        result = []
        for addr_info in addresses:
            result.append({
                'address': hex(addr_info.address),
                'module': addr_info.module,
                'offset': hex(addr_info.offset),
                'reads': addr_info.read_count,
                'writes': addr_info.write_count,
                'total': addr_info.total_accesses,
                'type': addr_info.access_type,
                'values': sorted([hex(v) for v in list(addr_info.values)[:10]]),
            })

        return result

    def print_report(self, limit: int = 20):
        """打印详细报告"""
        summary = self.get_summary()

        logger.info("\n" + "=" * 80)
        logger.info("动态MMIO监测报告")
        logger.info("=" * 80)

        logger.info(f"\n[总体统计]")
        logger.info(f"  总访问数: {summary['total_accesses']}")
        logger.info(f"  独特地址: {summary['total_addresses']}")

        logger.info(f"\n[按模块分布]")
        for module, stats in summary['by_module'].items():
            logger.info(
                f"  {module:12s}: {stats['count']:6d} accesses "
                f"(R:{stats['reads']:4d}, W:{stats['writes']:4d}, "
                f"A:{stats['addresses']:3d} addr)"
            )

        logger.info(f"\n[高频MMIO地址 (前{limit}个)]")
        addresses = self.get_addresses()
        for i, addr_info in enumerate(addresses[:limit], 1):
            logger.info(
                f"  {i:2d}. {addr_info['address']:10s} ({addr_info['module']:12s}): "
                f"R={addr_info['reads']:4d}, W={addr_info['writes']:4d}, "
                f"Type={addr_info['type']:12s}"
            )
            if addr_info['values']:
                logger.info(f"       Values: {', '.join(addr_info['values'][:5])}")

        logger.info("\n" + "=" * 80)

    def export_json(self, filename: str):
        """导出为JSON格式"""
        summary = self.get_summary()
        addresses = self.get_addresses()

        data = {
            'summary': summary,
            'addresses': addresses,
            'total_records': len(self.accesses)
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"✓ 导出到 {filename}")

    def get_recommended_values(self) -> Dict[str, int]:
        """
        生成推荐的MMIO值

        规则：
        1. 对于读寄存器，优先使用最常见的值
        2. 对于写寄存器，使用0（默认）
        3. 对于状态寄存器，使用"就绪"标记位
        """
        recommendations = {}

        for addr, addr_info in self.addresses.items():
            if addr_info.read_count == 0:
                continue

            if addr_info.values:
                most_common = max(addr_info.values, key=lambda v: sum(1 for a in self.accesses if a.value == v and a.operation == AccessType.READ))
                recommendations[hex(addr)] = most_common
            else:
                recommendations[hex(addr)] = 0

        return recommendations
