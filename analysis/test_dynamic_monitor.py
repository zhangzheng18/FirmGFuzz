#!/usr/bin/env python3
"""
动态MMIO监测器测试脚本
"""

import sys
import logging
from dynamic_mmio_monitor import DynamicMMIOMonitor

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def test_basic_recording():
    """测试基本的MMIO记录"""
    logger.info("\n" + "="*80)
    logger.info("测试1: 基本MMIO记录")
    logger.info("="*80)

    monitor = DynamicMMIOMonitor()

    # 模拟UART访问
    logger.info("\n添加UART1访问...")
    monitor.record_access(0x40011000, 0xC0, 'read', 0x08000100)
    monitor.record_access(0x40011000, 0xC0, 'read', 0x08000102)
    monitor.record_access(0x40011000, 0x80, 'read', 0x08000104)
    monitor.record_access(0x40011004, 0xAA, 'write', 0x08000106)

    # 模拟GPIO访问
    logger.info("添加GPIO_A访问...")
    monitor.record_access(0x40010800, 0x1234, 'write', 0x08000200)
    monitor.record_access(0x40010808, 0x5678, 'read', 0x08000202)
    monitor.record_access(0x40010800, 0x1234, 'read', 0x08000204)

    # 模拟TIM2访问
    logger.info("添加TIM2访问...")
    for i in range(10):
        monitor.record_access(0x40000000, 0x0001, 'write', 0x08000300 + i*2)
        monitor.record_access(0x40000004, 0x0000, 'read', 0x08000400 + i*2)

    # 检查结果
    summary = monitor.get_summary()
    logger.info(f"\n✓ 记录了 {summary['total_accesses']} 次访问")
    logger.info(f"✓ 发现 {summary['total_addresses']} 个MMIO地址")

    # 4 + 3 + 20 = 27 次访问
    assert summary['total_accesses'] == 27, f"期望27次访问，得到{summary['total_accesses']}"
    # UART1 SR, UART1 DR, GPIO_A CRL, GPIO_A IDR, TIM2 CR1, TIM2 CNT = 6个地址
    assert summary['total_addresses'] == 6, f"期望6个地址，得到{summary['total_addresses']}"

    logger.info("✓ 测试1通过")
    return True


def test_module_detection():
    """测试模块检测"""
    logger.info("\n" + "="*80)
    logger.info("测试2: 模块检测")
    logger.info("="*80)

    monitor = DynamicMMIOMonitor()

    test_cases = [
        (0x40011000, 'UART1'),
        (0x40010800, 'GPIO_A'),
        (0x40000000, 'TIM2'),
        (0x40021000, 'RCC'),
        (0x50000000, 'UNKNOWN'),  # 超出范围
    ]

    logger.info("\n检测模块...")
    for addr, expected_module in test_cases:
        monitor.record_access(addr, 0, 'read', 0x08000000)
        actual_module = monitor.get_module_name(addr)
        logger.info(f"  0x{addr:08x} → {actual_module:12s} (expected: {expected_module})")
        assert actual_module == expected_module, f"地址0x{addr:08x}应该是{expected_module}，但是{actual_module}"

    logger.info("✓ 测试2通过")
    return True


def test_report_generation():
    """测试报告生成"""
    logger.info("\n" + "="*80)
    logger.info("测试3: 报告生成")
    logger.info("="*80)

    monitor = DynamicMMIOMonitor()

    # 添加测试数据
    logger.info("\n添加测试数据...")
    for i in range(100):
        monitor.record_access(0x40011000, 0xC0 + (i % 4), 'read', 0x08000000 + i)
    for i in range(50):
        monitor.record_access(0x40011004, 0xAA + (i % 2), 'write', 0x08001000 + i)

    # 生成报告
    logger.info("\n生成报告...")
    monitor.print_report(limit=5)

    # 检查数据
    summary = monitor.get_summary()
    assert summary['total_accesses'] == 150
    assert summary['total_addresses'] == 2

    logger.info("\n✓ 测试3通过")
    return True


def test_json_export():
    """测试JSON导出"""
    logger.info("\n" + "="*80)
    logger.info("测试4: JSON导出")
    logger.info("="*80)

    monitor = DynamicMMIOMonitor()

    # 添加数据
    for i in range(10):
        monitor.record_access(0x40011000, i, 'read', 0x08000000 + i)

    # 导出
    logger.info("\n导出JSON...")
    monitor.export_json('/tmp/mmio_test.json')

    # 验证文件
    import json
    with open('/tmp/mmio_test.json', 'r') as f:
        data = json.load(f)

    assert 'summary' in data
    assert 'addresses' in data
    assert data['total_records'] == 10

    logger.info("✓ 测试4通过")
    return True


def test_recommended_values():
    """测试推荐值生成"""
    logger.info("\n" + "="*80)
    logger.info("测试5: 推荐值生成")
    logger.info("="*80)

    monitor = DynamicMMIOMonitor()

    # 添加读访问
    logger.info("\n添加读访问...")
    monitor.record_access(0x40011000, 0xC0, 'read', 0x08000000)
    monitor.record_access(0x40011000, 0xC0, 'read', 0x08000002)
    monitor.record_access(0x40011000, 0x80, 'read', 0x08000004)

    # 生成推荐值
    logger.info("\n生成推荐值...")
    recommendations = monitor.get_recommended_values()

    logger.info(f"推荐值: {recommendations}")

    assert len(recommendations) > 0
    logger.info("✓ 测试5通过")
    return True


def test_access_patterns():
    """测试不同访问模式的识别"""
    logger.info("\n" + "="*80)
    logger.info("测试6: 不同访问模式")
    logger.info("="*80)

    monitor = DynamicMMIOMonitor()

    logger.info("\n模拟不同的访问模式...")

    # 模式1: 基址 + 偏移 [r1, #0x14]
    logger.info("  模式1: 基址 + 偏移")
    monitor.record_access(0x40010814, 0x00, 'read', 0x08000100)  # GPIO_A + 0x14

    # 模式2: 寄存器间接 [r1]
    logger.info("  模式2: 寄存器间接")
    monitor.record_access(0x40010800, 0x12, 'read', 0x08000102)  # GPIO_A base

    # 模式3: 基址 + 索引 [r1, r2]
    logger.info("  模式3: 基址 + 索引")
    monitor.record_access(0x40010808, 0x34, 'read', 0x08000104)  # GPIO_A + offset

    # 模式4: 前/后索引 [r1, #4]!
    logger.info("  模式4: 前/后索引")
    monitor.record_access(0x40010804, 0x56, 'read', 0x08000106)
    monitor.record_access(0x40010808, 0x78, 'read', 0x08000108)

    summary = monitor.get_summary()
    logger.info(f"\n✓ 识别了 {summary['total_accesses']} 次访问")
    logger.info(f"✓ 发现了 {summary['total_addresses']} 个不同的地址")

    logger.info("\n[访问地址详情]")
    for addr in sorted(monitor.addresses.keys()):
        addr_info = monitor.addresses[addr]
        logger.info(f"  0x{addr:08x}: R={addr_info.read_count}, W={addr_info.write_count}")

    assert summary['total_accesses'] == 5
    assert summary['total_addresses'] == 4  # 0x40010800, 0x40010804, 0x40010808, 0x40010814

    logger.info("✓ 测试6通过")
    return True


def main():
    """运行所有测试"""
    logger.info("\n" + "#"*80)
    logger.info("# 动态MMIO监测器测试")
    logger.info("#"*80)

    tests = [
        ('基本记录', test_basic_recording),
        ('模块检测', test_module_detection),
        ('报告生成', test_report_generation),
        ('JSON导出', test_json_export),
        ('推荐值', test_recommended_values),
        ('访问模式', test_access_patterns),
    ]

    results = []
    for name, test_func in tests:
        try:
            if test_func():
                results.append((name, 'PASS'))
        except Exception as e:
            logger.error(f"\n✗ {name}失败: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, 'FAIL'))

    # 总结
    logger.info("\n" + "#"*80)
    logger.info("# 测试总结")
    logger.info("#"*80)

    for name, result in results:
        status = '✓' if result == 'PASS' else '✗'
        logger.info(f"{status} {name}: {result}")

    passed = sum(1 for _, r in results if r == 'PASS')
    total = len(results)

    logger.info(f"\n总计: {passed}/{total} 通过")
    logger.info("\n" + "="*80)

    return all(r == 'PASS' for _, r in results)


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
