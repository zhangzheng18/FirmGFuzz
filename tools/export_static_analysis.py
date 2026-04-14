#!/usr/bin/env python3
"""
静态分析结果导出器

将静态分析结果导出为JSON格式，包括：
- 架构信息
- 机器类型
- MMIO地址和约束
- 函数信息
- 基本块信息
- 外设信息
"""

import json
import sys
import os
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from static_analyzer import StaticAnalyzer, StaticAnalysisResult


def export_to_json(result: StaticAnalysisResult, output_path: str):
    """将静态分析结果导出为JSON"""

    # 构建JSON结构
    data = {
        "metadata": {
            "analyzer_version": "1.0",
            "firmware_path": getattr(result, 'firmware_path', 'unknown'),
        },

        "architecture": {
            "type": getattr(result.arch_info, 'arch', 'unknown') if hasattr(result, 'arch_info') else 'unknown',
            "entry_point": f"0x{getattr(result.arch_info, 'entry', 0):08x}" if hasattr(result, 'arch_info') else '0x00000000',
            "endianness": getattr(result.arch_info, 'endian', 'little') if hasattr(result, 'arch_info') else 'little',
            "word_size": getattr(result.arch_info, 'bits', 32) if hasattr(result, 'arch_info') else 32,
            "machine_type": getattr(result.arch_info, 'machine', 'unknown') if hasattr(result, 'arch_info') else 'unknown',
        },

        "statistics": {
            "total_functions": len(result.functions),
            "total_basic_blocks": result.total_basic_blocks if hasattr(result, 'total_basic_blocks') else sum(len(f.basic_blocks) for f in result.functions.values()),
            "total_instructions": result.total_instructions if hasattr(result, 'total_instructions') else 0,
            "total_mmio_accesses": len(result.mmio_accesses),
            "total_peripherals": len(result.peripherals),
            "dataflow_coverage": f"{result.dataflow_coverage:.2%}" if hasattr(result, 'dataflow_coverage') else "0%",
            "symbolic_coverage": f"{result.symbolic_coverage:.2%}" if hasattr(result, 'symbolic_coverage') else "0%",
        },

        "functions": [],
        "mmio_accesses": [],
        "peripherals": {},
        "constraints": [],
    }

    # 导出函数信息
    for func_addr, func in result.functions.items():
        # 处理基本块（可能是对象或整数）
        basic_blocks_data = []
        for bb in func.basic_blocks:
            if isinstance(bb, int):
                # 如果是整数，只记录地址
                basic_blocks_data.append({
                    "start": f"0x{bb:08x}",
                })
            else:
                # 如果是对象，记录完整信息
                basic_blocks_data.append({
                    "start": f"0x{bb.start_addr:08x}",
                    "end": f"0x{bb.end_addr:08x}" if hasattr(bb, 'end_addr') and bb.end_addr else None,
                    "size": bb.end_addr - bb.start_addr if hasattr(bb, 'end_addr') and bb.end_addr else 0,
                    "successors": [f"0x{s:08x}" for s in bb.successors] if hasattr(bb, 'successors') else [],
                })

        func_data = {
            "address": f"0x{func_addr:08x}",
            "name": func.name or f"sub_{func_addr:08x}",
            "size": func.size if hasattr(func, 'size') else 0,
            "basic_blocks": basic_blocks_data,
            "calls_to": [f"0x{addr:08x}" for addr in func.calls_to] if hasattr(func, 'calls_to') else [],
            "called_by": [f"0x{addr:08x}" for addr in func.called_by] if hasattr(func, 'called_by') else [],
        }
        data["functions"].append(func_data)

    # 导出MMIO访问信息
    mmio_by_address = {}
    for mmio in result.mmio_accesses:
        addr_key = f"0x{mmio.address:08x}"
        if addr_key not in mmio_by_address:
            mmio_by_address[addr_key] = {
                "address": addr_key,
                "reads": [],
                "writes": [],
                "access_count": 0,
            }

        access_info = {
            "instruction": str(mmio.instruction) if hasattr(mmio, 'instruction') else 'unknown',
            "pattern": str(mmio.pattern) if hasattr(mmio, 'pattern') else 'unknown',
        }

        if mmio.is_read:
            mmio_by_address[addr_key]["reads"].append(access_info)
        else:
            mmio_by_address[addr_key]["writes"].append(access_info)

        mmio_by_address[addr_key]["access_count"] += 1

    data["mmio_accesses"] = list(mmio_by_address.values())

    # 按访问次数排序
    data["mmio_accesses"].sort(key=lambda x: x["access_count"], reverse=True)

    # 导出约束信息（从MMIO访问推断）
    constraints = []

    # 约束1：MMIO地址范围
    if data["mmio_accesses"]:
        mmio_addrs = [int(m["address"], 16) for m in data["mmio_accesses"]]
        constraints.append({
            "type": "mmio_range",
            "description": "MMIO地址范围",
            "min_address": f"0x{min(mmio_addrs):08x}",
            "max_address": f"0x{max(mmio_addrs):08x}",
        })

    # 约束2：常见的MMIO地址（访问次数 > 10）
    frequent_mmio = [m for m in data["mmio_accesses"] if m["access_count"] > 10]
    if frequent_mmio:
        constraints.append({
            "type": "frequent_mmio",
            "description": "频繁访问的MMIO地址（可能是关键寄存器）",
            "addresses": [m["address"] for m in frequent_mmio[:10]],
        })

    # 约束3：只读MMIO（只有读操作）
    readonly_mmio = [m for m in data["mmio_accesses"] if m["reads"] and not m["writes"]]
    if readonly_mmio:
        constraints.append({
            "type": "readonly_mmio",
            "description": "只读MMIO地址（可能是状态寄存器）",
            "addresses": [m["address"] for m in readonly_mmio[:10]],
        })

    # 约束4：只写MMIO（只有写操作）
    writeonly_mmio = [m for m in data["mmio_accesses"] if m["writes"] and not m["reads"]]
    if writeonly_mmio:
        constraints.append({
            "type": "writeonly_mmio",
            "description": "只写MMIO地址（可能是控制寄存器）",
            "addresses": [m["address"] for m in writeonly_mmio[:10]],
        })

    # 约束5：写入的常量值
    write_values = {}
    for mmio in data["mmio_accesses"]:
        for write in mmio["writes"]:
            if "value" in write:
                addr = mmio["address"]
                if addr not in write_values:
                    write_values[addr] = []
                write_values[addr].append(write["value"])

    if write_values:
        constraints.append({
            "type": "write_constants",
            "description": "写入MMIO的常量值",
            "values": {addr: list(set(vals)) for addr, vals in write_values.items()},
        })

    data["constraints"] = constraints

    # 写入JSON文件
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"✅ 静态分析结果已导出到: {output_path}")
    print(f"   - 函数数: {len(data['functions'])}")
    print(f"   - MMIO地址数: {len(data['mmio_accesses'])}")
    print(f"   - 外设数: {len(data['peripherals'])}")
    print(f"   - 约束数: {len(data['constraints'])}")


def main():
    if len(sys.argv) < 2:
        print("用法: python3 export_static_analysis.py <firmware.elf> [output.json]")
        sys.exit(1)

    firmware_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else firmware_path.replace('.elf', '_analysis.json')

    print(f"正在分析固件: {firmware_path}")

    # 运行静态分析
    analyzer = StaticAnalyzer(firmware_path, enable_advanced=True)
    result = analyzer.analyze(max_instructions=None)

    # 保存固件路径到结果
    result.firmware_path = firmware_path

    # 导出为JSON
    export_to_json(result, output_path)

    print(f"\n✅ 完成！")
    print(f"   JSON文件: {output_path}")


if __name__ == "__main__":
    main()
