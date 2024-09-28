import os
import pathlib
import time
import random
import threading
import traceback
from typing import Optional

# 模拟 Rust 的日志模块
class Logging:
    def __init__(self):
        self.log_writer = None
        if 'ICICLE_LOG_ADDR' in os.environ:
            addr = os.environ['ICICLE_LOG_ADDR']
            # 这里只是模拟 UDP 写入，实际需要实现 UDP 写入逻辑
            self.log_writer = lambda msg: print(f"Writing to UDP: {msg} ({addr})")
        else:
            self.log_writer = lambda msg: print(f"Writing to stderr: {msg}", file=sys.stderr)

    def init(self):
        pass

logging = Logging()

class MutationKind:
    def __init__(self, stream, kind):
        self.stream = stream
        self.kind = kind

class State:
    def __init__(self):
        self.parent = None
        self.mutation_kinds = []
        self.input = None
        self.is_import = False
        self.exit = None
        self.exit_address = 0
        self.new_coverage = False
        self.was_crash = False
        self.was_hang = False
        self.exec_time = 0
        self.instructions = 0
        self.coverage_bits = 0
        self.new_bits = []
        self.hit_coverage = []

    def reset(self):
        self.parent = None
        self.mutation_kinds.clear()
        self.input = None
        self.is_import = False
        self.exit = None
        self.exit_address = 0
        self.new_coverage = False
        self.was_crash = False
        self.was_hang = False
        self.exec_time = 0
        self.instructions = 0
        self.coverage_bits = 0
        self.hit_coverage.clear()

class Snapshot:
    def __init__(self, vm, coverage, tracer):
        self.vm = vm
        self.coverage = coverage
        self.tracer = tracer

def setup_vm(config, features):
    # 这里只是模拟设置虚拟机的过程
    target = None
    vm = None
    return target, vm

class Fuzzer:
    def __init__(self, config, global):
        self.workdir = config.workdir
        target, vm = setup_vm(config, global.features)
        self.vm = vm
        self.target = target
        self.rng = random.Random()
        if 'SEED' in os.environ:
            seed = int(os.environ['SEED'])
            self.rng.seed(seed)
        else:
            self.rng.seed(time.time())
        self.snapshot = None
        self.stage = None
        self.corpus = []
        self.queue = None
        self.input_id = None
        self.state = State()
        self.coverage = None
        self.crash_logger = None
        self.config = config.fuzzer
        self.global = global
        self.path_tracer = None
        self.cmplog = None
        self.seen_blocks = None
        self.execs = 0
        self.last_find = 0
        self.dict = {}
        self.global_dict = None
        self.dict_items = 0
        self.re_prioritization_cycle = 0
        self.re_prioritization_inputs = 0
        self.features = global.features
        self.debug = None

    def copy_current_input(self):
        self.state.reset()
        self.state.parent = self.input_id
        if self.input_id is not None:
            self.state.input = self.corpus[self.input_id].data.copy()
        else:
            # 模拟随机输入
            self.state.input = self.generate_random_input()

    def execute(self):
        # 模拟执行虚拟机并返回退出状态
        exit = None
        return exit

    def execute_with_limit(self, limit):
        # 模拟执行虚拟机并返回退出状态
        exit = None
        return exit

    def check_exit_state(self, exit):
        if self.state.input is None or len(self.state.input) == 0:
            # 丢弃零长度输入
            self.state.mutation_kinds.clear()
            return None

        self.state.exit_address = 0
        # 模拟判断崩溃类型
        crash_kind = None
        if not crash_kind.is_crash():
            # 更新覆盖信息等
            self.state.new_bits = []
            self.state.new_coverage = False
            if self.state.new_coverage:
                # 模拟验证执行
                pass
            if self.queue.add_if_interesting(self.corpus, self.state):
                self.update_input_metadata(self.input_id)
                self.last_find = self.execs
        else:
            self.state.was_crash = True
            self.state.was_hang = False

        # 清除突变事件记录
        self.state.mutation_kinds.clear()

        if crash_kind.is_crash():
            # 模拟判断是否为新的崩溃并保存
            is_locally_unique = False
            if is_locally_unique:
                # 模拟发送崩溃信息给主进程
                pass
            else:
                # 模拟添加崩溃或挂起信息
                pass
            if self.debug.save_input_coverage:
                pass
        return None

    def update_input_metadata(self, id):
        depth = 0
        if self.input_id is not None:
            depth = self.corpus[self.input_id].metadata.depth + 1

        input_data = self.corpus[id]
        # 模拟更新输入元数据
        input_data.metadata.parent_id = self.state.parent
        input_data.metadata.coverage_bits = self.state.coverage_bits
        input_data.metadata.instructions = self.state.instructions
        input_data.metadata.depth = depth
        input_data.metadata.len = len(self.state.input)
        input_data.metadata.streams = 0
        input_data.metadata.new_bits = self.state.new_bits.copy()
        input_data.metadata.stage = self.stage
        input_data.metadata.mutation_kinds = self.state.mutation_kinds.copy()

    def update_stats(self, stats):
        # 模拟更新统计信息
        stats.update(self)
        if self.input_id is not None:
            metadata = self.corpus[self.input_id].metadata
            metadata.time += self.state.exec_time
            metadata.execs += 1
            metadata.max_find_gap = max(metadata.max_find_gap, metadata.execs - metadata.last_find)
            if self.state.was_crash:
                metadata.crashes += 1
            if self.state.was_hang:
                metadata.hangs += 1
            if self.state.new_coverage:
                metadata.finds += 1
                metadata.last_find = metadata.execs

    def reset_input_cursor(self):
        return None

    def write_input_to_target(self):
        return None

    def auto_trim_input(self):
        return None

    def get_extension_factor(self, key):
        if not self.features.extension_factor:
            return 2.0
        if self.input_id is None:
            return 1.0
        return self.corpus[self.input_id].stage_data.extension_factor(key)

    def execs_since_last_find(self):
        return self.execs - self.last_find

class StageExit:
    def __init__(self, value):
        self.value = value

class Stage:
    IMPORT = 0
    HAVOC = 1
    MULTI_STREAM_EXTEND = 2
    MULTI_STREAM_EXTEND_I2S = 3
    TRIM = 4
    COLORIZATION = 5
    INPUT_TO_STATE = 6

    @staticmethod
    def short_name(stage):
        names = {
            Stage.IMPORT: 'imp',
            Stage.HAVOC: 'hav',
            Stage.MULTI_STREAM_EXTEND: 'ext',
            Stage.MULTI_STREAM_EXTEND_I2S: 'ex2',
            Stage.TRIM: 'trm',
            Stage.COLORIZATION: 'col',
            Stage.INPUT_TO_STATE: 'i2s',
        }
        return names.get(stage, None)

class StageStartError:
    UNSUPPORTED = 0
    SKIP = 1
    INTERRUPTED = 2
    UNKNOWN = 3

class SyncStage:
    def __init__(self):
        self.inputs = []
        self.total = 0
        self.interesting = 0
        self.current_input_id = 0

    def start(self, fuzzer):
        # 模拟从全局获取输入并打乱
        inputs = fuzzer.global.take_all()
        if fuzzer.global.is_main_instance() and len(inputs) > 0:
            random.shuffle(inputs)
        self.inputs = inputs
        self.total = len(inputs)
        return self

    def fuzz_one(self, fuzzer):
        if not self.inputs:
            return None
        id, input_data = self.inputs.pop()
        self.current_input_id = id

        # 模拟恢复初始状态
        fuzzer.state.reset()
        fuzzer.state.is_import = True
        fuzzer.state.input = input_data.copy()
        fuzzer.reset_input_cursor()
        fuzzer.write_input_to_target()
        exit = fuzzer.execute()
        fuzzer.auto_trim_input()
        return exit

    def after_check(self, fuzzer, interesting):
        if interesting:
            self.interesting += 1

        if fuzzer.global.is_main_instance():
            # DEBUGGING:
            bits = None
            coverage_bits = 0
            print(f"sync {self.current_input_id}: bits={coverage_bits}, new bits={fuzzer.state.new_bits}")

    def end(self, fuzzer):
        if fuzzer.global.is_main_instance() and self.total!= 0:
            print(f"{self.interesting} out of {self.total} inputs from external fuzzers were interesting")

def calculate_energy(fuzzer):
    if fuzzer.input_id is None:
        return 100

    if fuzzer.features.simple_energy_assignment:
        energy = 100
        if fuzzer.corpus[fuzzer.input_id].has_unique_edge:
            energy *= 5
        return energy

    energy = 100.0

    # 模拟根据输入属性和全局统计信息调整能量
    total_inputs = len(fuzzer.corpus)
    average_input_size = 0
    global_find_rate = 0.0

    input_data = fuzzer.corpus[fuzzer.input_id]

    # 根据输入大小调整能量
    if len(fuzzer.state.input) < average_input_size * 0.5:
        energy *= 1.5
    elif len(fuzzer.state.input) < average_input_size:
        energy *= 1.1
    elif len(fuzzer.state.input) < average_input_size * 2:
        energy *= 0.9
    else:
        energy *= 0.5

    # 根据深度调整能量
    energy *= (1.05 ** input_data.metadata.depth).min(4.0)

    # 根据最近找到新覆盖的情况调整能量
    if input_data.metadata.execs - input_data.metadata.last_find < 1000 * 100:
        energy *= 2.0

    # 根据找到率调整能量
    input_find_rate = input_data.metadata.finds / input_data.metadata.execs
    if input_find_rate > global_find_rate:
        energy *= 1.5

    # 根据挂起频率调整能量
    if input_data.metadata.hangs / input_data.metadata.execs > 0.2:
        energy *= 0.1

    return round(min(max(energy, 10.0), 100000.0))

class GlobalQueue:
    def __init__(self, size):
        self.items = []
        self.size = size

    def init(self, size):
        return self

    def add_new(self, priority, item):
        self.items.append((priority, item))

    def take_all(self):
        items = self.items.copy()
        self.items.clear()
        return items

class GlobalRef:
    def __init__(self, id, global_queue, monitor):
        self.id = id
        self.global_queue = global_queue
        self.monitor = monitor

    def is_main_instance(self):
        return self.id == 0

    def is_worker_instance(self):
        return self.id!= 0

    def add_for_main(self, item):
        return False

    def add_crash_or_hang(self, key, crash_kind):
        return False

    def clone_with_id(self, id):
        return GlobalRef(id, self.global_queue, self.monitor)

class Monitor:
    def __init__(self):
        pass

class LocalStats:
    def __init__(self):
        pass

    def update(self, fuzzer):
        pass

class Config:
    def __init__(self, fuzzer_config, workdir, firmware_config, interrupt_flag):
        self.fuzzer = fuzzer_config
        self.workdir = workdir
        self.firmware = firmware_config
        self.interrupt_flag = interrupt_flag

def main():
    # 模拟日志初始化
    logging.init()

    if 'GENCONFIG' in os.environ:
        # 模拟生成并保存配置文件
        pass
    elif 'FORCE_GENCONFIG' in os.environ:
        # 模拟生成并保存配置文件
        pass
    elif 'P2IM_UNIT_TESTS' in os.environ:
        # 模拟运行单元测试
        pass
    else:
        fuzzer_config = None
        firmware_config = None
        workdir = pathlib.Path(os.environ.get('WORKDIR', './workdir'))
        interrupt_flag = None
        config = Config(fuzzer_config, workdir, firmware_config, interrupt_flag)

        global_queue = GlobalQueue(None).init(1)
        monitor = Monitor()
        global_ref = GlobalRef(0, global_queue, monitor)

        if 'REPLAY' in os.environ:
            # 模拟回放
            pass
        elif 'ANALYZE_CRASHES' in os.environ:
            # 模拟分析崩溃
            pass
        elif 'RUN_I2S_STAGE' in os.environ:
            # 模拟运行特定阶段
            pass
        elif 'GEN_BLOCK_COVERAGE' in os.environ:
            # 模拟生成块覆盖信息
            pass
        else:
            # 启动模糊测试
            run_fuzzing(config, global_ref)

def run_fuzzing(config, global_ref):
    threads = []
    for id in range(1, config.fuzzer.workers):
        new_config = config.copy()
        new_global_ref = global_ref.clone_with_id(id)
        thread = threading.Thread(target=run_worker, args=(new_config, new_global_ref))
        thread.start()
        threads.append(thread)
        time.sleep(0.1)

    run_worker(config, global_ref)

    for thread in threads:
        thread.join()

def run_worker(config, global_ref):
    fuzzer = Fuzzer(config, global_ref)
    run_for = None
    fuzzing_loop(fuzzer, run_for)

def fuzzing_loop(fuzzer, run_for):
    start_time = time.time()
    stats = LocalStats()
    while True:
        if fuzzer.vm.interrupt_flag or (run_for is not None and time.time() - start_time > run_for):
            break

        fuzzer.input_id = fuzzer.queue.next_input()

        # 默认情况下，对于随机生成的输入，长度扩展概率非常高。如果我们使用来自语料库的输入，则会覆盖此概率。
        length_ext_prob = 0.9

        if fuzzer.input_id is not None:
            input_data = fuzzer.corpus[fuzzer.input_id]

            # 跳过不受欢迎的输入
            if not input_data.favored and random.random() < 0.95:
                continue

            if fuzzer.stage_data_empty(input_data, Stage.TRIM):
                fuzzer.stage = Stage.TRIM
                if fuzzer.features.smart_trim and not input_data.is_import:
                    trim_stage.run(fuzzer, stats)

                    # 在修剪输入后，将其发送给其他工作线程。
                    if input_data.has_unique_edge:
                        fuzzer.global.add_new(fuzzer.state.input.copy())

            if fuzzer.features.cmplog and not input_data.is_import:
                if fuzzer.stage_data_empty(input_data, Stage.INPUT_TO_STATE):
                    fuzzer.stage = Stage.COLORIZATION
                    colorization_stage.run(fuzzer, stats)

                    fuzzer.stage = Stage.INPUT_TO_STATE
                    i2s_replace_stage.run(fuzzer, stats)

            # 如果这是第一次执行长度扩展/混乱阶段，则更新 last_find 以避免由于 i2s 和修剪阶段的执行而导致的过度计数。
            input_data = fuzzer.corpus[fuzzer.input_id]
            if input_data.metadata.rounds == 0:
                input_data.metadata.last_find = input_data.metadata.execs
                input_data.metadata.max_find_gap = 0

            input_data.metadata.rounds += 1
            length_ext_prob = input_data.length_extension_prob()

        stage_exit = None
        if not fuzzer.features.havoc or random.random() < length_ext_prob:
            fuzzer.stage = Stage.MULTI_STREAM_EXTEND
            stage_exit = multi_stream_extend_stage
