import os
import pathlib
import time
import random
import threading
import traceback
import anyio
from typing import Optional, List, Dict, Any, Tuple

# 模拟相关模块
class VmExit:
    def __init__(self, value):
        self.value = value

class Vm:
    def __init__(self):
        self.icount_limit = None
        self.interrupt_flag = False
        self.cpu = Cpu()

class Cpu:
    def __init__(self):
        self.icount = 0
        self.read_pc = lambda: 0

class CortexmMultiStream:
    def __init__(self):
        pass

    def run(self, vm):
        return VmExit(None)

    def get_mmio_handler(self, vm):
        return None

    def initialize_vm(self, config, vm):
        pass

    def fuzzware_init(self, firmware, vm, multi_stream):
        pass

class Snapshot:
    def __init__(self):
        self.vm = None
        self.coverage = None
        self.tracer = None

    def capture(fuzzer):
        return Snapshot()

    def restore(self, fuzzer):
        pass

    def restore_initial(fuzzer):
        pass

class State:
    def __init__(self):
        self.parent = None
        self.mutation_kinds = []
        self.input = None
        self.is_import = False
        self.exit = VmExit(None)
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
        pass

class BlockCoverageTracker:
    def __init__(self):
        pass

    def add_new(self, code, input_id):
        pass

    def maybe_save(self, path):
        pass

class CrashLogger:
    def __init__(self, config):
        pass

    def is_new(self, vm, exit):
        return False

    def save(self, state, vm, target, exit):
        pass

    def new(config):
        return CrashLogger(None)

class GlobalQueue:
    def __init__(self, size):
        pass

    def init(size):
        return GlobalQueue(size)

    def add_new(self, id, input):
        pass

class GlobalRef:
    def __init__(self, id, global_queue, monitor):
        self.id = id
        self.global_queue = global_queue
        self.monitor = monitor

    def clone_with_id(self, id):
        return GlobalRef(id, self.global_queue, self.monitor)

    def is_main_instance(self):
        return False

    def is_worker_instance(self):
        return False

    def add_crash_or_hang(self, key, crash_kind):
        return False

    def add_for_main(self, input):
        pass

    def take_all(self):
        return []

class Dictionary:
    def __init__(self):
        pass

    def add_item(self, item, value):
        pass

    def compute_weights(self):
        pass

class MultiStreamDict:
    def __init__(self):
        pass

class CorpusStore:
    def __init__(self):
        self.data = []
        self.inputs = 0

    def __getitem__(self, index):
        return self.data[index]

    def __len__(self):
        return len(self.data)

    def add_new(self, input):
        self.data.append(input)

    def maybe_save(self, workdir):
        return None

    def recompute_input_prioritization(self):
        pass

class CoverageAny:
    def __init__(self):
        pass

    def snapshot_local(self, vm):
        return None

    def restore_local(self, vm, coverage):
        pass

    def new_bits(self, vm):
        return []

    def get_bits(self, vm):
        return []

    def merge(self, vm):
        pass

    def count(self):
        return 0

class PathTracerRef:
    def __init__(self):
        pass

    def snapshot(self, vm):
        return None

    def restore(self, vm, snapshot):
        pass

class Config:
    def __init__(self, fuzzer_config, workdir, firmware_config, interrupt_flag):
        self.fuzzer = fuzzer_config
        self.workdir = workdir
        self.firmware = firmware_config
        self.interrupt_flag = interrupt_flag

class EnabledFeatures:
    def __init__(self):
        pass

    @classmethod
    def from_env(cls):
        return EnabledFeatures()

class DebugSettings:
    def __init__(self):
        pass

    @classmethod
    def from_env(cls):
        return DebugSettings()

def add_ctrlc_handler():
    return False

def configure_coverage(fuzzer_config, vm):
    return CoverageAny()

def setup_vm(config, features):
    target = CortexmMultiStream()
    vm = Vm()
    return target, vm

def fuzzing_loop(fuzzer, run_for):
    start_time = time.time()
    stats = LocalStats()
    while not fuzzer.vm.interrupt_flag and (run_for is None or time.time() - start_time < run_for):
        fuzzer.input_id = fuzzer.queue.next_input()
        length_ext_prob = 0.9
        if fuzzer.input_id is not None:
            input_data = fuzzer.corpus[fuzzer.input_id]
            is_import = input_data.is_import
            has_unique_edge = input_data.has_unique_edge
            if not input_data.favored and random.random() < 0.95:
                continue
            if input_data.stage_data.get(Stage.Trim) is None:
                input_data.stage_data[Stage.Trim] = None
                fuzzer.stage = Stage.Trim
                if fuzzer.features.smart_trim and not is_import:
                    trim_stage(fuzzer, stats)
                    if has_unique_edge:
                        fuzzer.global.add_new(fuzzer.state.input.copy())
            if fuzzer.features.cmplog and not is_import:
                if input_data.stage_data.get(Stage.InputToState) is None:
                    input_data.stage_data[Stage.InputToState] = None
                    fuzzer.stage = Stage.Colorization
                    colorization_stage(fuzzer, stats)
                    fuzzer.stage = Stage.InputToState
                    i2s_replace_stage(fuzzer, stats)
            input_data.metadata.rounds += 1
            length_ext_prob = input_data.length_extension_prob()
        stage_exit = None
        if not fuzzer.features.havoc or random.random() < length_ext_prob:
            fuzzer.stage = Stage.MultiStreamExtend
            stage_exit = multi_stream_extend_stage(fuzzer, stats)
        else:
            fuzzer.stage = Stage.Havoc
            stage_exit = havoc_stage(fuzzer, stats)
        if stage_exit == StageExit.Finished:
            continue
        elif stage_exit in [StageExit.Error, StageExit.Interrupted]:
            break
        elif stage_exit == StageExit.Unsupported:
            pass
        new_inputs = fuzzer.corpus.inputs() - fuzzer.re_prioritization_inputs
        if (fuzzer.re_prioritization_cycle!= fuzzer.queue.cycles and new_inputs!= 0) or new_inputs > 20:
            fuzzer.corpus.recompute_input_prioritization()
            fuzzer.re_prioritization_cycle = fuzzer.queue.cycles
            fuzzer.re_prioritization_inputs = fuzzer.corpus.inputs()
        fuzzer.stage = Stage.Import
        if sync_stage(fuzzer, stats) == StageExit.Interrupted:
            break
    if fuzzer.global.is_main_instance():
        print("Fuzzing stopped, saving data")
        fuzzer.corpus.maybe_save(fuzzer.workdir)
        with open(fuzzer.workdir.join("disasm.asm"), "w") as f:
            pass
        coverage = ""
        fuzzer.coverage.serialize(fuzzer.vm, coverage)
        with open(fuzzer.workdir.join("coverage"), "w") as f:
            f.write(coverage)
    return None

def run():
    if os.environ.get("GENCONFIG"):
        return None
    if os.environ.get("FORCE_GENCONFIG"):
        return None
    os.environ.setdefault("GHIDRA_SRC", "./ghidra")
    fuzzer_config = FuzzConfig.load()
    if os.environ.get("ICICLE_ENABLE_SHADOW_STACK") is None:
        fuzzer_config.enable_shadow_stack = False
    if os.environ.get("COVERAGE_MODE") is None:
        fuzzer_config.coverage_mode = CoverageMode.Blocks
    interrupt_flag = add_ctrlc_handler()
    if os.environ.get("P2IM_UNIT_TESTS"):
        return None
    config_arg = None
    if len(sys.argv) > 1:
        config_arg = sys.argv[1]
    firmware_config = None
    if config_arg is None or config_arg == "":
        firmware_config = FirmwareConfig.from_env()
    else:
        firmware_config = FirmwareConfig.from_path(config_arg)
    workdir = pathlib.Path(os.environ.get("WORKDIR", "./workdir"))
    config = Config(fuzzer_config, workdir, firmware_config, interrupt_flag)
    if os.environ.get("REPLAY"):
        return None
    if os.environ.get("ANALYZE_CRASHES"):
        return None
    if os.environ.get("RUN_I2S_STAGE"):
        return None
    if os.environ.get("GEN_BLOCK_COVERAGE"):
        pass
    print("Starting fuzzer")
    _workdir_lock = init_workdir(config)
    global_queue = GlobalQueue.init(config.fuzzer.workers)
    if config.fuzzer.resume:
        for entry in os.listdir(config.workdir.join("imports")):
            path = pathlib.Path(entry)
            if path.is_file():
                input_data = MultiStream.from_path(path)
                if input_data is not None:
                    global_queue.add_new(None, input_data)
    monitor = GlobalRef(None, global_queue, None)
    global_ref = GlobalRef(0, global_queue, None)
    with anyio.create_task_group() as s:
        for id in range(1, config.fuzzer.workers):
            print(f"spawning worker: {id}")
            new_config = config.copy()
            new_global = global_ref.clone_with_id(id)
            s.start_soon(fuzzer_loop, Fuzzer(new_config, new_global))
            time.sleep(0.1)
        # Run the primary worker on the current thread (this helps for debugging and profiling).
        fuzzer_loop(Fuzzer(config, global_ref))
    return None

class Fuzzer:
    def __init__(self, config, global_ref):
        self.workdir = config.workdir
        self.vm = None
        self.target = None
        self.snapshot = Snapshot()
        self.queue = CoverageQueue()
        self.stage = Stage.MultiStreamExtend
        self.rng = random.Random()
        self.corpus = CorpusStore()
        self.input_id = None
        self.state = State()
        self.coverage = CoverageAny()
        self.crash_logger = CrashLogger(config)
        self.config = config.fuzzer
        self.global = global_ref
        self.path_tracer = None
        self.cmplog = None
        self.seen_blocks = BlockCoverageTracker()
        self.execs = 0
        self.last_find = 0
        self.dict = {}
        self.global_dict = Dictionary()
        self.dict_items = 0
        self.re_prioritization_cycle = 0
        self.re_prioritization_inputs = 0
        self.features = EnabledFeatures.from_env()
        self.debug = DebugSettings.from_env()

    def copy_current_input(self):
        self.state.reset()
        self.state.parent = self.input_id
        if self.input_id is not None:
            self.state.input = self.corpus[self.input_id].data.copy()
        else:
            random_input(self)

    def execute(self):
        return None

    def execute_with_limit(self, limit):
        return None

    def check_exit_state(self, exit):
        if self.state.input.total_bytes() == 0:
            return None
        self.state.exit_address = self.vm.cpu.read_pc()
        crash_kind = CrashKind.from(exit)
        if not crash_kind.is_crash():
            self.state.new_bits = self.coverage.new_bits(self.vm)
            self.state.new_coverage = len(self.state.new_bits) > 0
            if self.state.new_coverage:
                if VALIDATE:
                    validate_last_exec(self, 0, exit)
                bits = self.coverage.get_bits(self.vm)
                self.state.coverage_bits = count_all_bits(bits)
                self.state.hit_coverage = [bit for bit in bit_iter(bits)]
                self.coverage.merge(self.vm)
            elif self.features.add_favored_inputs and self.queue.new_inputs() == 0 and self.stage!= Stage.Trim and random.random() < 0.01:
                bits = self.coverage.get_bits(self.vm)
                self.state.coverage_bits = count_all_bits(bits)
                self.state.hit_coverage = [bit for bit in bit_iter(bits)]
                if current_state_is_favored(self.state, self.corpus):
                    self.state.new_coverage = True
            if self.queue.add_if_interesting(self.corpus, self.state) is not None:
                self.update_input_metadata(self.queue.add_if_interesting(self.corpus, self.state))
                self.last_find = self.execs
        self.state.mutation_kinds = []
        if crash_kind == CrashKind.Halt:
            return None
        elif crash_kind == CrashKind.Hang:
            self.state.was_hang = True
        else:
            self.state.was_crash = True
        is_locally_unique = self.crash_logger.is_new(self.vm, exit)
        if is_locally_unique:
            key = gen_crash_key(self.vm, exit)
            if self.global.is_worker_instance():
                if crash_kind.is_crash():
                    self.global.add_for_main(self.state.input.copy())
            elif self.global.add_crash_or_hang(key, crash_kind):
                self.crash_logger.save(self.state, self.vm, self.target, exit)
        if VALIDATE_CRASHES:
            validate_last_exec(self, 0, exit)
        return None

    def update_input_metadata(self, id):
        depth = 0 if self.input_id is None else self.corpus[self.input_id].metadata.depth + 1
        input_data = self.corpus[id]
        if self.debug.save_input_coverage:
            pass
        metadata = input_data.metadata
        metadata.parent_id = self.state.parent
        metadata.coverage_bits = self.state.coverage_bits
        metadata.instructions = self.state.instructions
        metadata.depth = depth
        metadata.len = self.state.input.total_bytes()
        metadata.streams = self.state.input.count_non_empty_streams()
        metadata.new_bits = self.state.new_bits.copy()
        metadata.stage = self.stage
        metadata.mutation_kinds = self.state.mutation_kinds.copy()

    def update_stats(self, stats):
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
        return 1.0 if self.input_id is None else self.corpus[self.input_id].stage_data.get(Stage.MultiStreamExtend, {}).get("extension_factor", {}).get(key, 1.0)

    def execs_since_last_find(self):
        return self.execs - self.last_find

class StageExit:
    Finished = "Finished"
    Interrupted = "Interrupted"
    Unsupported = "Unsupported"
    Error = "Error"

class Stage:
    Import = "Import"
    Havoc = "Havoc"
    MultiStreamExtend = "MultiStreamExtend"
    MultiStreamExtendI2S = "MultiStreamExtendI2S"
    Trim = "Trim"
    Colorization = "Colorization"
    InputToState = "InputToState"

    @staticmethod
    def short_name(stage):
        if stage == Stage.Import:
            return "imp"
        elif stage == Stage.Havoc:
            return "hav"
        elif stage == Stage.MultiStreamExtend:
            return "ext"
