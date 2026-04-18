import asyncio
import time
import sys

# ==========================================
# HEURISTIC CONFIGURATION
# ==========================================
MIN_CONCURRENCY   = 50
MAX_CONCURRENCY   = 5000
INITIAL_CONCURRENCY = 1000
HEURISTIC_INTERVAL = 2.0   # seconds between speed adjustments
CONNECT_TIMEOUT    = 1.5   # seconds per port attempt
HIGH_TIMEOUT_RATE  = 0.20  # >20% timeouts -> slow down
LOW_TIMEOUT_RATE   = 0.05  # <5%  timeouts -> speed up
SPEED_STEP         = 200   # how much to increase/decrease concurrency per tick


def concurrency_to_timing(avg_concurrency):
    """Maps average concurrency to an Nmap -T flag string."""
    if avg_concurrency >= 2000: return "-T5"
    if avg_concurrency >= 1000: return "-T4"
    if avg_concurrency >= 500:  return "-T3"
    return "-T2"


# ==========================================
# SHARED STATE
# ==========================================
class HeuristicState:
    def __init__(self, initial_concurrency):
        self.concurrency      = initial_concurrency
        self.lock             = asyncio.Lock()

        # Counters (reset each heuristic tick)
        self.tick_attempts    = 0
        self.tick_timeouts    = 0

        # Overall counters for display
        self.total_attempts   = 0
        self.total_timeouts   = 0
        self.total_open       = 0

        # Results
        self.open_ports       = []

        # History for timing suggestion
        self.concurrency_log  = []

        # Control flag
        self.done             = False


# ==========================================
# CORE PORT PROBE
# ==========================================
async def probe_port(host, port, state, sem):
    """Attempts a TCP connection to (host, port). Updates shared state."""
    # Count the attempt BEFORE acquiring the semaphore so the display
    # task sees progress even if we're queued waiting for a slot.
    async with state.lock:
        state.tick_attempts  += 1
        state.total_attempts += 1

    async with sem:
        timed_out = False
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=CONNECT_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            async with state.lock:
                state.open_ports.append(port)
                state.total_open += 1

        except asyncio.TimeoutError:
            timed_out = True
        except (ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass

        if timed_out:
            async with state.lock:
                state.tick_timeouts  += 1
                state.total_timeouts += 1


# ==========================================
# HEURISTIC CONTROLLER
# ==========================================
async def heuristic_controller(state):
    """Periodically samples timeout rate and adjusts concurrency."""
    while not state.done:
        await asyncio.sleep(HEURISTIC_INTERVAL)
        async with state.lock:
            attempts = state.tick_attempts
            timeouts = state.tick_timeouts
            state.tick_attempts = 0
            state.tick_timeouts = 0

        if attempts == 0:
            continue

        timeout_rate = timeouts / attempts

        if timeout_rate > HIGH_TIMEOUT_RATE:
            new_c = max(MIN_CONCURRENCY, state.concurrency - SPEED_STEP)
        elif timeout_rate < LOW_TIMEOUT_RATE:
            new_c = min(MAX_CONCURRENCY, state.concurrency + SPEED_STEP)
        else:
            new_c = state.concurrency

        state.concurrency = new_c
        state.concurrency_log.append(new_c)


# ==========================================
# LIVE PROGRESS DISPLAY
# ==========================================
async def progress_display(state, total_ports):
    """Refreshes a single console line with live scan stats."""
    start_time = time.monotonic()
    while not state.done:
        elapsed   = max(time.monotonic() - start_time, 0.001)
        rate      = int(state.total_attempts / elapsed)
        pct       = (state.total_attempts / total_ports) * 100
        bar_len   = 30
        filled    = int(bar_len * state.total_attempts / total_ports)
        bar       = "#" * filled + "-" * (bar_len - filled)

        sys.stdout.write(
            f"\r  [{bar}] {pct:5.1f}%  |  "
            f"Scanned: {state.total_attempts:>6}/{total_ports}  |  "
            f"Open: {state.total_open}  |  "
            f"Speed: {rate:>5} p/s  |  "
            f"Concurrency: {state.concurrency}"
        )
        sys.stdout.flush()
        await asyncio.sleep(0.1)  # Lower tick = more responsive display

    sys.stdout.write("\n")
    sys.stdout.flush()


# ==========================================
# MAIN ASYNC RUNNER
# ==========================================
async def run_probe(target, start_port=1, end_port=65535):
    """
    Full async probe coroutine.
    Returns (sorted open_ports, suggested_nmap_timing, avg_concurrency).
    """
    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    state = HeuristicState(INITIAL_CONCURRENCY)

    print(f"\n{'='*60}")
    print(f"  RedScan Port Prober  |  Target: {target}")
    print(f"  Ports {start_port}-{end_port}  |  Initial Concurrency: {INITIAL_CONCURRENCY}")
    print(f"{'='*60}\n")

    # One shared semaphore — limits truly concurrent connections
    sem = asyncio.Semaphore(INITIAL_CONCURRENCY)

    # Background tasks
    ctrl_task = asyncio.create_task(heuristic_controller(state))
    disp_task = asyncio.create_task(progress_display(state, total))

    # Schedule all probe coroutines; Semaphore gates how many run at once.
    # We chunk them in batches with a yield between each batch so the
    # display and heuristic tasks get event-loop time during fast scans.
    BATCH_SIZE = 500
    for i in range(0, len(ports), BATCH_SIZE):
        batch = [probe_port(target, p, state, sem) for p in ports[i:i+BATCH_SIZE]]
        await asyncio.gather(*batch)
        await asyncio.sleep(0)  # yield to display + heuristic tasks

    # Teardown
    state.done = True
    ctrl_task.cancel()
    disp_task.cancel()
    try:
        await ctrl_task
    except asyncio.CancelledError:
        pass
    try:
        await disp_task
    except asyncio.CancelledError:
        pass

    # Compute suggested timing
    if state.concurrency_log:
        avg_c = int(sum(state.concurrency_log) / len(state.concurrency_log))
    else:
        avg_c = state.concurrency
    timing = concurrency_to_timing(avg_c)

    return sorted(state.open_ports), timing, avg_c



# ==========================================
# SYNC ENTRY POINT (called from main.py)
# ==========================================
def launch_probe(target, start_port=1, end_port=65535):
    """
    Synchronous wrapper. Runs the async probe and returns results.
    Returns (open_ports: list[int], timing_flag: str).
    """
    try:
        return asyncio.run(run_probe(target, start_port, end_port))
    except KeyboardInterrupt:
        print("\n\n[!] Probe interrupted by user.")
        return [], "-T3", 500
