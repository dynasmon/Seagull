export type TopologyInvalidationSchedulerOptions = {
  debounceMs?: number;
  minGapMs?: number;
  now?: () => number;
  setTimeoutFn?: (callback: () => void, delayMs: number) => ReturnType<typeof setTimeout>;
  clearTimeoutFn?: (timer: ReturnType<typeof setTimeout>) => void;
};

export type TopologyInvalidationScheduler = {
  notify: () => void;
  flush: () => void;
  cancel: () => void;
  setCallback: (callback: () => void) => void;
};

export function createTopologyInvalidationScheduler(
  callback: () => void,
  options: TopologyInvalidationSchedulerOptions = {},
): TopologyInvalidationScheduler {
  const debounceMs = Math.max(0, options.debounceMs ?? 650);
  const minGapMs = Math.max(0, options.minGapMs ?? 5000);
  const now = options.now ?? (() => Date.now());
  const setTimer = options.setTimeoutFn ?? ((cb, delay) => setTimeout(cb, delay));
  const clearTimer = options.clearTimeoutFn ?? ((timer) => clearTimeout(timer));

  let timer: ReturnType<typeof setTimeout> | null = null;
  let lastRunAt = Number.NEGATIVE_INFINITY;
  let currentCallback = callback;

  const cancel = () => {
    if (timer === null) return;
    clearTimer(timer);
    timer = null;
  };

  const run = () => {
    timer = null;
    lastRunAt = now();
    currentCallback();
  };

  return {
    notify: () => {
      cancel();
      const elapsed = now() - lastRunAt;
      const delayMs = Math.max(debounceMs, minGapMs - elapsed);
      timer = setTimer(run, delayMs);
    },
    flush: () => {
      cancel();
      run();
    },
    cancel,
    setCallback: (nextCallback: () => void) => {
      currentCallback = nextCallback;
    },
  };
}
