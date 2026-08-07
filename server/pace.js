/**
 * Spacing between outbound connections.
 *
 * A scan needs several dozen handshakes, and firing them as fast as the pool
 * allows looks exactly like what a rate limiter is built to stop: targets
 * behind one start dropping probes, and a report assembled from that silence
 * is worse than no report at all.
 *
 * So every probe reserves a slot before it opens a socket. The slots are handed
 * out one interval apart across the whole process, which paces the scanner
 * without changing how any individual probe is written.
 */

const INTERVAL = Number(process.env.PROBE_INTERVAL_MS ?? 40);

/** When the next connection may start. */
let nextSlot = 0;

/** Reserves the next slot and resolves when it is due. */
export function pace() {
  if (!(INTERVAL > 0)) return Promise.resolve();

  const now = Date.now();
  const at = Math.max(now, nextSlot);
  nextSlot = at + INTERVAL;

  const wait = at - now;
  return wait > 0 ? new Promise(resolve => setTimeout(resolve, wait)) : Promise.resolve();
}

export function paceInterval() {
  return INTERVAL;
}
