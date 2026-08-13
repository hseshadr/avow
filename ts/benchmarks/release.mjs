/** Deterministic TypeScript envelope gate frozen in docs/OPERATIONS.md. */

import { performance } from "node:perf_hooks";
import { signPayload, verifySignature } from "../dist/index.js";

const SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SUBJECT = { evidence: "e".repeat(4096) };

function percentile(samples, quantile) {
  const ordered = samples.toSorted((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(quantile * ordered.length) - 1)];
}

async function operation() {
  const receipt = await signPayload(SUBJECT, SEED);
  await verifySignature(receipt, receipt.public_key);
}

async function sample(warmup, count) {
  for (let index = 0; index < warmup; index += 1) await operation();
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    const started = performance.now();
    await operation();
    samples.push(performance.now() - started);
  }
  return samples;
}

function enforce(stats) {
  const observed = [stats.p50_ms, stats.p95_ms, stats.p99_ms];
  const limits = [3, 8, 20];
  if (observed.some((value, index) => value > limits[index])) {
    throw new Error(`latency budget missed: ${observed} > ${limits}`);
  }
  if (stats.peak_rss_mib > 128) {
    throw new Error(`RSS budget missed: ${stats.peak_rss_mib} > 128 MiB`);
  }
}

const samples = await sample(25, 500);
const stats = {
  count: samples.length,
  p50_ms: percentile(samples, 0.5),
  p95_ms: percentile(samples, 0.95),
  p99_ms: percentile(samples, 0.99),
  peak_rss_mib: process.memoryUsage().rss / (1024 * 1024),
};
enforce(stats);
console.log(JSON.stringify({ envelope: stats }));
