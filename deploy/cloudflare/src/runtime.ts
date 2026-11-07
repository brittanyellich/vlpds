// Match the upstream tiny profile; the default server settings exceed 3 GiB.
export const runtimeArgs = [
  '--shards', '1', '--spaces', '--memory-budget-mb', '3072',
  '--max-exports', '4', '--firehose-max-backfills', '4',
  '--lazy-mst-node-cache-mb', '64', '--firehose-ring-mb', '64',
  '--firehose-merge-queue-mb', '32', '--firehose-max-lag-mb', '64',
  '--live-ring-mb', '32', '--backfill-readahead-mb', '16',
  '--backfill-cache-mb', '32', '--firehose-threads', '1',
];
