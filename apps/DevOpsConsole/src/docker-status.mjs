// Docker CLI snapshots use a human Status string such as "Up 3 minutes",
// while normalized coordinator inventory uses the lifecycle value "running".
// Both are authoritative live states at their respective API boundaries.
export function isDockerContainerRunningStatus(value) {
  const status = String(value ?? '').trim();
  return /^up\b/i.test(status) || /^running$/i.test(status);
}
