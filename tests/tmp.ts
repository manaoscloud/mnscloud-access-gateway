// Temporary directories under /tmp (the test task grants --allow-write=/tmp; Deno 2.8 resolves
// makeTempDir against its own <TMP> permission instead).

export async function tempDir(prefix: string): Promise<string> {
  const path = `/tmp/${prefix}${crypto.randomUUID().slice(0, 12)}`;
  await Deno.mkdir(path, { mode: 0o700 });
  return path;
}
