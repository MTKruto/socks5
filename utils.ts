import { Reader } from "./deps.ts";

export async function readN(
  reader: Reader,
  n: number,
): Promise<Uint8Array> {
  const out = new Uint8Array(n);
  let nRead = 0;
  while (nRead < n) {
    const m = await reader.read(out.subarray(nRead));
    if (m === null) {
      throw new Deno.errors.UnexpectedEof(
        `reached EOF but we expected to read ${n - nRead} more bytes`,
      );
    }
    nRead += m;
  }
  return out;
}
