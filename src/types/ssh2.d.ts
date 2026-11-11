// Minimal typing of the vendored ssh2 package (it ships no declarations). The gateway uses only
// Client (worker) and Server/utils (tests); call sites keep their own narrow types.
// deno-lint-ignore no-explicit-any
declare const ssh2: any;
export default ssh2;
