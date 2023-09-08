/** @internal */
function raise(message: any): never {
    const error = new Error(`\x1b[0m${message}`);
    error.name = `\x1b[0m\x1b[38;5;9mil2cpp\x1b[0m`;
    error.stack = error.stack
        ?.replace(/^Error/, error.name)
        ?.replace(/\n    at (.+) \((.+):(.+)\)/, "\x1b[3m\x1b[2m")
        ?.concat("\x1B[0m");

    throw error;
}

/** @internal */
function warn(message: any): void {
    (globalThis as any).console.log(`\x1b[38;5;11mil2cpp\x1b[0m: ${message}`);
}

/** @internal */
function ok(message: any): void {
    (globalThis as any).console.log(`\x1b[38;5;10mil2cpp\x1b[0m: ${message}`);
}

/** @internal */
function inform(message: any): void {
    (globalThis as any).console.log(`\x1b[38;5;12mil2cpp\x1b[0m: ${message}`);
}
