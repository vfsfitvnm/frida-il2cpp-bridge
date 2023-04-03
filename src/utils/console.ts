/** @internal */
export function raise(message: any): never {
    const error = new Error(`\x1B[0m${message}`);
    error.name = `\x1B[0m\x1B[38;5;9mil2cpp\x1B[0m`;
    error.stack = error.stack
        ?.replace("Error", error.name)
        ?.replace(/\n    at (.+) \((.+):(.+)\)/, "\x1b[3m\x1b[2m")
        ?.concat("\x1B[0m");

    throw error;
}

/** @internal */
export function warn(message: any): void {
    console.log(`\x1B[38;5;11mil2cpp\x1B[0m: ${message}`);
}

/** @internal */
export function ok(message: any): void {
    console.log(`\x1B[38;5;10mil2cpp\x1B[0m: ${message}`);
}

/** @internal */
export function inform(message: any): void {
    console.log(`\x1B[38;5;12mil2cpp\x1B[0m: ${message}`);
}
