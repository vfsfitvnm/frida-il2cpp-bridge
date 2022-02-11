/** @internal */
export function raise(message: any): never {
    throw `\x1B[0m\x1B[38;5;9mil2cpp\x1B[0m: ${message}`;
}

/** @internal */
export function warn(message: any): void {
    (globalThis as any).console.log(`\x1B[38;5;11mil2cpp\x1B[0m: ${message}`);
}

/** @internal */
export function ok(message: any): void {
    (globalThis as any).console.log(`\x1B[38;5;10mil2cpp\x1B[0m: ${message}`);
}

/** @internal */
export function inform(message: any): void {
    (globalThis as any).console.log(`\x1B[38;5;12mil2cpp\x1B[0m: ${message}`);
}
