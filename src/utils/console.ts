/** @internal */
export function raise(message: string): never {
    const error = new Error(message);
    error.stack = error.stack?.replace("Error:", "\x1b[31m[il2cpp]\x1b[0m");
    throw error;
}

/** @internal */
export function ok(message: string): void {
    console.log(`\x1b[32m[il2cpp]\x1b[0m ${message}`);
}

/** @internal */
export function warn(message: string): void {
    console.log(`\x1b[33m[il2cpp]\x1b[0m ${message}`);
}

/** @internal */
export function inform(message: string): void {
    console.log(`\x1b[34m[il2cpp]\x1b[0m ${message}`);
}

/** @internal */
export function platformNotSupported(): never {
    raise(`Platform "${Process.platform}" is not supported yet.`);
}
