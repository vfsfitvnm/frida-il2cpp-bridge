/** @internal */
function raise(message: any): never {
    const error = new Error(message);
    // in the stack message, it is only used by V8 - qjs ignores it
    error.name = "Il2CppError";
    error.stack = error.stack
        // reset style and replace "(Il2Cpp)?Error" with custom tag
        ?.replace(/^(Il2Cpp)?Error/, "\x1b[0m\x1b[38;5;9mil2cpp\x1b[0m")
        // replace the (unhelpful) first line of the stack ("at raise ...") and
        // add style to the stack lines
        ?.replace(/\n    at (.+) \((.+):(.+)\)/, "\x1b[3m\x1b[2m")
        // reset style
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
