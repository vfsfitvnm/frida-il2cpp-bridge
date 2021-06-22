const NAME = "il2cpp";

const RED = `\x1b[31m[${NAME}]\x1b[0m`;

const GREEN = `\x1b[32m[${NAME}]\x1b[0m`;

const YELLOW = `\x1b[33m[${NAME}]\x1b[0m`;

const BLUE = `\x1b[34m[${NAME}]\x1b[0m`;

const MAGENTA = `\x1b[35m[${NAME}]\x1b[0m`;

/** @internal */
export function raise(message: string): never {
    const error = new Error(message);
    error.stack = error.stack?.replace("Error:", RED);
    throw error;
}

/** @internal */
export function ok(message: string): void {
    console.log(GREEN + " " + message);
}

/** @internal */
export function warn(message: string): void {
    console.log(YELLOW + " " + message);
}

/** @internal */
export function inform(message: string): void {
    console.log(BLUE + " " + message);
}

/** @internal */
export function platformNotSupported(): never {
    raise(`Platform "${Process.platform}" is not supported yet.`);
}
