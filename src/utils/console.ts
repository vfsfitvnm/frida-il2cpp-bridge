/** @internal */
const NAME = "il2cpp";

/** @internal */
const RED = `\x1b[31m[${NAME}]\x1b[0m`;

/** @internal */
const GREEN = `\x1b[32m[${NAME}]\x1b[0m`;

/** @internal */
const YELLOW = `\x1b[33m[${NAME}]\x1b[0m`;

/** @internal */
const BLUE = `\x1b[34m[${NAME}]\x1b[0m`;

/** @internal */
const MAGENTA = `\x1b[35m[${NAME}]\x1b[0m`;

/** @internal */
export function raise(message: string): never {
    const error = new Error(message);
    error.stack = error.stack?.replace("Error:", RED);
    throw error;
}

/** @internal */
export function ok(message: string) {
    console.log(GREEN + " " + message);
}

/** @internal */
export function warn(message: string) {
    console.log(YELLOW + " " + message);
}

/** @internal */
export function inform(message: string) {
    console.log(BLUE + " " + message);
}
