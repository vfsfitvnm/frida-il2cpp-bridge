import kleur from "kleur";

kleur.enabled = true;

/** @internal */
export function raise(message: string): never {
    const error = new Error(message);
    error.stack = error.stack?.replace("Error:", kleur.red("[il2cpp]"));
    throw error;
}

/** @internal */
export function ok(message: string): void {
    console.log(`${kleur.green("[il2cpp]")} ${message}`);
}

/** @internal */
export function warn(message: string): void {
    console.log(`${kleur.yellow("[il2cpp]")} ${message}`);
}

/** @internal */
export function inform(message: string): void {
    console.log(`${kleur.blue("[il2cpp]")} ${message}`);
}

/** @internal */
export function platformNotSupported(): never {
    raise(`Platform "${Process.platform}" is not supported yet.`);
}
