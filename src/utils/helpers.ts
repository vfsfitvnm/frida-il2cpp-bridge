import { raise } from "./console";

/** @internal */
export const getOrNull = <T>(handle: NativePointer, target: new (handle: NativePointer) => T) =>
    handle.isNull() ? null : new target(handle);

/** @internal */
export function platformNotSupported(): never {
    raise(`Platform "${Process.platform}" is not supported yet.`);
}
