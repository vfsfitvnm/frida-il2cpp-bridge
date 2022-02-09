import "./il2cpp";
import "./unity";

/** @internal */
declare global {
    interface NativePointer {
        nullOr<T>(Class: new (handle: NativePointer) => T): T | null;
        format(): string;
    }
}

NativePointer.prototype.nullOr = function <T>(Class: new (handle: NativePointer) => T): T | null {
    return this.isNull() ? null : new Class(this);
};

NativePointer.prototype.format = function (): string {
    return `0x${this.toString(16).padStart(8, "0")}`;
};
