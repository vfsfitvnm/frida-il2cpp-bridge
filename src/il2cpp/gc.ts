import Api from "./api";
import UnityVersion from "../utils/unity-version";
import { raise } from "../utils/console";

/** @internal */
namespace GC {
    export function collect(generation: 0 | 1 | 2) {
        Api._gcCollect(generation);
    }

    export function collectALittle() {
        if (UnityVersion.CURRENT.isBelow("5.3.5")) raise("Operation not available.");
        Api._gcCollectALittle();
    }

    export function disable() {
        if (UnityVersion.CURRENT.isBelow("5.3.5")) raise("Operation not available.");
        Api._gcDisable();
    }

    export function enable() {
        if (UnityVersion.CURRENT.isBelow("5.3.5")) raise("Operation not available.");
        Api._gcEnable();
    }

    export function isDisabled() {
        if (UnityVersion.CURRENT.isBelow("2018.3.0")) raise("Operation not available.");
        return Api._gcIsDisabled();
    }
}

export default GC;
