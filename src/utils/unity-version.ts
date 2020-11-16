import { unityLibraryName } from "./platform";
import { raise } from "./console";

/** @internal */
const matchPattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})(?:([abcfp]|rc){0,2}\d?)/;

/** @internal */
export default class UnityVersion {
    static readonly MIN = new UnityVersion("5.3.0");

    static readonly MAX = new UnityVersion("2020.2.1");

    private readonly source: string;

    private readonly major: number;

    private readonly minor: number;

    private readonly revision: number;

    constructor(source: string) {
        if (matchPattern.test(source)) {
            const matches = source.match(matchPattern)!;
            this.source = matches[0];
            this.major = Number(matches[1]);
            this.minor = Number(matches[2]);
            this.revision = Number(matches[3]);
        } else {
            this.source = source;
            this.major = -1;
            this.minor = -1;
            this.revision = -1;
        }
    }

    private static _CURRENT: UnityVersion;

    static get CURRENT() {
        if (this._CURRENT === undefined) {
            const searchStringHex = "45787065637465642076657273696f6e3a"; // "Expected version: "
            try {
                const unityLibrary = Process.getModuleByName(unityLibraryName!);
                for (const range of unityLibrary!.enumerateRanges("r-x")) {
                    const result = Memory.scanSync(range.base, range.size, searchStringHex)[0];
                    if (result !== undefined) this._CURRENT = new UnityVersion(result.address.readUtf8String()!);
                }
            } catch (e) {
                raise("Couldn't obtain the Unity version. Please specify it. " + e);
            }
        }
        return this._CURRENT;
    }

    get isValid() {
        return this.major != -1;
    }

    get isSupported() {
        return this.isBetween(UnityVersion.MIN, UnityVersion.MAX);
    }

    compare(other: string | UnityVersion) {
        if (typeof other == "string") {
            other = new UnityVersion(other);
        }

        if (this.major > other.major) return 1;
        if (this.major < other.major) return -1;
        if (this.minor > other.minor) return 1;
        if (this.minor < other.minor) return -1;
        if (this.revision > other.revision) return 1;
        if (this.revision < other.revision) return -1;

        return 0;
    }

    isEqual(other: string | UnityVersion) {
        return this.compare(other) == 0;
    }

    isAbove(other: string | UnityVersion) {
        return this.compare(other) == 1;
    }

    isBelow(other: string | UnityVersion) {
        return this.compare(other) == -1;
    }

    isEqualOrAbove(other: string | UnityVersion) {
        return this.compare(other) >= 0;
    }

    isEqualOrBelow(other: string | UnityVersion) {
        return this.compare(other) <= 0;
    }

    isBetween(first: string | UnityVersion, second: string | UnityVersion) {
        return this.isEqualOrAbove(first) && this.isBelow(second);
    }

    toString() {
        return this.source;
    }
}
