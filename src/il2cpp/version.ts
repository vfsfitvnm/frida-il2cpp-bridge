import { cache } from "decorator-cache-getter";

import { warn } from "../utils/console";

const matchPattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})([abcfp]|rc){0,2}\d?/;
// const matchPattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})(?:([abcfp]|rc){0,2}\d?)/;

/**
 * Represent the Unity version of the current application.
 */
export class UnityVersion {
    /** @internal */
    private readonly source: string;

    /** @internal */
    private readonly major: number;

    /** @internal */
    private readonly minor: number;

    /** @internal */
    private readonly revision: number;

    /** @internal */
    constructor(source: string) {
        const matches = source.match(matchPattern);
        this.source = matches ? matches[0] : source;
        this.major = matches ? Number(matches[1]) : -1;
        this.minor = matches ? Number(matches[2]) : -1;
        this.revision = matches ? Number(matches[3]) : -1;

        if (matches == null) {
            warn(`"${source}" is not a valid Unity version.`);
        }
    }

    /**
     *  @internal
     * `true` if the current version is older than 2018.3.0.
     */
    @cache
    get isLegacy(): boolean {
        return this.isBelow("2018.3.0");
    }

    toString(): string {
        return this.source;
    }

    /** @internal */
    isEqual(other: string): boolean {
        return this.compare(other) == 0;
    }

    /** @internal */
    isAbove(other: string): boolean {
        return this.compare(other) == 1;
    }

    /** @internal */
    isBelow(other: string): boolean {
        return this.compare(other) == -1;
    }

    /** @internal */
    isEqualOrAbove(other: string): boolean {
        return this.compare(other) >= 0;
    }

    /** @internal */
    isEqualOrBelow(other: string): boolean {
        return this.compare(other) <= 0;
    }

    /** @internal */
    private compare(otherSource: string): -1 | 0 | 1 {
        const other = new UnityVersion(otherSource);

        if (this.major > other.major) return 1;
        if (this.major < other.major) return -1;
        if (this.minor > other.minor) return 1;
        if (this.minor < other.minor) return -1;
        if (this.revision > other.revision) return 1;
        if (this.revision < other.revision) return -1;

        return 0;
    }
}
