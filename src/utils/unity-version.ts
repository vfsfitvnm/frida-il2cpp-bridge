import { raise } from "./console";

const matchPattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})(?:([abcfp]|rc){0,2}\d?)/;

interface IUnityVersion {
    readonly source: string;
    readonly major: number;
    readonly minor: number;
    readonly revision: number;
}

function parse(source: string) {
    if (matchPattern.test(source)) {
        const matches = source.match(matchPattern)!;
        return {
            source: matches[0],
            major: Number(matches[1]),
            minor: Number(matches[2]),
            revision: Number(matches[3])
        } as IUnityVersion;
    } else {
        return {
            source: source,
            major: -1,
            minor: -1,
            revision: -1
        } as IUnityVersion;
    }
}

/**
 * Represent the Unity version of the current application.
 */
export default class UnityVersion {
    /** @internal */
    readonly isEqualOrAbove_5_3_2: number;

    /** @internal */
    readonly isEqualOrAbove_5_3_3: number;

    /** @internal */
    readonly isEqualOrAbove_5_3_6: number;

    /** @internal */
    readonly isEqualOrAbove_5_4_4: number;

    /** @internal */
    readonly isEqualOrAbove_5_5_0: number;

    /** @internal */
    readonly isEqualOrAbove_5_6_0: number;

    /** @internal */
    readonly isEqualOrAbove_2017_1_0: number;

    /** @internal */
    readonly isEqualOrAbove_2017_1_3: number;

    /** @internal */
    readonly isEqualOrAbove_2018_1_0: number;

    /** @internal */
    readonly isEqualOrAbove_2018_2_0: number;

    /** @internal */
    readonly isEqualOrAbove_2018_3_0: number;

    /** @internal */
    readonly isEqualOrAbove_2018_3_8: number;

    /** @internal */
    readonly isEqualOrAbove_2019_1_0: number;

    /** @internal */
    readonly isEqualOrAbove_2020_2_0: number;

    /** @internal */
    readonly isBelow_5_3_3: number;

    /** @internal */
    readonly isBelow_5_3_5: number;

    /** @internal */
    readonly isBelow_5_3_6: number;

    /** @internal */
    readonly isBelow_5_5_0: number;

    /** @internal */
    readonly isBelow_2018_1_0: number;

    /** @internal */
    readonly isBelow_2018_3_0: number;

    /** @internal */
    readonly isBelow_2019_3_0: number;

    /** @internal */
    readonly isBelow_2020_2_0: number;

    /** @internal */
    readonly isNotEqual_2017_2_0: number;

    /** @internal */
    readonly isNotEqual_5_5_0: number;

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
        const obj = parse(source);
        this.source = obj.source;
        this.major = obj.major;
        this.minor = obj.minor;
        this.revision = obj.revision;

        if (this.isBelow("5.3.0") || this.isEqualOrAbove("2021.1.0")) {
            raise(`Unity version "${this}" is not valid or supported.`);
        }

        this.isEqualOrAbove_5_3_2 = +this.isEqualOrAbove("5.3.2");
        this.isEqualOrAbove_5_3_3 = +this.isEqualOrAbove("5.3.3");
        this.isEqualOrAbove_5_3_6 = +this.isEqualOrAbove("5.3.6");
        this.isEqualOrAbove_5_4_4 = +this.isEqualOrAbove("5.4.4");
        this.isEqualOrAbove_5_5_0 = +this.isEqualOrAbove("5.5.0");
        this.isEqualOrAbove_5_6_0 = +this.isEqualOrAbove("5.6.0");
        this.isEqualOrAbove_2017_1_0 = +this.isEqualOrAbove("2017.1.0");
        this.isEqualOrAbove_2017_1_3 = +this.isEqualOrAbove("2017.1.3");
        this.isEqualOrAbove_2018_1_0 = +this.isEqualOrAbove("2018.1.0");
        this.isEqualOrAbove_2018_2_0 = +this.isEqualOrAbove("2018.2.0");
        this.isEqualOrAbove_2018_3_0 = +this.isEqualOrAbove("2018.3.0");
        this.isEqualOrAbove_2018_3_8 = +this.isEqualOrAbove("2018.3.8");
        this.isEqualOrAbove_2019_1_0 = +this.isEqualOrAbove("2019.1.0");
        this.isEqualOrAbove_2020_2_0 = +this.isEqualOrAbove("2020.2.0");

        this.isBelow_5_3_3 = +!this.isEqualOrAbove_5_3_3;
        this.isBelow_5_3_5 = +this.isBelow("5.3.5");
        this.isBelow_5_3_6 = +!this.isEqualOrAbove_5_3_6;
        this.isBelow_5_5_0 = +!this.isEqualOrAbove_5_5_0;
        this.isBelow_2018_1_0 = +!this.isEqualOrAbove_2018_1_0;
        this.isBelow_2018_3_0 = +!this.isEqualOrAbove_2018_3_0;
        this.isBelow_2019_3_0 = +this.isBelow("2019.3.0");
        this.isBelow_2020_2_0 = +!this.isEqualOrAbove_2020_2_0;

        this.isNotEqual_2017_2_0 = +!this.isEqual("2017.2.0");
        this.isNotEqual_5_5_0 = +!this.isEqual("5.5.0");
    }

    /**
     * ```typescript
     * console.log(Il2Cpp.unityVersion); // 2019.4.5f1
     * ```
     * @return The current Unity version as a string.
     */
    toString() {
        return this.source;
    }

    /** @internal */
    private compare(otherSource: string) {
        const other = parse(otherSource);

        if (this.major > other.major) return 1;
        if (this.major < other.major) return -1;
        if (this.minor > other.minor) return 1;
        if (this.minor < other.minor) return -1;
        if (this.revision > other.revision) return 1;
        if (this.revision < other.revision) return -1;

        return 0;
    }

    /** @internal */
    private isEqual(other: string) {
        return this.compare(other) == 0;
    }

    /** @internal */
    private isAbove(other: string) {
        return this.compare(other) == 1;
    }

    /** @internal */
    private isBelow(other: string) {
        return this.compare(other) == -1;
    }

    /** @internal */
    private isEqualOrAbove(other: string) {
        return this.compare(other) >= 0;
    }

    /** @internal */
    private isEqualOrBelow(other: string) {
        return this.compare(other) <= 0;
    }
}
