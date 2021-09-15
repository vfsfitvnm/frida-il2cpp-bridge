/** A version utility class. */
export class Version {
    static pattern?: RegExp;

    /** @internal */
    readonly #source: string;

    /** @internal */
    readonly #major: number;

    /** @internal */
    readonly #minor: number;

    /** @internal */
    readonly #revision: number;

    /** @internal */
    constructor(source: string) {
        if (Version.pattern == undefined) {
            throw new Error(`The version match pattern has not been set.`);
        }

        const matches = source.match(Version.pattern);
        this.#source = matches ? matches[0] : source;
        this.#major = matches ? Number(matches[1]) : -1;
        this.#minor = matches ? Number(matches[2]) : -1;
        this.#revision = matches ? Number(matches[3]) : -1;

        if (matches == null) {
            throw new Error(`"${source}" is not a valid version.`);
        }
    }

    isEqual(other: string): boolean {
        return this.compare(other) == 0;
    }

    isAbove(other: string): boolean {
        return this.compare(other) == 1;
    }

    isBelow(other: string): boolean {
        return this.compare(other) == -1;
    }

    isEqualOrAbove(other: string): boolean {
        return this.compare(other) >= 0;
    }

    isEqualOrBelow(other: string): boolean {
        return this.compare(other) <= 0;
    }

    /** @internal */
    private compare(otherSource: string): -1 | 0 | 1 {
        const other = new Version(otherSource);

        if (this.#major > other.#major) return 1;
        if (this.#major < other.#major) return -1;
        if (this.#minor > other.#minor) return 1;
        if (this.#minor < other.#minor) return -1;
        if (this.#revision > other.#revision) return 1;
        if (this.#revision < other.#revision) return -1;

        return 0;
    }

    /** @internal */
    toJSON(): string {
        return this.toString();
    }

    toString(): string {
        return this.#source;
    }
}
