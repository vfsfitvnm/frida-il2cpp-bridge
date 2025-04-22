/** @internal */
namespace UnityVersion {
    const pattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})(?:[abcfp]|rc){0,2}\d?/;

    export function find(string: string | null): string | undefined {
        return string?.match(pattern)?.[0];
    }

    export function gte(a: string, b: string): boolean {
        return compare(a, b) >= 0;
    }

    export function lt(a: string, b: string): boolean {
        return compare(a, b) < 0;
    }

    function compare(a: string, b: string): -1 | 0 | 1 {
        const aMatches = a.match(pattern);
        const bMatches = b.match(pattern);

        for (let i = 1; i <= 3; i++) {
            const a = Number(aMatches?.[i] ?? -1);
            const b = Number(bMatches?.[i] ?? -1);

            if (a > b) return 1;
            else if (a < b) return -1;
        }

        return 0;
    }
}
