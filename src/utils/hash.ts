/** @internal https://stackoverflow.com/a/52171480/16885569 */
function cyrb53(str: string): number {
    let h1 = 0xdeadbeef;
    let h2 = 0x41c6ce57;

    for (let i = 0, ch; i < str.length; i++) {
        ch = str.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
    }

    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
    h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);

    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
    h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);

    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

/** @internal */
function exportsHash(module: Module): number {
    return cyrb53(
        module
            .enumerateExports()
            .sort((a, b) => a.name.localeCompare(b.name))
            .map(_ => _.name + _.address.sub(module.base))
            .join("")
    );
}
