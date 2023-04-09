/** @internal */
function keyNotFound(key: string, owner: string, candidates: string[]): never {
    const closestMatch = closest(key, candidates);
    raise(`couldn't find ${key} in ${owner}${closestMatch ? `, did you mean ${closestMatch}?` : ``}`);
}
