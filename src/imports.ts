/** @internal */
declare const { $$ts }: typeof import("ts-macros");

/** @internal */
declare const { closest }: typeof import("fastest-levenshtein/esm/mod");
$$ts!(`import { closest } from "fastest-levenshtein/esm/mod.js"`);

/** @internal */
declare const Versioning: typeof import("versioning").default;
$$ts!(`import Versioning from "versioning"`);

/** @internal */
declare const { $INLINE_FILE }: typeof import("ts-transformer-inline-file");
