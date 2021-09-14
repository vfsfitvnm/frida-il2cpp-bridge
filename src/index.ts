import "./il2cpp/index";

declare global {
    /** */
    type IterableRecord<T> = Readonly<Record<string, T>> & Iterable<T>;
}
