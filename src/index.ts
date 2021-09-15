import "./il2cpp";
import "./unity";

declare global {
    type IterableRecord<T> = Readonly<Record<string, T>> & Iterable<T>;
}
