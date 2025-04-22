namespace Il2Cpp {
    export class Parameter {
        /** Name of this parameter. */
        readonly name: string;

        /** Position of this parameter. */
        readonly position: number;

        /** Type of this parameter. */
        readonly type: Il2Cpp.Type;

        constructor(name: string, position: number, type: Il2Cpp.Type) {
            this.name = name;
            this.position = position;
            this.type = type;
        }

        /** */
        toString(): string {
            return `${this.type.name} ${this.name}`;
        }
    }

    export namespace Parameter {
        export type Type = Il2Cpp.Field.Type | Il2Cpp.Reference;
    }
}
