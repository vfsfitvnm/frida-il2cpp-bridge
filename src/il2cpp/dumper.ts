import { inform, ok } from "../utils/console";

/** Dumping utilities. */
class Il2CppDumper {
    /** @internal */
    #directoryPath?: string;

    /** @internal */
    #fileName?: string;

    /** @internal */
    #extension?: string;

    /** @internal */
    #generator?: () => Generator<string>;

    directoryPath(directoryPath: string): Pick<Il2Cpp.Dumper, "fileName" | "classes"> {
        this.#directoryPath = directoryPath;
        return this;
    }

    fileName(fileName: string): Pick<Il2Cpp.Dumper, "classes"> {
        this.#fileName = fileName;
        return this;
    }

    classes(): Pick<Il2Cpp.Dumper, "build"> {
        this.#generator = function* (): Generator<string> {
            for (const assembly of Il2Cpp.Domain.assemblies) {
                inform(`dumping ${assembly.name}...`);

                for (const klass of assembly.image.classes) {
                    yield klass.toString();
                }
            }
        };

        this.#extension = "cs";
        return this;
    }

    build(): void {
        const directoryPath = this.#directoryPath ?? Il2Cpp.applicationDataPath;
        const fileName = this.#fileName ?? `${Il2Cpp.applicationVersion ?? "unknown"}_${Il2Cpp.applicationVersion ?? "unknown"}`;

        const destinationPath = `${directoryPath}/${fileName}.${this.#extension ?? "dump"}`;
        const file = new File(destinationPath, "w");

        for (const chunk of this.#generator!()) {
            file.write(chunk + "\n\n");
        }

        file.flush();
        file.close();
        ok(`dump saved to ${destinationPath}`);
    }
}

Il2Cpp.Dumper = Il2CppDumper;

declare global {
    namespace Il2Cpp {
        class Dumper extends Il2CppDumper {}
    }
}
