import { inform, ok } from "../utils/console";

/** Dumping utilities. */
class Il2CppDumper {
    /** Gets the default directory path where the dump will be saved to. */
    static get defaultDirectoryPath(): string {
        const get_persistentDataPath = Il2Cpp.internalCall("UnityEngine.Application::get_persistentDataPath", "pointer", [])!;
        return new Il2Cpp.String(get_persistentDataPath()).content!;
    }

    /** Gets the default file name. */
    static get defaultFileName(): string {
        const get_identifier =
            Il2Cpp.internalCall("UnityEngine.Application::get_identifier", "pointer", []) ||
            Il2Cpp.internalCall("UnityEngine.Application::get_bundleIdentifier", "pointer", []);

        const get_version = Il2Cpp.internalCall("UnityEngine.Application::get_version", "pointer", []);

        const identifier = get_identifier ? new Il2Cpp.String(get_identifier()).content : "unknownidentifier";
        const version = get_version ? new Il2Cpp.String(get_version()).content : "unknownversion";

        return `${identifier}_${version}`;
    }

    /** @internal */
    #directoryPath?: string;

    /** @internal */
    #fileName?: string;

    /** @internal */
    #extension?: string;

    /** @internal */
    #generator?: () => Generator<string>;

    directoryPath(directoryPath: string): Pick<Il2Cpp.Dumper, "fileName" | "classes" | "methods"> {
        this.#directoryPath = directoryPath;
        return this;
    }

    fileName(fileName: string): Pick<Il2Cpp.Dumper, "classes" | "methods"> {
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

    methods(): Pick<Il2Cpp.Dumper, "build"> {
        this.#generator = function* (): Generator<string> {
            for (const assembly of Il2Cpp.Domain.assemblies) {
                inform(`dumping methods from ${assembly.name}...`);

                for (let klass of assembly.image.classes) {
                    for (let method of klass.methods) {
                        if (!method.virtualAddress.isNull()) {
                            yield `${method.relativeVirtualAddress.format()} ${klass.type.name}.${method.name}\n`;
                        }
                    }
                }
            }
        };

        this.#extension = "ms";
        return this;
    }

    build(): void {
        const directoryPath = this.#directoryPath ?? Il2Cpp.Dumper.defaultDirectoryPath;
        const fileName = this.#fileName ?? Il2Cpp.Dumper.defaultFileName;

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
