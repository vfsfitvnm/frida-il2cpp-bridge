import { inform, ok, raise, warn } from "../utils/console";
import { injectToIl2Cpp } from "./decorators";

@injectToIl2Cpp("Dumper")
class Dumper {
    static get destinationPath(): string | undefined {
        const coreModuleName = "UnityEngine.CoreModule" in Il2Cpp.Domain.reference.assemblies ? "UnityEngine.CoreModule" : "UnityEngine";
        const applicationMethods = Il2Cpp.Domain.reference.assemblies[coreModuleName].image.classes["UnityEngine.Application"].methods;

        const persistentDataPath = applicationMethods.get_persistentDataPath.invoke<Il2Cpp.String>().content;

        const getIdentifierName = "get_identifier" in applicationMethods ? "get_identifier" : "get_bundleIdentifier";
        const identifier = applicationMethods[getIdentifierName].invoke<Il2Cpp.String>().content;
        const version = applicationMethods.get_version.invoke<Il2Cpp.String>().content;

        return `${persistentDataPath}/${identifier}_${version}.cs`;
    }

    static dump(generator: () => Generator<string>, destinationPath: string | undefined = this.destinationPath) {
        if (destinationPath == undefined) {
            raise("A destination path has not been specified and it couldn't be guessed.");
        }

        const file = new File(destinationPath, "w");

        for (const block of generator()) {
            file.write(block);
        }

        file.flush();
        file.close();
        ok(`Dump saved to ${destinationPath}.`);
    }

    static classicDump(destinationPath?: string): void {
        this.dump(function* (): Generator<string> {
            for (const assembly of Object.values(Il2Cpp.Domain.reference.assemblies)) {
                inform(`Dumping \x1b[1m${assembly.name}\x1b[0m...`);
                for (const klass of Object.values(assembly.image.classes)) {
                    yield klass.toString();
                }
            }
        }, destinationPath);
    }

    static snapshotDump(destinationPath?: string): void {
        warn("A snapshot dump will be effective only after process startup.");

        this.dump(function* (): Generator<string> {
            for (const metadataType of new Il2Cpp.MemorySnapshot().metadataSnapshot.metadataTypes) {
                yield metadataType.class.toString();
            }
        }, destinationPath);
    }
}
