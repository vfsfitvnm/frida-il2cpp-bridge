import { cache } from "decorator-cache-getter";

import { injectToIl2Cpp } from "./decorators";

import { inform, ok, warn } from "../utils/console";
import { getUntilFound } from "../utils/utils";

@injectToIl2Cpp("Dumper")
class Dumper {
    @cache
    static get directoryPath(): string {
        const UnityEngine = getUntilFound(Il2Cpp.Domain.reference.assemblies, "UnityEngine.CoreModule", "UnityEngine")!.image;
        const Application = UnityEngine.classes["UnityEngine.Application"];
        return Application.methods.get_persistentDataPath.invoke<Il2Cpp.String>().content!;
    }

    static get fileName(): string {
        const UnityEngine = getUntilFound(Il2Cpp.Domain.reference.assemblies, "UnityEngine.CoreModule", "UnityEngine")!.image;
        const Application = UnityEngine.classes["UnityEngine.Application"];

        try {
            const identifier = getUntilFound(Application.methods, "get_identifier", "get_bundleIdentifier")!.invoke<Il2Cpp.String>();
            const version = Application.methods.get_version.invoke<Il2Cpp.String>();
            return `${identifier.content}_${version.content}.cs`;
        } catch (e) {
            return `${new Date().getTime()}.cs`;
        }
    }

    static classicDump(fileName?: string, destinationDirectoryPath?: string): void {
        this.dump(
            function* (): Generator<string> {
                for (const assembly of Object.values(Il2Cpp.Domain.reference.assemblies)) {
                    inform(`Dumping \x1b[1m${assembly.name}\x1b[0m...`);
                    for (const klass of Object.values(assembly.image.classes)) {
                        yield klass.toString();
                    }
                }
            },
            fileName,
            destinationDirectoryPath
        );
    }

    static dump(
        generator: () => Generator<string>,
        fileName: string = this.fileName,
        destinationDirectoryPath: string = this.directoryPath
    ) {
        const destinationPath = `${destinationDirectoryPath}/${fileName}`;
        const file = new File(destinationPath, "w");

        for (const block of generator()) {
            file.write(block);
        }

        file.flush();
        file.close();
        ok(`Dump saved to ${destinationPath}.`);
    }

    static snapshotDump(fileName?: string, destinationDirectoryPath?: string): void {
        warn("A snapshot dump will be effective only after process startup.");

        this.dump(
            function* (): Generator<string> {
                for (const assembly of Object.values(Il2Cpp.Domain.reference.assemblies)) {
                    inform(`Dumping \x1b[1m${assembly.name}\x1b[0m...`);
                    for (const klass of Object.values(assembly.image.classes)) {
                        yield klass.toString();
                    }
                }

                inform("Appending some \x1b[1mmemory-snapshot-discovered\x1b[0m classes...");

                const snapshot = new Il2Cpp.MemorySnapshot();
                for (const metadataType of Object.values(snapshot.metadataSnapshot.metadataTypes)) {
                    if (!(metadataType.name in Il2Cpp.Domain.reference.assemblies[metadataType.assemblyName].image.classes)) {
                        yield metadataType.class.toString();
                    }
                }
                snapshot.free();
            },
            fileName,
            destinationDirectoryPath
        );
    }
}
