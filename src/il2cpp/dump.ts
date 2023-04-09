namespace Il2Cpp {
    /** Dumps the application. */
    export function dump(fileName?: string, path?: string): void {
        fileName = fileName ?? `${Il2Cpp.applicationIdentifier ?? "unknown"}_${Il2Cpp.applicationVersion ?? "unknown"}.cs`;

        const destination = `${path ?? Il2Cpp.applicationDataPath}/${fileName}`;
        const file = new File(destination, "w");

        for (const assembly of Il2Cpp.Domain.assemblies) {
            inform(`dumping ${assembly.name}...`);

            for (const klass of assembly.image.classes) {
                file.write(`${klass}\n\n`);
            }
        }

        file.flush();
        file.close();
        ok(`dump saved to ${destination}`);
    }
}
