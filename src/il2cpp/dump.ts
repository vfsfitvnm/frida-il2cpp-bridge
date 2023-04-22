namespace Il2Cpp {
    /** Dumps the application. */
    export function dump(fileName?: string, path?: string): void {
        fileName = fileName ?? `${Il2Cpp.application.identifier ?? "unknown"}_${Il2Cpp.application.version ?? "unknown"}.cs`;

        const destination = `${path ?? Il2Cpp.application.dataPath}/${fileName}`;
        const file = new File(destination, "w");

        for (const assembly of Il2Cpp.domain.assemblies) {
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
