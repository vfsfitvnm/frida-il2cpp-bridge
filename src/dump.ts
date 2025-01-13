namespace Il2Cpp {
    /**
     * Dumps the application, i.e. it creates a dummy `.cs` file that contains
     * all the class, field and method declarations.
     *
     * The dump is very useful when it comes to inspecting the application as
     * you can easily search for succulent members using a simple text search,
     * hence this is typically the very first thing it should be done when
     * working with a new application. \
     * Keep in mind the dump is version, platform and arch dependentend, so
     * it has to be re-genereated if any of these changes.
     *
     * The file is generated in the **target** device, so you might need to
     * pull it to the host device afterwards.
     *
     * Dumping *may* require a file name and a directory path (a place where the
     * application can write to). If not provided, the target path is generated
     * automatically using the information from {@link Il2Cpp.application}.
     *
     * ```ts
     * Il2Cpp.perform(() => {
     *     Il2Cpp.dump();
     * });
     * ```
     *
     * For instance, the dump resembles the following:
     * ```
     * class Mono.DataConverter.PackContext : System.Object
     * {
     *     System.Byte[] buffer; // 0x10
     *     System.Int32 next; // 0x18
     *     System.String description; // 0x20
     *     System.Int32 i; // 0x28
     *     Mono.DataConverter conv; // 0x30
     *     System.Int32 repeat; // 0x38
     *     System.Int32 align; // 0x3c
     *
     *     System.Void Add(System.Byte[] group); // 0x012ef4f0
     *     System.Byte[] Get(); // 0x012ef6ec
     *     System.Void .ctor(); // 0x012ef78c
     *   }
     * ```
     */
    export function dump(fileName?: string, path?: string): void {
        fileName = fileName ?? `${Il2Cpp.application.identifier ?? "unknown"}_${Il2Cpp.application.version ?? "unknown"}.cs`;
        path = path ?? Il2Cpp.application.dataPath!;

        // Create directory (recursively) if necessary
        createDirectoryRecursively(path);

        const destination = `${path}/${fileName}`;
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

    export function dumpTree(path?: string, deleteIfExists: boolean = false): void {
        const basePath = path ?? `${Il2Cpp.application.dataPath!}/${Il2Cpp.application.identifier ?? "unknown"}_${Il2Cpp.application.version ?? "unknown"}`;
        const basePathExists = directoryExists(basePath);

        if (!deleteIfExists && basePathExists) {
            warn(`directory ${basePath} already exists, skipping...`);
            return;
        }

        if (deleteIfExists && basePathExists) {
            warn(`directory ${basePath} already exists, but tree deletion not yet supported, skipping...`);
            return;
        }

        for (const assembly of Il2Cpp.domain.assemblies) {
            const assemblyParts = assembly.name.split(".");
            const assemblyPath = assemblyParts.length >= 2 ? assemblyParts.slice(0, -1).join("/") : null;
            const filename = assemblyParts[assemblyParts.length - 1] + '.cs';
            const path = assemblyPath ? `${basePath}/${assemblyPath}` : basePath;

            // Create directory (recursively) if necessary
            createDirectoryRecursively(path);

            const destination = `${path}/${filename}`;    
            const file = new File(destination, "w");

            inform(`dumping ${path}/${filename}`);

            for (const klass of assembly.image.classes) {
                file.write(`${klass}\n\n`);
            }

            file.flush();
            file.close();            
        }

        ok(`dump saved to ${basePath}`);
    }

    function createDirectoryRecursively(p: string) {
        const Directory = Il2Cpp.corlib.class('System.IO.Directory');
        const CreateDirectory = Directory.method('CreateDirectory');
        CreateDirectory.invoke(Il2Cpp.string(p));
    }

    function directoryExists(p: string): boolean {
        const Directory = Il2Cpp.corlib.class('System.IO.Directory');
        const Exists = Directory.method<boolean>('Exists');
        return Exists.invoke(Il2Cpp.string(p));
    }

    /**
     * Not always available
     */
    function removeDirectoryTree(p: string) {
        const Directory = Il2Cpp.corlib.class('System.IO.Directory');
        const Delete = Directory.method('Delete', 2);
        Delete.invoke(Il2Cpp.string(p), true);
    }
}
