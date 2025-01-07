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
    function mkdir(p: string): boolean {
        const mkdirPtr = Module.findExportByName('libc.so', "mkdir")!;
        const mkdirFn = new NativeFunction(mkdirPtr, "int", ["pointer", "int32"]);
        const res = mkdirFn(Memory.allocUtf8String(p), 0o777);
        // 0 means success
        return res === 0;
    }

    function mkdirp(p: string) {
        const parts = p.split("/");
        // All parent paths along the way
        const paths = parts.map((_, i) => parts.slice(0, i + 1).join("/"));
        // Create each ancestor path in turn, ignoring existing ones
        const successes = paths.map((path) => mkdir(path));

        // If all failed to create, let's hope it already existed (TODO: check `stat`)
        if (successes.every((s) => !s)) return;

        // If last one failed to create but some others didn't, something went wrong
        if (!successes[successes.length - 1])
        throw new Error(`Failed to create directory: ${p}`);
    }

    function access(p: string, mode: number = 4): boolean {
        const accessPtr = Module.findExportByName('libc.so', "access")!;
        const accessFn = new NativeFunction(accessPtr, "int", ["pointer", "int32"]);
        const res = accessFn(Memory.allocUtf8String(p), mode);
        // 0 means success –> file can be accessed for given read/write/execute mode
        return res === 0;
    }

    export function dump(fileName?: string, path?: string): void {
        fileName = fileName ?? `${Il2Cpp.application.identifier ?? "unknown"}_${Il2Cpp.application.version ?? "unknown"}.cs`;
        path = path ?? Il2Cpp.application.dataPath!;

        // Create directory (recursively) if necessary
        mkdirp(path);

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

    export function dumpTree(path?: string, deleteIfExists: boolean = false): void {
        const basePath = path ?? `${Il2Cpp.application.identifier ?? "unknown"}_${Il2Cpp.application.version ?? "unknown"}`;
        const basePathExists = access(basePath);

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
            mkdirp(path);

            const filepath = `${path}/${filename}`;    
            const file = new File(filepath, "w");

            inform(`dumping ${path}/${filename}`);

            for (const klass of assembly.image.classes) {
                file.write(`${klass}\n\n`);
            }

            file.flush();
            file.close();            
        }

        ok(`dump saved to ${basePath}`);
    }
}
