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

    /**
     * Just like {@link Il2Cpp.dump}, but a `.cs` file per assembly is
     * generated instead of having a single big `.cs` file. For instance, all
     * classes within `System.Core` and `System.Runtime.CompilerServices.Unsafe`
     * are dumped into `System/Core.cs` and
     * `System/Runtime/CompilerServices/Unsafe.cs`, respectively.
     * 
     * ```ts
     * Il2Cpp.perform(() => {
     *     Il2Cpp.dumpTree();
     * });
     * ```
     */
    export function dumpTree(path?: string, ignoreAlreadyExistingDirectory: boolean = false): void {
        path = path ?? `${Il2Cpp.application.dataPath!}/${Il2Cpp.application.identifier ?? "unknown"}_${Il2Cpp.application.version ?? "unknown"}`;

        if (!ignoreAlreadyExistingDirectory && directoryExists(path)) {
            raise(`directory ${path} already exists - pass ignoreAlreadyExistingDirectory = true to skip this check`);
        }

        for (const assembly of Il2Cpp.domain.assemblies) {
            inform(`dumping ${assembly.name}...`);

            const destination = `${path}/${assembly.name.replaceAll(".", "/")}.cs`;

            createDirectoryRecursively(destination.substring(0, destination.lastIndexOf("/")));

            const file = new File(destination, "w");

            for (const klass of assembly.image.classes) {
                file.write(`${klass}\n\n`);
            }

            file.flush();
            file.close();            
        }

        ok(`dump saved to ${path}`);
    }

    function directoryExists(path: string): boolean {
        return Il2Cpp.corlib.class("System.IO.Directory").method<boolean>("Exists").invoke(Il2Cpp.string(path));
    }

    function createDirectoryRecursively(path: string) {
        Il2Cpp.corlib.class("System.IO.Directory").method("CreateDirectory").invoke(Il2Cpp.string(path));
    }
}
