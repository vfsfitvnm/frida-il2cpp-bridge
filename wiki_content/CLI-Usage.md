# CLI Usage

Beyond the TypeScript library, `frida-il2cpp-bridge` also includes a powerful Python-based Command Line Interface (CLI) tool. This CLI is designed for performing common tasks, such as dumping detailed application data for offline analysis, without needing to write custom Frida scripts.

**Running the CLI:**

The CLI tool is typically run from the root of the `frida-il2cpp-bridge` project directory using the Python module syntax:

```shell
python -m cli.main [command] [options...]
```

Ensure you have the necessary Python dependencies installed, primarily `frida`.

**The `dump` command:**

The primary command provided by the CLI is `dump`. Its purpose is to connect to a target IL2CPP application and extract comprehensive information about its structure, including assemblies, classes, methods, fields, and their memory addresses. This information is then saved, typically as pseudo-C# files.

**General CLI Options (applicable to `dump`):**

These options control how the CLI connects to the target application and some initial configurations:

*   `-H HOST`, `--host HOST`: Connect to Frida server on `HOST`.
*   `-D ID`, `--device ID`: Connect to device with `ID`.
*   `-U`, `--usb`: Connect to the first USB device.
*   `-R`, `--remote`: Connect to a remote Frida server (equivalent to `-H` with a default host if not specified).
*   `-f APP_ID`, `--attach-frontmost APP_ID`: Attach to the frontmost application that matches `APP_ID` (bundle identifier).
*   `-n APP_NAME`, `--attach-name APP_NAME`: Attach to an application by its process `APP_NAME`.
*   `-p PID`, `--attach-pid PID`: Attach to a process by its `PID`.
*   `--unity-version VERSION`: Manually specify the Unity `VERSION` if it cannot be detected automatically (e.g., "2020.3.15f1").
*   `--module-name NAME`: Manually specify the IL2CPP module `NAME` if it cannot be detected automatically (e.g., "MyGameAssembly.dll").
*   `--script-prelude PATH`: Path to a custom JavaScript (`.js`) file to be executed by Frida before the main `dump` agent script runs.

**`dump` Command Specific Options:**

These options tailor the output and behavior of the `dump` command:

*   `--out-dir PATH`: Specifies the directory `PATH` where the dump output will be saved. Defaults to the current working directory.
*   `--cs-output {none|stdout|flat|tree}`: Defines the style for the C# output (default: `tree`).
    *   `none`: No C# output is generated.
    *   `stdout`: Prints the C# dump directly to the console (standard output).
    *   `flat`: Generates a single `dump.cs` file in the output directory.
    *   `tree`: Creates a directory structure where each assembly is dumped into its own `.cs` file within a folder named after the application identifier and version.
*   `--no-namespaces`: If set, namespace blocks are omitted from the C# output. Class declarations will be prepended with their namespace names instead.
*   `--flatten-nested-classes`: If set, nested classes are written at the same level as their enclosing classes, with their names prefixed by the enclosing class name(s).
*   `--keep-implicit-base-classes`: If set, explicitly writes base classes like `System.Object` for classes, `System.ValueType` for structs, and `System.Enum` for enums in the C# output.
*   `--enums-as-structs`: If set, enum declarations are written as struct declarations in the C# output.
*   `--no-type-keywords`: If set, uses fully qualified names for built-in C# types (e.g., `System.Int32` instead of `int`, `System.String` instead of `string`).
*   `--actual-constructor-names`: If set, uses the internal IL2CPP names for constructors (e.g., `.ctor` for instance constructors, `.cctor` for static constructors) instead of the class name.
*   `--indentation-size INT`: Sets the number of spaces used for indentation in the C# output (default: `4`).

**Examples for `dump` command:**

1.  **Basic dump to current directory (tree output):**
    Attach to an application by its name (e.g., "MyGame.exe" or "com.example.mygame") and dump its structure.
    ```shell
    python -m cli.main dump -n YourAppName --cs-output tree
    ```
    (Replace `YourAppName` with the target application's process name or bundle identifier if using `-f`)

2.  **Dump to a specific directory with flat C# output:**
    Attach to the frontmost application (identified by its bundle ID) and save the dump to `./my_app_dump`.
    ```shell
    python -m cli.main dump -f com.example.mygame --out-dir ./my_app_dump --cs-output flat
    ```

3.  **Dump with no namespaces and actual constructor names:**
    Attach to an application by its PID.
    ```shell
    python -m cli.main dump -p 1234 --no-namespaces --actual-constructor-names
    ```

**Output Description:**

The `dump` command primarily generates pseudo-C# (`.cs`) files.
*   If `--cs-output tree` (default) is used, the output will be a directory structure like `output_dir/app_identifier/app_version/AssemblyName.cs`. This provides a clean, organized view of the dumped application.
*   If `--cs-output flat` is used, a single `dump.cs` file containing all dumped information is created in the specified output directory.
*   If `--cs-output stdout` is used, this C# content is printed to your terminal.

These files contain the structure of the application's managed code, including class definitions, fields, methods (with signatures and memory addresses), and inheritance information, which is invaluable for reverse engineering and analysis.
