# Building the Project

If you want to build `frida-il2cpp-bridge` from source, for example, to make modifications or contribute to its development, follow these steps.

**Prerequisites:**

*   **Node.js and npm:** Required for managing dependencies and running build scripts. You can download them from [nodejs.org](https://nodejs.org/).
*   **Make:** The build process uses a `Makefile`. Ensure `make` is installed on your system (common on Linux and macOS; for Windows, you might need to install it via tools like Chocolatey or MinGW).

**Build Steps:**

1.  **Clone the repository (if you haven't already):**
    ```shell
    git clone https://github.com/vfsfitvnm/frida-il2cpp-bridge.git
    cd frida-il2cpp-bridge
    ```

2.  **Install dependencies:**
    This step installs the necessary Node.js packages defined in `package.json`.
    ```shell
    npm install
    ```
    (This is also implicitly handled by the `make dist` command if the `node_modules` directory doesn't exist).

3.  **Build the TypeScript library:**
    The main build command compiles the TypeScript source code from the `lib/` directory into JavaScript files in the `dist/` directory. This command also handles the inlining of the C module (`lib/cmodules/memory-snapshot.c`) into the JavaScript output.
    ```shell
    make dist
    ```
    Alternatively, you can run the npm script which does the same:
    ```shell
    npm run prepare
    ```

**Build Output:**

*   The compiled JavaScript files and type definitions (`.d.ts`) will be located in the `dist/` directory. This is the directory that gets packaged if you publish the module or use it locally.
*   The Python-based CLI tool located in the `cli/` directory does not require a separate build step and can be run directly from the source (e.g., `python -m cli.main dump ...`).

No separate C compilation is typically needed for the core library, as the C module content is inlined during the TypeScript build process.
