# Installation and Setup

### Project setup
A practical example demonstrating the usage of `frida-il2cpp-bridge` can be found in the `example` folder of this repository.

You can explore it directly in the repository or download it using a service like [DownGit](https://minhaskamal.github.io/DownGit/#/home?url=https://github.com/vfsfitvnm/frida-il2cpp-bridge/tree/master/example).

**To understand the example:**
1.  Examine `example/package.json`: This file shows how `frida-il2cpp-bridge` is included as a dependency and any scripts used to build/run the example.
2.  Review `example/index.ts`: This is the main TypeScript file showcasing how to import and use the bridge API to interact with an Il2Cpp application.
3.  Check `example/tsconfig.json`: This file contains the TypeScript compiler options used for the example.

The example typically demonstrates initializing the bridge, finding classes/methods, and performing basic interactions. It serves as a starting point for your own agent scripts.

### Add to an existing project

1.  **Install Frida:**
    If you haven't already, install Frida. You can install it globally or as a project dependency. For global installation:
    ```shell script
    npm install -g frida frida-tools
    ```
    Or, for a project-level dependency (recommended for reproducible builds):
    ```shell script
    npm install --save-dev frida frida-tools
    ```
    Frida is essential for `frida-il2cpp-bridge` to communicate with the target application.

2.  **Install frida-il2cpp-bridge:**
    ```shell script
    npm install --save-dev frida-il2cpp-bridge
    ```
    This installs the bridge library as a development dependency for your project.

3.  **Configure TypeScript (if applicable):**
    If you are using TypeScript, you may need to include `"moduleResolution": "node"` in your `tsconfig.json` compiler options. This setting helps the TypeScript compiler locate the modules correctly, especially in projects with Node.js-style dependencies.
    ```json
    {
      "compilerOptions": {
        "moduleResolution": "node",
        // ... other options
      }
    }
    ```
