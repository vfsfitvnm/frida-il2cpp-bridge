# Known Limitations

While `frida-il2cpp-bridge` is a powerful tool, there are some known limitations and areas for future improvement:

-   **Manipulation of Primitive `ref` and `out` Parameters**: While the bridge can identify by-reference types (e.g., `System.Int32&`), directly modifying primitive types passed as `ref` or `out` (like `ref int a`) from JavaScript in a way that reflects back to the C# caller might require manual memory operations. Object types passed by reference are generally handled via their pointers.
-   **Complex Generic Scenarios**: While the library provides utilities for instantiating (inflating) generic types and methods, and for inspecting their generic arguments, very complex generic scenarios (e.g., involving advanced generic constraints or dynamic type creation with generics) might have limitations.
-   **Performance**: For extremely high-frequency hooks or data manipulations, the overhead of the bridge might be a consideration. Always profile if performance is critical.
-   **Error Handling**: While efforts are made to handle errors gracefully, the vastness of the Il2Cpp runtime and potential game-specific customizations mean that edge cases might exist.
-   **Evolving APIs**: The Il2Cpp API landscape can change with Unity versions. While the bridge aims for broad compatibility (as indicated in the main [Version Support section](index.md#version-support)), newer or very old Unity versions might present untested scenarios.
-   And likely others, given the complexity of interacting with a runtime like Il2Cpp. Contributions are welcome!
