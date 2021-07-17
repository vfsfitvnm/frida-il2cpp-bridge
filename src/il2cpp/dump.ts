import { inform, ok, raise } from "../utils/console";
import { injectToIl2Cpp } from "./decorators";

function dump(filePath?: string): void {
    if (Il2Cpp.Domain.reference == undefined) {
        raise("Not yet initialized!");
    }

    if (filePath == undefined) {
        const coreModuleName = "UnityEngine.CoreModule" in Il2Cpp.Domain.reference.assemblies ? "UnityEngine.CoreModule" : "UnityEngine";
        const applicationMethods = Il2Cpp.Domain.reference.assemblies[coreModuleName].image.classes["UnityEngine.Application"].methods;

        const persistentDataPath = applicationMethods.get_persistentDataPath.invoke<Il2Cpp.String>().content;

        const getIdentifierName = "get_identifier" in applicationMethods ? "get_identifier" : "get_bundleIdentifier";
        const identifier = applicationMethods[getIdentifierName].invoke<Il2Cpp.String>().content;
        const version = applicationMethods.get_version.invoke<Il2Cpp.String>().content;

        filePath = `${persistentDataPath}/${identifier}_${version}.cs`;
    }

    const file = new File(filePath, "w");

    for (const assembly of Object.values(Il2Cpp.Domain.reference.assemblies)) {
        inform(`Dumping ${assembly.name}...`);
        for (const klass of Object.values(assembly.image.classes)) {
            file.write(klass.toString());
        }
    }

    file.flush();
    file.close();
    ok(`Dump saved to ${filePath}.`);
}

injectToIl2Cpp("dump")(dump);
