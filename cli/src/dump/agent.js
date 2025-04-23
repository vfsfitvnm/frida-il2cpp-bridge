/// <reference path="../../../lib/index.ts">/>
const t0 = new Date();
setTimeout(() => {
    Il2Cpp.perform(() => {
        send({ action: "init", elapsed_ms: new Date() - t0, application: Il2Cpp.application, unityVersion: Il2Cpp.unityVersion });
        const t1 = new Date();
        Il2Cpp.domain.assemblies.forEach(assembly => {
            send({
                type: "assembly",
                handle: assembly.handle,
                name: assembly.name,
                class_count: assembly.image.classCount
            });
            assembly.image.classes.forEach((klass, i) =>
                send({
                    type: "class",
                    nth: i + 1,
                    assembly_handle: assembly.handle,
                    handle: klass.handle,
                    namespace: klass.namespace,
                    name: klass.name,
                    declaring_class_handle: klass.declaringClass?.handle,
                    kind: klass.isEnum ? `enum` : klass.isStruct ? `struct` : klass.isInterface ? `interface` : `class`,
                    generics_type_names: klass.generics.map(_ => _.type.name),
                    parent_type_name: klass.parent?.type.name,
                    interfaces_type_names: klass.interfaces.map(_ => _.type.name),
                    fields: klass.fields.map(field => ({
                        name: field.name,
                        type_name: field.type.name,
                        is_thread_static: field.isThreadStatic,
                        is_static: field.isStatic,
                        is_literal: field.isLiteral,
                        value: field.isLiteral ? (field.type.class.isEnum ? field.value.field("value__").value : field.value)?.toString() : undefined,
                        offset: field.isThreadStatic || field.isLiteral ? undefined : field.offset
                    })),
                    methods: klass.methods.map(method => ({
                        is_static: method.isStatic,
                        name: method.name,
                        return_type_name: method.returnType.name,
                        generics_type_names: method.generics.map(_ => _.type.name),
                        parameters: method.parameters.map(parameter => ({
                            position: parameter.position,
                            name: parameter.name,
                            type_name: parameter.type.name
                        })),
                        offset: method.virtualAddress.isNull() ? undefined : method.relativeVirtualAddress
                    }))
                })
            );
        });
        return new Date() - t1;
    }).then(_ => send({ action: "exit", elapsed_ms: _ }));
});
