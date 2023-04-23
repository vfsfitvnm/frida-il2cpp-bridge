namespace Il2Cpp {
    /** Backtracing utilities. */
    export class Backtracer extends Il2Cpp.AbstractTracer {
        /** @internal */
        private mode?: globalThis.Backtracer;

        /** @internal */
        private isVerbose: boolean = true;

        /** @internal */
        readonly methodList = Il2Cpp.domain.assemblies
            .flatMap(_ => _.image.classes.flatMap(_ => _.methods.filter(_ => !_.virtualAddress.isNull())))
            .sort((_, __) => _.virtualAddress.compare(__.virtualAddress));

        /** */
        strategy(value: "fuzzy" | "accurate"): Pick<Il2Cpp.Backtracer, "verbose"> {
            this.mode = (globalThis as any).Backtracer[value.toUpperCase()];
            return this;
        }

        /** Determines whether print duplicate logs. */
        verbose(value: boolean): Il2Cpp.AbstractTracer.ChooseTargets {
            this.isVerbose = value;
            return this;
        }

        attach(): void {
            const backtracer = this;
            const history = this.isVerbose ? undefined : new Set<string>();

            for (const target of this.targets) {
                if (target.virtualAddress.isNull()) {
                    continue;
                }

                try {
                    Interceptor.attach(target.virtualAddress, function () {
                        let backtrace = globalThis.Thread.backtrace(this.context, backtracer.mode).reverse();

                        backtrace.push(target.virtualAddress);

                        if (!backtracer.isVerbose) {
                            const key = backtrace.map(_ => _.toString()).join("");

                            if (history?.has(key)) {
                                return;
                            }

                            history?.add(key);
                        }

                        let i = 0;

                        for (const address of backtrace) {
                            const method =
                                address >= Il2Cpp.module.base && address < Il2Cpp.module.base.add(Il2Cpp.module.size)
                                    ? backtracer.searchInsert(address)
                                    : undefined;

                            const decoration = i == 0 ? "" : `${" ".repeat((i - 1) * 2)}└─`;

                            if (method != undefined) {
                                const offset = address.sub(method.virtualAddress);

                                if (address.sub(method.virtualAddress).compare(0xfff) > 0) {
                                    continue;
                                }

                                inform(`\
\x1b[2m\
0x${method.relativeVirtualAddress.toString(16).padStart(8, `0`)}\
+0x${offset.toString(16).padStart(3, `0`)}\
\x1b[0m\
 ${decoration}\
${method.class.type.name}.\x1b[1m${method.name}\x1b[0m`);
                            } else {
                                continue;
                            }

                            i++;
                        }
                    });
                } catch (e: any) {}
            }
        }

        /** @internal */
        private searchInsert(target: NativePointer): Il2Cpp.Method {
            let left = 0;
            let right = this.methodList.length - 1;

            while (left <= right) {
                const pivot = Math.floor((left + right) / 2);
                const comparison = this.methodList[pivot].virtualAddress.compare(target);

                if (comparison == 0) {
                    return this.methodList[pivot];
                } else if (comparison > 0) {
                    right = pivot - 1;
                } else {
                    left = pivot + 1;
                }
            }
            return this.methodList[right];
        }
    }

    /** Creates a new `Il2Cpp.Backtracer` instance. */
    export function backtrace(): Pick<Il2Cpp.Backtracer, "strategy"> {
        return new Il2Cpp.Backtracer();
    }
}
