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
            const mainThreadId = Il2Cpp.mainThread.id;

            for (const target of this.targets) {
                if (target.virtualAddress.isNull()) {
                    continue;
                }

                try {
                    Interceptor.attach(target.virtualAddress, function () {
                        if (this.threadId != mainThreadId) {
                            return;
                        }

                        const handles = globalThis.Thread.backtrace(this.context, backtracer.mode);
                        handles.unshift(target.virtualAddress);

                        for (const handle of handles) {
                            if (handle.compare(Il2Cpp.module.base) > 0 && handle.compare(Il2Cpp.module.base.add(Il2Cpp.module.size)) < 0) {
                                const method = backtracer.searchInsert(handle);

                                if (method) {
                                    const offset = handle.sub(method.virtualAddress);

                                    if (offset.compare(0xfff) < 0) {
                                        backtracer.events.buffer.push(`\
\x1b[2m0x${method.relativeVirtualAddress.toString(16).padStart(8, `0`)}+0x${offset.toString(16).padStart(3, `0`)}\x1b[0m \
${method.class.type.name}::\x1b[1m${method.name}\x1b[0m`);
                                    }
                                }
                            }
                        }

                        backtracer.maybeFlush(!backtracer.isVerbose);
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
