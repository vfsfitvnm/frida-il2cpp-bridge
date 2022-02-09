import { cache } from "decorator-cache-getter";

/** @internal */
export class GLib {
    @cache
    private static get cModule(): CModule {
        return new CModule(`
#include <glib.h>

static void
_ ()
{
    g_free (NULL);
}
        `);
    }

    private static get _free() {
        return new NativeFunction(this.cModule.g_free, "void", ["pointer"]);
    }

    static free(handle: NativePointer): void {
        return this._free(handle);
    }
}
