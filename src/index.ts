import "./il2cpp/index";

declare global {
    /** https://docs.microsoft.com/en-us/javascript/api/@azure/keyvault-certificates/requireatleastone */
    type RequireAtLeastOne<T> = { [K in keyof T]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<keyof T, K>>> }[keyof T];

    /** @internal */
    namespace console {
        function log(message?: any, ...optionalParams: any[]): void;
    }
}
