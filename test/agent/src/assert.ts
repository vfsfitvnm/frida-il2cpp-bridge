function test(name: string, block: () => void) {
    try {
        block();
        send({ name: name });
    } catch (exception: any) {
        send({ name: name, exception: exception.stack });
    }
}

function assert(actual: () => any): CallbackAssertion;
function assert<T>(actual: T): ValueAssertion<T>;

function assert<T>(actual: T | (() => any)): T extends () => any ? CallbackAssertion : ValueAssertion<T> {
    return new Assertion(actual) as any;
}

type ValueAssertion<T> = Omit<Assertion<T>, keyof CallbackAssertion>;

type CallbackAssertion = Pick<Assertion<any>, "throws">;

class Assertion<T> {
    constructor(private readonly actual: T | (() => any)) {}

    is(expected: T) {
        if (Array.isArray(expected) && Array.isArray(this.actual)) {
            if (expected.length != this.actual.length) {
                throw new AssertionError(`array length of \x1b[1m${expected.length}\x1b[22m was expected, but is \x1b[1m${this.actual.length}\x1b[22m`);
            }

            for (let i = 0; i < Math.max(expected.length, this.actual.length); i++) {
                if (!eq(expected[i], this.actual[i])) {
                    throw new AssertionError(`(#${i} element) \x1b[1m${expected[i]}\x1b[22m was expected, but got \x1b[1m${this.actual[i]}\x1b[22m`);
                }
            }
        } else if (!eq(expected, this.actual)) {
            throw new AssertionError(`\x1b[1m${expected}\x1b[22m was expected, but got \x1b[1m${this.actual}\x1b[22m`);
        }
    }

    not(unexpected: T) {
        if (eq(unexpected, this.actual)) {
            throw new AssertionError(`\x1b[1m${unexpected}\x1b[22m was not expected`);
        }
    }

    throws(expectedMessage: string) {
        try {
            const value = isCallable(this.actual) ? this.actual() : this.actual;
            throw new AssertionError(`error message \x1b[1m${expectedMessage}\x1b[22m was expected, but got value \x1b[1m${value}\x1b[22m`);
        } catch (err: any) {
            if (err instanceof AssertionError) {
                throw err;
            } else {
                assert(err.message.replaceAll(/\x1b\[[^m]+m/g, "")).is(expectedMessage);
            }
        }
    }
}

class AssertionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "AssertionError";
    }
}

const ANY: any = {};

function eq(a: any, b: any) {
    return a === ANY || b === ANY ? true : a instanceof NativePointer || a instanceof NativeStruct ? a.equals(b) : a == b;
}

const isCallable = <T>(maybeFunction: T | (() => any)): maybeFunction is () => T => typeof maybeFunction === "function";
