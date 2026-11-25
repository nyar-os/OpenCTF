/**
 * Stable error surface of `@wae/open-ctf`.
 *
 * Codes are contract, not prose: callers compare them, localize around them and
 * never parse the message. A failure therefore keeps its code even when the
 * text is translated.
 */

/** Every stable code the inspection surface may report. */
export const errorCodes = [
    'binary/parse',
    'binary/range',
    'binary/unsupported',
    'binary/io',
    'handle/invalid',
    'capability/not-implemented',
] as const;

/** Union of {@link errorCodes}. */
export type CtfErrorCode = (typeof errorCodes)[number];

/** Optional locators a failure can carry so callers can point at the input. */
export interface CtfErrorDetails {
    readonly offset?: number;
    readonly length?: number;
    readonly handle?: number;
    readonly format?: string;
    /** Capability involved in the failure, e.g. `binary.patch`. */
    readonly feature?: string;
}

/** Options accepted by {@link CtfError}. */
export interface CtfErrorOptions {
    readonly recoverable?: boolean;
    readonly details?: CtfErrorDetails;
    readonly cause?: unknown;
}

/** Every failure thrown or rejected by this package. */
export class CtfError extends Error {
    /** Stable, comparable code. */
    readonly code: CtfErrorCode;
    /** Whether retrying with different input or state can succeed. */
    readonly recoverable: boolean;
    /** Optional locators (`offset`, `length`, `handle`, `format`, `feature`). */
    readonly details: CtfErrorDetails;

    constructor(code: CtfErrorCode, message: string, options: CtfErrorOptions = {}) {
        super(message, options.cause === undefined ? undefined : { cause: options.cause });
        this.name = 'CtfError';
        this.code = code;
        this.recoverable = options.recoverable ?? false;
        this.details = Object.freeze({ ...options.details });
    }
}

/**
 * Reported by declared methods whose backing capability is not wired yet.
 *
 * An absent addon is a declarative state, not a crash. The CLI reports the same
 * code the studio shows instead of inventing an empty result.
 */
export class NotImplementedError extends CtfError {
    constructor(feature: string, message = `\`${feature}\` is not implemented yet`) {
        super('capability/not-implemented', message, { recoverable: false, details: { feature } });
        this.name = 'NotImplementedError';
    }
}

const knownCodes = new Set<string>(errorCodes);

/**
 * Maps an unknown thrown value onto {@link CtfError}.
 *
 * The engine prefixes every message with its stable code; a message without a
 * known code becomes `binary/io` and keeps the original value as the cause.
 */
export function translateNativeError(error: unknown): CtfError {
    if (error instanceof CtfError) {
        return error;
    }
    const message = error instanceof Error ? error.message : String(error);
    const separator = message.indexOf(': ');
    const code = separator > 0 ? message.slice(0, separator) : '';
    if (knownCodes.has(code)) {
        return new CtfError(code as CtfErrorCode, message.slice(separator + 2), { details: { feature: code } });
    }
    return new CtfError('binary/io', message, { cause: error });
}

/** Narrows an unknown thrown value to {@link CtfError}. */
export function isCtfError(value: unknown): value is CtfError {
    return value instanceof CtfError;
}
