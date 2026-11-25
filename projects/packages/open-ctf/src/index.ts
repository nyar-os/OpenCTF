/**
 * Inspection surface of `@wae/open-ctf`.
 *
 * The API, report shapes and error contract are declared here; the built-in
 * engine answers every operation. Analysis never happens in this package, so
 * the CLI and the studio cannot disagree about a file.
 */

export { OpenCTF, capabilities } from './api.js';
export type { OpenCtfOptions } from './api.js';
export { GuiError, closeGui, defaultGuiContentDir, isGuiOpen, openGui, pumpEvents, runGui } from './gui.js';
export type { GuiCloseResult, GuiOpenResult, GuiStatus, OpenGuiOptions } from './gui.js';
export { CtfError, NotImplementedError, errorCodes, isCtfError, translateNativeError } from './errors.js';
export type { CtfErrorCode, CtfErrorDetails, CtfErrorOptions } from './errors.js';
export { nativeBinding } from './native.js';
export type { NativeBinding } from './native.js';
export type * from './types.js';
