export * from "./generated/api";
export * from "./generated/api.schemas";
export { setBaseUrl, setAuthTokenGetter, customFetch } from "./custom-fetch";
// ApiError carries the status and the parsed error body, which is the only way
// a caller can tell one refusal from another without matching on the message
// text a human is meant to read.
export { ApiError, ResponseParseError } from "./custom-fetch";
export type { AuthTokenGetter, ErrorType } from "./custom-fetch";
