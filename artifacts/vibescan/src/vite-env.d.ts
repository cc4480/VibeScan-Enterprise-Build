/// <reference types="vite/client" />

/**
 * Public origin the bundle was built for, injected by vite.config.ts from the
 * APP_ORIGIN build arg. Never has a trailing slash.
 */
declare const __APP_ORIGIN__: string;
