/**
 * The site's public origin, fixed at build time (see APP_ORIGIN in
 * vite.config.ts). Used for canonical URLs and the attribution line printed
 * into exported reports — both must name the domain the site is actually
 * served from, so neither may be hardcoded.
 */
export const APP_ORIGIN: string = __APP_ORIGIN__;

/** The origin without its scheme, for display ("secscan.us"). */
export const APP_DOMAIN: string = APP_ORIGIN.replace(/^https?:\/\//, "");
