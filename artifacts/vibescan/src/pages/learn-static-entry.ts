import { LEARN_CATEGORIES, LEARN_LAST_REVIEWED, checkManifest } from "./learn-checks";
import { renderLearnStatic, renderLearnMarkdown } from "./learn-static";

export { LEARN_LAST_REVIEWED };

/** Loaded by the build's prerender step; the page itself imports the data directly. */
export const learnStaticHtml = renderLearnStatic(LEARN_CATEGORIES);

/** The origin is a placeholder here; the build rewrites it like every other public file. */
export const learnStaticMarkdown = renderLearnMarkdown(LEARN_CATEGORIES, "https://seclayer.io");

/** One entry per check page: the server's list of valid /learn/<id> addresses and their metadata. */
export const learnCheckManifest = checkManifest();
