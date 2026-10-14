import { LEARN_CATEGORIES_A } from "./learn-data-a";
import { LEARN_CATEGORIES_B } from "./learn-data-b";
import { LEARN_CATEGORIES_C } from "./learn-data-c";
import { renderLearnStatic } from "./learn-static";

/** Loaded by the build's prerender step; the page itself imports the data directly. */
export const learnStaticHtml = renderLearnStatic([...LEARN_CATEGORIES_A, ...LEARN_CATEGORIES_B, ...LEARN_CATEGORIES_C]);
