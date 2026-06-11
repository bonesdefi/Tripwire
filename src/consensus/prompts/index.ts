import type { CheckName, CheckPrompt } from '../types.js';
import { BOUNDS_AND_SANITY_V1 } from './bounds_and_sanity.js';
import { INTENT_MATCH_V1 } from './intent_match.js';
import { SOURCE_GROUNDING_V1 } from './source_grounding.js';

/** Current prompt template per check. Versions are pinned in the audit log. */
export const CHECK_PROMPTS: Record<CheckName, CheckPrompt> = {
  intent_match: INTENT_MATCH_V1,
  source_grounding: SOURCE_GROUNDING_V1,
  bounds_and_sanity: BOUNDS_AND_SANITY_V1,
};

export { BOUNDS_AND_SANITY_V1, INTENT_MATCH_V1, SOURCE_GROUNDING_V1 };
