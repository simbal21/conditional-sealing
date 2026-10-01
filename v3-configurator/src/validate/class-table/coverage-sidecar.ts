// S2-4 §5.4A — materialized coverage sidecar instance.

import {
  REQUIRED_CONDITION_MODULE_ROW_IDS,
  REQUIRED_VIEW_ROW_IDS,
  type CoverageSidecar,
} from "../../types/coverage-sidecar.js";

export const COVERAGE_SIDECAR: CoverageSidecar = {
  views: REQUIRED_VIEW_ROW_IDS,
  conditionModules: REQUIRED_CONDITION_MODULE_ROW_IDS,
};

