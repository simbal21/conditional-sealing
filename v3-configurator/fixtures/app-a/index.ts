export { deadManSwitch, deadManSwitchSubmittedPda } from "./dead-man-switch.js";
export { evidenceArchival, evidenceArchivalSubmittedPda } from "./evidence-archival.js";
export { kycLending, kycLendingSubmittedPda } from "./kyc-lending.js";
export { mAndADeal, mAndADealSubmittedPda } from "./m-and-a-deal.js";
export { testament, testamentSubmittedPda } from "./testament.js";

import { deadManSwitchSubmittedPda } from "./dead-man-switch.js";
import { evidenceArchivalSubmittedPda } from "./evidence-archival.js";
import { kycLendingSubmittedPda } from "./kyc-lending.js";
import { mAndADealSubmittedPda } from "./m-and-a-deal.js";
import { testamentSubmittedPda } from "./testament.js";

export const APP_A_FIXTURES = [
  { name: "kyc-lending", submitted: kycLendingSubmittedPda },
  { name: "testament", submitted: testamentSubmittedPda },
  { name: "evidence-archival", submitted: evidenceArchivalSubmittedPda },
  { name: "m-and-a-deal", submitted: mAndADealSubmittedPda },
  { name: "dead-man-switch", submitted: deadManSwitchSubmittedPda },
] as const;
