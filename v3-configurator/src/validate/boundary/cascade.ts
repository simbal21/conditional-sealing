import type { BoundaryClassification, ClassifySurfaceSignature, Surface } from "./types.js";
import { asBoundaryContext, runTest1 } from "./test-1.js";
import { runTest15 } from "./test-1-5.js";
import { runTest2 } from "./test-2.js";
import { runTest3 } from "./test-3.js";

export const classifySurface: ClassifySurfaceSignature = (
  surface: Surface,
  context?: unknown,
): BoundaryClassification => {
  const boundaryContext = asBoundaryContext(context);
  const test1 = runTest1(surface, boundaryContext);
  if (test1 !== null) return test1;
  const test15 = runTest15(surface, boundaryContext);
  if (test15 !== null) return test15;
  const test2 = runTest2(surface, boundaryContext);
  if (test2 !== null) return test2;
  return runTest3(surface, boundaryContext);
};
