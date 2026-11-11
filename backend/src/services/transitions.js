// FR-RESP-06: New -> Acknowledged -> Resolved | Blocked | False Positive (New may also be dismissed as FP)
export const ALLOWED = {
  new: ["acknowledged", "false_positive"],
  acknowledged: ["resolved", "blocked", "false_positive"],
  resolved: [], blocked: [], false_positive: [],
};
export const canTransition = (from, to) => (ALLOWED[from] || []).includes(to);
