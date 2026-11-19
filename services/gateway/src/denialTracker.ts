export type DenialTracker = {
  readonly record: (subjectId: string) => void;
  // How many denials this subject has had within the window.
  readonly count: (subjectId: string) => number;
};

// State lives in this gateway instance; several replicas would need a shared store such as Redis.
export const createDenialTracker = (
  windowMs: number,
  now: () => number = Date.now,
): DenialTracker => {
  const denials = new Map<string, readonly number[]>();
  const recent = (subjectId: string): readonly number[] => {
    const cutoff = now() - windowMs;
    return (denials.get(subjectId) ?? []).filter((at) => at > cutoff);
  };
  return {
    record: (subjectId) => {
      denials.set(subjectId, [...recent(subjectId), now()]);
    },
    count: (subjectId) => {
      const current = recent(subjectId);
      if (current.length === 0) {
        denials.delete(subjectId);
      }
      return current.length;
    },
  };
};
