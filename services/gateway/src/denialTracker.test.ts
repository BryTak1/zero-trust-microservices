import { describe, expect, it } from "vitest";
import { createDenialTracker } from "./denialTracker";

const createClock = (start: number) => {
  let time = start;
  return { now: () => time, advance: (ms: number) => (time += ms) };
};

describe("createDenialTracker", () => {
  it("counts denials per subject within the window", () => {
    const clock = createClock(0);
    const tracker = createDenialTracker(60_000, clock.now);
    tracker.record("u1");
    tracker.record("u1");
    tracker.record("u2");
    expect(tracker.count("u1")).toBe(2);
    expect(tracker.count("u2")).toBe(1);
    expect(tracker.count("u3")).toBe(0);
  });

  it("forgets denials once they leave the window", () => {
    const clock = createClock(0);
    const tracker = createDenialTracker(60_000, clock.now);
    tracker.record("u1");
    clock.advance(30_000);
    tracker.record("u1");
    clock.advance(30_001);
    expect(tracker.count("u1")).toBe(1);
    clock.advance(30_000);
    expect(tracker.count("u1")).toBe(0);
  });
});
