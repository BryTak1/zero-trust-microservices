import { describe, expect, it } from "vitest";
import { resolveUpstream } from "./proxy";

const upstreams = [{ prefix: "/api/documents", target: "http://resource/documents" }];

describe("resolveUpstream", () => {
  it("maps a public path onto its upstream", () => {
    expect(resolveUpstream(upstreams, "/api/documents")).toBe("http://resource/documents");
    expect(resolveUpstream(upstreams, "/api/documents/abc-123")).toBe(
      "http://resource/documents/abc-123",
    );
  });

  it("refuses paths no upstream owns", () => {
    expect(resolveUpstream(upstreams, "/api/other")).toBeUndefined();
    expect(resolveUpstream(upstreams, "/api/documents-private")).toBeUndefined();
  });

  it("refuses traversal and encoded segments", () => {
    expect(resolveUpstream(upstreams, "/api/documents/../health")).toBeUndefined();
    expect(resolveUpstream(upstreams, "/api/documents/%2e%2e/health")).toBeUndefined();
    expect(resolveUpstream(upstreams, "/api/documents//x")).toBeUndefined();
  });
});
