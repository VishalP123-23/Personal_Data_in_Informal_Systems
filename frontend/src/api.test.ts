import { describe, it, expect, vi, afterEach } from "vitest";
import { api } from "./api";
afterEach(() => vi.unstubAllGlobals());
describe("API client", () => {
  it("includes CSRF token in authenticated writes", async () => {
    vi.stubGlobal("document", { cookie: "clinic_csrf=demo-token" });
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ok:true})));
    vi.stubGlobal("fetch", fetch);
    await api("/api/consents", {method:"POST", body:"{}"});
    expect(fetch.mock.calls[0][1].headers.get("X-CSRF-Token")).toBe("demo-token");
    expect(fetch.mock.calls[0][1].credentials).toBe("include");
  });
  it("surfaces server errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({detail:"Access denied"}), {status:403})));
    await expect(api("/api/records/mine")).rejects.toThrow("Access denied");
  });
});
