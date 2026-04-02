import { apiFetch, fetcher } from "@/lib/fetcher";

describe("fetcher", () => {
  afterEach(() => {
    jest.restoreAllMocks();
    document.cookie = "csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  });

  it("returns parsed JSON for successful responses", async () => {
    const payload = { ok: true, value: 123 };
    jest.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => payload,
    } as Response);

    await expect(fetcher<typeof payload>("/api/test")).resolves.toEqual(payload);
  });

  it("throws an error with status for failed responses", async () => {
    jest.spyOn(global, "fetch").mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    } as Response);

    await expect(fetcher("/api/fail")).rejects.toMatchObject({
      message: "Request failed: 500 Internal Server Error",
      status: 500,
    });
  });

  it("applies default transport headers and credentials", async () => {
    const fetchMock = jest.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true }),
    } as Response);

    await apiFetch("/api/v1/admin/system/metrics");

    expect(fetchMock).toHaveBeenCalledWith("/api/v1/admin/system/metrics", expect.objectContaining({
      credentials: "include",
      headers: expect.any(Headers),
    }));

    const headers = fetchMock.mock.calls[0][1]?.headers as Headers;
    expect(headers.get("X-API-Version")).toBe("v1");
    expect(headers.get("Accept")).toBe("application/vnd.aetherflow.v1+json");
  });

  it("attaches the csrf token to auth-side mutating requests", async () => {
    document.cookie = "csrf_token=test-token; path=/";
    const fetchMock = jest.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true }),
    } as Response);

    await apiFetch("/api/v1/auth/logout", { method: "POST" });

    const headers = fetchMock.mock.calls[0][1]?.headers as Headers;
    expect(headers.get("X-CSRF-Token")).toBe("test-token");
  });
});
