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

  it("transparently refreshes and retries when a request receives 401", async () => {
    const fetchMock = jest
      .spyOn(global, "fetch")
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ status: "success" }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ services: ["plex"] }),
      } as Response);

    const result = await fetcher<{ services: string[] }>("/api/v1/admin/services");
    expect(result).toEqual({ services: ["plex"] });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/auth/refresh");
  });

  it("dispatches af:session-expired when silent token refresh fails with 401", async () => {
    jest
      .spyOn(global, "fetch")
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      } as Response)
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      } as Response);

    const expiredListener = jest.fn();
    window.addEventListener("af:session-expired", expiredListener);

    const res = await apiFetch("/api/v1/admin/services");
    window.removeEventListener("af:session-expired", expiredListener);

    expect(res.status).toBe(401);
    expect(expiredListener).toHaveBeenCalledTimes(1);
  });

  describe("cancellation during shared authentication requests", () => {
    beforeEach(() => jest.resetModules());

    it("settles an aborted launch while CSRF is stalled without cancelling another caller", async () => {
      const { apiFetch: request } = await import("@/lib/fetcher");
      let completeCSRF!: (response: Response) => void;
      const csrf = new Promise<Response>(resolve => { completeCSRF = resolve; });
      const fetchMock = jest.spyOn(global, "fetch").mockImplementation(async input => {
        if (input === "/api/v1/public/csrf-token") return csrf;
        return { ok: true, status: 200 } as Response;
      });
      const controller = new AbortController();
      const launch = request("/api/v1/admin/system/update/run", { method: "POST", signal: controller.signal });
      const other = request("/api/v1/admin/settings", { method: "PUT" });
      const aborted = expect(launch).rejects.toMatchObject({ name: "AbortError" });
      controller.abort();
      await aborted;
      expect(fetchMock).toHaveBeenCalledTimes(1);
      completeCSRF({ ok: true, json: async () => ({ csrf_token: "fixture" }) } as Response);
      await expect(other).resolves.toMatchObject({ status: 200 });
      expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
        "/api/v1/public/csrf-token", "/api/v1/admin/settings",
      ]);
    });

    it("settles aborted status polling while refresh is stalled and preserves shared refresh", async () => {
      const { apiFetch: request } = await import("@/lib/fetcher");
      let completeRefresh!: (response: Response) => void;
      let markRefreshStarted!: () => void;
      const refresh = new Promise<Response>(resolve => { completeRefresh = resolve; });
      const refreshStarted = new Promise<void>(resolve => { markRefreshStarted = resolve; });
      let otherCalls = 0;
      const fetchMock = jest.spyOn(global, "fetch").mockImplementation(async input => {
        if (input === "/api/v1/auth/refresh") {
          markRefreshStarted();
          return refresh;
        }
        if (input === "/api/v1/auth/settings") otherCalls += 1;
        return { ok: otherCalls > 1, status: otherCalls > 1 ? 200 : 401 } as Response;
      });
      const expiredListener = jest.fn();
      window.addEventListener("af:session-expired", expiredListener);
      try {
        const controller = new AbortController();
        const polling = request("/api/v1/auth/system/update/status", { signal: controller.signal });
        await refreshStarted;
        const other = request("/api/v1/auth/settings");
        const aborted = expect(polling).rejects.toMatchObject({ name: "AbortError" });
        controller.abort();
        await aborted;
        completeRefresh({ ok: true, status: 200 } as Response);
        await expect(other).resolves.toMatchObject({ status: 200 });
        expect(fetchMock.mock.calls.filter(([url]) => url === "/api/v1/auth/refresh")).toHaveLength(1);
        expect(fetchMock.mock.calls.filter(([url]) => url === "/api/v1/auth/system/update/status")).toHaveLength(1);
        expect(expiredListener).not.toHaveBeenCalled();
      } finally {
        window.removeEventListener("af:session-expired", expiredListener);
      }
    });

    it("does not start an authentication request for an already aborted caller", async () => {
      const { apiFetch: request } = await import("@/lib/fetcher");
      const fetchMock = jest.spyOn(global, "fetch");
      const controller = new AbortController();
      controller.abort();
      await expect(request("/api/v1/admin/system/update/run", { method: "POST", signal: controller.signal }))
        .rejects.toMatchObject({ name: "AbortError" });
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  describe("OPUS-005: credential verification failures (403 INVALID_CURRENT_PASSWORD / INVALID_2FA_CODE)", () => {
    it("does not call refresh, does not set af_logout_sync, and does not dispatch af:session-expired on 403 INVALID_CURRENT_PASSWORD", async () => {
      document.cookie = "csrf_token=valid-csrf-token; path=/";
      const initialSync = "initial-sync-marker";
      window.localStorage.setItem("af_logout_sync", initialSync);
      const expiredListener = jest.fn();
      window.addEventListener("af:session-expired", expiredListener);

      const fetchMock = jest.spyOn(global, "fetch").mockResolvedValue({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: async () => ({
          code: "INVALID_CURRENT_PASSWORD",
          message: "Current password verification failed",
        }),
      } as Response);

      const res = await apiFetch("/api/v1/auth/profile/password", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current_password: "wrong", new_password: "new-password-123" }),
      });

      window.removeEventListener("af:session-expired", expiredListener);

      expect(res.status).toBe(403);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls.filter(([url]) => url === "/api/v1/auth/refresh")).toHaveLength(0);
      expect(expiredListener).not.toHaveBeenCalled();
      expect(window.localStorage.getItem("af_logout_sync")).toBe(initialSync);
    });

    it("does not call refresh, does not set af_logout_sync, and does not dispatch af:session-expired on 403 INVALID_2FA_CODE", async () => {
      document.cookie = "csrf_token=valid-csrf-token; path=/";
      const initialSync = "initial-sync-marker";
      window.localStorage.setItem("af_logout_sync", initialSync);
      const expiredListener = jest.fn();
      window.addEventListener("af:session-expired", expiredListener);

      const fetchMock = jest.spyOn(global, "fetch").mockResolvedValue({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: async () => ({
          code: "INVALID_2FA_CODE",
          message: "The provided 2FA code is invalid",
        }),
      } as Response);

      const res = await apiFetch("/api/v1/auth/user/2fa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: "000000" }),
      });

      window.removeEventListener("af:session-expired", expiredListener);

      expect(res.status).toBe(403);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls.filter(([url]) => url === "/api/v1/auth/refresh")).toHaveLength(0);
      expect(expiredListener).not.toHaveBeenCalled();
      expect(window.localStorage.getItem("af_logout_sync")).toBe(initialSync);
    });

    it("parses 403 APIError with code and verifies isSessionError is false", async () => {
      jest.spyOn(global, "fetch").mockResolvedValue({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: async () => ({
          code: "INVALID_CURRENT_PASSWORD",
          message: "Incorrect password",
        }),
      } as Response);

      await expect(fetcher("/api/v1/auth/profile/password")).rejects.toMatchObject({
        name: "APIError",
        status: 403,
        code: "INVALID_CURRENT_PASSWORD",
        isSessionError: false,
      });
    });
  });
});
