import { fetcher } from "@/lib/fetcher";

describe("fetcher", () => {
  afterEach(() => {
    jest.restoreAllMocks();
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
});
