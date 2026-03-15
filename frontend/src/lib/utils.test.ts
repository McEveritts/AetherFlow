import { cn } from "@/lib/utils";

describe("cn", () => {
  it("merges conditional class values", () => {
    const value = cn("base", false && "hidden", "visible");
    expect(value).toContain("base");
    expect(value).toContain("visible");
    expect(value).not.toContain("hidden");
  });

  it("resolves tailwind class conflicts with latest value", () => {
    const value = cn("px-2", "px-4", "text-sm");
    expect(value).toContain("px-4");
    expect(value).not.toContain("px-2");
    expect(value).toContain("text-sm");
  });
});
