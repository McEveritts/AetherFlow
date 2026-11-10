import { render, screen } from "@testing-library/react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";

describe("Card", () => {
  it("embeds page content without a floating glass surface", () => {
    render(
      <Card variant="embedded" data-testid="embedded-section" aria-label="Account settings">
        <CardContent>Settings</CardContent>
      </Card>
    );

    const section = screen.getByTestId("embedded-section");
    expect(section).toHaveClass("obs-canvas-section", "min-w-0", "max-w-full");
    expect(section).not.toHaveClass("glass-card", "glass-panel", "glass-hero");
    expect(section).toHaveAttribute("aria-label", "Account settings");
    expect(screen.getByText("Settings")).toBeInTheDocument();
  });

  it("renders panel variant and nested content", () => {
    render(
      <Card variant="panel" data-testid="card-root">
        <CardHeader>
          <CardTitle>System</CardTitle>
          <CardDescription>Live status</CardDescription>
        </CardHeader>
        <CardContent>Body</CardContent>
      </Card>
    );

    expect(screen.getByTestId("card-root")).toHaveClass("glass-panel");
    expect(screen.getByText("System")).toBeInTheDocument();
    expect(screen.getByText("Live status")).toBeInTheDocument();
    expect(screen.getByText("Body")).toBeInTheDocument();
  });
});
