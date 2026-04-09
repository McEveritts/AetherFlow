import { render, screen } from "@testing-library/react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";

describe("Card", () => {
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
