import { fireEvent, render, screen } from "@testing-library/react";

import { Button } from "@/components/ui/Button";

describe("Button", () => {
  it("renders with variant classes and custom className", () => {
    render(
      <Button variant="primary" className="custom-class">
        Save
      </Button>
    );

    const button = screen.getByRole("button", { name: "Save" });
    expect(button).toHaveClass("glass-button-primary");
    expect(button).toHaveClass("custom-class");
  });

  it("fires click handlers", () => {
    const onClick = jest.fn();
    render(<Button onClick={onClick}>Run</Button>);

    fireEvent.click(screen.getByRole("button", { name: "Run" }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});
