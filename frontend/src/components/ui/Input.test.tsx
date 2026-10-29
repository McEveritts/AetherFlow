import { fireEvent, render, screen } from "@testing-library/react";
import React from "react";
import { Input } from "@/components/ui/Input";

describe("Input", () => {
  it("renders with default glass-input styles and custom className", () => {
    render(<Input placeholder="Test input" className="custom-input-class" />);

    const input = screen.getByPlaceholderText("Test input");
    expect(input).toBeInTheDocument();
    expect(input).toHaveClass("glass-input");
    expect(input).toHaveClass("custom-input-class");
  });

  it("handles user typing and value updates", () => {
    const onChange = jest.fn();
    render(<Input placeholder="Type here" onChange={onChange} />);

    const input = screen.getByPlaceholderText("Type here");
    fireEvent.change(input, { target: { value: "AetherFlow" } });
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it("renders error state message when error string is passed", () => {
    render(<Input placeholder="Error field" error="Invalid field value" />);

    const errorMsg = screen.getByText("Invalid field value");
    expect(errorMsg).toBeInTheDocument();
    expect(errorMsg).toHaveClass("text-red-400");
  });
});
