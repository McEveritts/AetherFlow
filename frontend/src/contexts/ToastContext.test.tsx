import { fireEvent, render, screen } from "@testing-library/react";
import { act } from "react";

import { ToastProvider, useToast } from "@/contexts/ToastContext";

function ToastProbe() {
  const { toasts, addToast, removeToast } = useToast();

  return (
    <div>
      <button onClick={() => addToast("Saved", "success")}>add</button>
      <button
        onClick={() => {
          if (toasts[0]) removeToast(toasts[0].id);
        }}
      >
        remove
      </button>
      <span data-testid="count">{toasts.length}</span>
      <span data-testid="message">{toasts[0]?.message ?? ""}</span>
    </div>
  );
}

describe("ToastContext", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  it("adds and removes toasts manually", () => {
    render(
      <ToastProvider>
        <ToastProbe />
      </ToastProvider>
    );

    fireEvent.click(screen.getByText("add"));
    expect(screen.getByTestId("count")).toHaveTextContent("1");
    expect(screen.getByTestId("message")).toHaveTextContent("Saved");

    fireEvent.click(screen.getByText("remove"));
    expect(screen.getByTestId("count")).toHaveTextContent("0");
  });

  it("auto-removes toast after timeout", () => {
    render(
      <ToastProvider>
        <ToastProbe />
      </ToastProvider>
    );

    fireEvent.click(screen.getByText("add"));
    expect(screen.getByTestId("count")).toHaveTextContent("1");

    act(() => {
      jest.advanceTimersByTime(4000);
    });

    expect(screen.getByTestId("count")).toHaveTextContent("0");
  });
});
