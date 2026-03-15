import { render, screen, waitFor } from "@testing-library/react";

import AuthGuard from "@/components/layout/AuthGuard";

const pushMock = jest.fn();
let pathnameMock = "/";
let authStateMock = {
  isAuthenticated: false,
  isLoading: false,
};

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  usePathname: () => pathnameMock,
}));

jest.mock("@/contexts/AuthContext", () => ({
  useAuth: () => authStateMock,
}));

describe("AuthGuard", () => {
  beforeEach(() => {
    pushMock.mockClear();
    pathnameMock = "/";
    authStateMock = {
      isAuthenticated: false,
      isLoading: false,
    };
  });

  it("shows loading state while auth is resolving", () => {
    authStateMock = { isAuthenticated: false, isLoading: true };

    render(
      <AuthGuard>
        <div>private</div>
      </AuthGuard>
    );

    expect(screen.getByText("Establishing secure connection...")).toBeInTheDocument();
  });

  it("redirects unauthenticated users away from protected routes", async () => {
    render(
      <AuthGuard>
        <div>private</div>
      </AuthGuard>
    );

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith("/login");
    });
    expect(screen.queryByText("private")).not.toBeInTheDocument();
  });

  it("renders children when authenticated", () => {
    authStateMock = { isAuthenticated: true, isLoading: false };

    render(
      <AuthGuard>
        <div>private</div>
      </AuthGuard>
    );

    expect(screen.getByText("private")).toBeInTheDocument();
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("does not redirect on login page", () => {
    pathnameMock = "/login";

    render(
      <AuthGuard>
        <div>login-page</div>
      </AuthGuard>
    );

    expect(pushMock).not.toHaveBeenCalled();
    expect(screen.getByText("login-page")).toBeInTheDocument();
  });
});
