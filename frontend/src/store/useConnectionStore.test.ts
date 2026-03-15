import { useConnectionStore } from "@/store/useConnectionStore";

describe("useConnectionStore", () => {
  beforeEach(() => {
    useConnectionStore.setState({
      connectionState: "CONNECTING",
      reconnectAttempt: 0,
      lastMessageAt: null,
    });
  });

  it("updates connection state and reconnect metadata", () => {
    useConnectionStore.getState().setConnectionState("CONNECTED");
    useConnectionStore.getState().setReconnectAttempt(3);
    useConnectionStore.getState().setLastMessageAt(123456789);

    const state = useConnectionStore.getState();
    expect(state.connectionState).toBe("CONNECTED");
    expect(state.reconnectAttempt).toBe(3);
    expect(state.lastMessageAt).toBe(123456789);
  });

  it("resets key fields back to initial values", () => {
    useConnectionStore.setState({
      connectionState: "FALLBACK",
      reconnectAttempt: 5,
      lastMessageAt: 111,
    });

    useConnectionStore.getState().reset();
    const state = useConnectionStore.getState();

    expect(state.connectionState).toBe("CONNECTING");
    expect(state.reconnectAttempt).toBe(0);
    // reset() intentionally does not clear lastMessageAt in current implementation
    expect(state.lastMessageAt).toBe(111);
  });
});
