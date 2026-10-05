import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

import { FakeWebSocket } from "./fake-websocket";

// What jsdom lacks and Radix (Select, Dialog) or the live log viewer use.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;
Element.prototype.scrollTo ??= function scrollTo() {};
Element.prototype.scrollIntoView ??= function scrollIntoView() {};
Element.prototype.hasPointerCapture ??= () => false;
Element.prototype.setPointerCapture ??= () => {};
Element.prototype.releasePointerCapture ??= () => {};
globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;

afterEach(() => {
  cleanup();
  FakeWebSocket.instances.length = 0;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  localStorage.clear();
});
