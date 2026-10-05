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
// The code editor (CodeMirror) measures text ranges; jsdom has no layout, so they measure as empty.
Range.prototype.getClientRects ??= function getClientRects() {
  return Object.assign([], { item: () => null }) as unknown as DOMRectList;
};
Range.prototype.getBoundingClientRect ??= () => new DOMRect();

afterEach(() => {
  cleanup();
  FakeWebSocket.instances.length = 0;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  localStorage.clear();
});
