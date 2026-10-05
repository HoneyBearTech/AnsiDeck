import { vi } from "vitest";

/** A WebSocket the test drives: `emit` delivers a message, `close` ends the stream. */
export class FakeWebSocket extends EventTarget {
  static instances: FakeWebSocket[] = [];
  readonly url: string;

  /** The `index`-th socket the page opened, once it has: pages connect in an effect, which can
   * run after the content a test waited for is already on screen. */
  static async opened(index = 0): Promise<FakeWebSocket> {
    return vi.waitFor(() => {
      const socket = FakeWebSocket.instances[index];
      if (!socket) throw new Error(`socket ${index} not opened yet`);
      return socket;
    });
  }

  constructor(url: string) {
    super();
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  open(): void {
    this.dispatchEvent(new Event("open"));
  }

  emit(data: unknown): void {
    this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(data) }));
  }

  close(code = 1000): void {
    this.dispatchEvent(new CloseEvent("close", { code }));
  }
}
