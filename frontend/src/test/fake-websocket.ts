/** A WebSocket the test drives: `emit` delivers a message, `close` ends the stream. */
export class FakeWebSocket extends EventTarget {
  static instances: FakeWebSocket[] = [];
  readonly url: string;

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
