import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as React from "react";
import { describe, expect, it, vi } from "vitest";

import { editorText, setEditorText } from "@/test/editor";

import { CodeEditor, type CodeEditorHandle } from "./code-editor";

function Harness({
  initial = "a: 1\n",
  readOnly = false,
  onChange = () => {},
  diagnostics,
  editorRef,
}: {
  initial?: string;
  readOnly?: boolean;
  onChange?: (value: string) => void;
  diagnostics?: React.ComponentProps<typeof CodeEditor>["diagnostics"];
  editorRef?: React.Ref<CodeEditorHandle>;
}) {
  const [value, setValue] = React.useState(initial);
  return (
    <>
      <span id="label">Content</span>
      <CodeEditor
        labelledBy="label"
        value={value}
        readOnly={readOnly}
        diagnostics={diagnostics}
        ref={editorRef}
        onChange={(next) => {
          setValue(next);
          onChange(next);
        }}
      />
      <button type="button" onClick={() => setValue("replaced: true\n")}>
        Replace
      </button>
      <button type="button">After</button>
    </>
  );
}

describe("CodeEditor", () => {
  it("is a labelled multi-line textbox that reports edits", async () => {
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    const box = screen.getByRole("textbox", { name: "Content" });
    expect(box).toHaveAttribute("aria-multiline", "true");
    expect(editorText(box)).toBe("a: 1\n");
    setEditorText(box, "b: 2\n");
    expect(onChange).toHaveBeenLastCalledWith("b: 2\n");
  });

  it("takes a new value from outside without echoing it back", async () => {
    const onChange = vi.fn();
    render(<Harness onChange={onChange} />);
    await userEvent.click(screen.getByRole("button", { name: "Replace" }));
    expect(editorText(screen.getByRole("textbox", { name: "Content" }))).toBe("replaced: true\n");
    expect(onChange).not.toHaveBeenCalled();
  });

  it("is announced as read-only and still focusable", () => {
    render(<Harness readOnly />);
    const box = screen.getByRole("textbox", { name: "Content" });
    expect(box).toHaveAttribute("aria-readonly", "true");
  });

  it("marks findings in the gutter and the text", () => {
    const { container } = render(
      <Harness
        initial={"- hosts: all\n  tasks:\n    - shell: echo\n"}
        diagnostics={[
          { line: 3, column: 7, level: "error", message: "Use FQCN" },
          { line: 1, level: "warning", message: "Name the play" },
          { line: 99, level: "warning", message: "Past the end" },
        ]}
      />,
    );
    expect(container.querySelector(".cm-lintRange-error")).toHaveTextContent("shell:");
    expect(container.querySelectorAll(".cm-lintRange-warning").length).toBeGreaterThan(0);
  });

  it("goes to a line and leaves Tab to the page", async () => {
    const ref = React.createRef<CodeEditorHandle>();
    render(<Harness initial={"a: 1\nb: 2\nc: 3\n"} editorRef={ref} />);
    const box = screen.getByRole("textbox", { name: "Content" });
    React.act(() => ref.current?.goTo(2, 1));
    expect(box).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "Replace" })).toHaveFocus();
  });
});
