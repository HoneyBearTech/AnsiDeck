import { EditorView } from "@codemirror/view";
import { act } from "@testing-library/react";

/** The CodeMirror view behind an editor's textbox (found by its label, e.g. getByRole("textbox", { name })). */
function viewOf(textbox: HTMLElement): EditorView {
  const view = EditorView.findFromDOM(textbox);
  if (!view) throw new Error("not a code editor");
  return view;
}

export function editorText(textbox: HTMLElement): string {
  return viewOf(textbox).state.doc.toString();
}

/** Replaces the editor's text as typing would (it reaches the page's onChange). */
export function setEditorText(textbox: HTMLElement, text: string): void {
  const view = viewOf(textbox);
  act(() => {
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text }, userEvent: "input" });
  });
}
