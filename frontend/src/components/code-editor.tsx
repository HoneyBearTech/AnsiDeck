import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { yaml } from "@codemirror/lang-yaml";
import { bracketMatching, indentOnInput, syntaxHighlighting } from "@codemirror/language";
import { type Diagnostic, lintGutter, lintKeymap, setDiagnostics } from "@codemirror/lint";
import { Annotation, Compartment, EditorSelection, EditorState, type Text } from "@codemirror/state";
import {
  drawSelection,
  EditorView,
  highlightActiveLine,
  highlightActiveLineGutter,
  keymap,
  lineNumbers,
  placeholder as placeholderText,
} from "@codemirror/view";
import { classHighlighter } from "@lezer/highlight";
import * as React from "react";

import { cn } from "@/lib/utils";

/** A finding to mark in the editor: 1-based line, optional 1-based column. */
export interface EditorDiagnostic {
  line: number;
  column?: number | null;
  level: "error" | "warning";
  message: string;
}

export interface CodeEditorHandle {
  focus(): void;
  /** Moves the cursor to a line (and column) and scrolls it into view. */
  goTo(line: number, column?: number | null): void;
}

interface CodeEditorProps {
  /** The id of the element that labels the editor (its <Label>). */
  labelledBy: string;
  describedBy?: string | undefined;
  value: string;
  onChange?: ((value: string) => void) | undefined;
  /** Read-only text stays focusable and selectable (and is announced as read-only). */
  readOnly?: boolean | undefined;
  diagnostics?: EditorDiagnostic[] | undefined;
  placeholder?: string | undefined;
  className?: string | undefined;
  ref?: React.Ref<CodeEditorHandle> | undefined;
}

// CodeMirror styles these itself, so they go through its theme (which outranks its base theme); the
// variables come from index.css (.code-editor), so the colours stay the app's theme tokens.
const theme = EditorView.theme(
  {
    ".cm-gutters": {
      backgroundColor: "var(--editor-gutter)",
      color: "var(--editor-gutter-text)",
      borderRight: "1px solid var(--editor-border)",
      borderTopLeftRadius: "inherit",
      borderBottomLeftRadius: "inherit",
    },
    ".cm-activeLine": { backgroundColor: "var(--editor-active-line)" },
    ".cm-activeLineGutter": { backgroundColor: "var(--editor-active-gutter)", color: "var(--editor-foreground)" },
    "&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground": {
      backgroundColor: "var(--editor-selection)",
    },
    ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--editor-caret)" },
    ".cm-content": { caretColor: "var(--editor-caret)" },
  },
  { dark: true },
);

// Marks changes that come from the value prop (a load, a file upload), so they aren't echoed back.
const external = Annotation.define<boolean>();

function position(doc: Text, line: number, column?: number | null): { from: number; to: number } {
  const target = doc.line(Math.min(Math.max(1, line), doc.lines));
  const indent = target.text.length - target.text.trimStart().length;
  const offset = column ? Math.min(Math.max(0, column - 1), target.length) : indent;
  const from = target.from + offset;
  if (!column) return { from, to: target.to };
  // The word at the column, so the underline marks what the finding is about.
  const rest = target.text.slice(offset);
  const word = rest.match(/^\S+/)?.[0].length ?? 0;
  return { from, to: from + word };
}

function toDiagnostics(doc: Text, findings: EditorDiagnostic[]): Diagnostic[] {
  return findings.map((finding) => ({
    ...position(doc, finding.line, finding.column),
    severity: finding.level,
    message: finding.message,
  }));
}

/**
 * A YAML code editor (CodeMirror 6): syntax highlighting, line numbers, undo history and lint markers.
 * Tab isn't captured, so keyboard users can always move on; the colours come from the theme tokens in
 * index.css.
 */
export function CodeEditor({
  labelledBy,
  describedBy,
  value,
  onChange,
  readOnly = false,
  diagnostics,
  placeholder,
  className,
  ref,
}: CodeEditorProps) {
  const host = React.useRef<HTMLDivElement>(null);
  const view = React.useRef<EditorView | null>(null);
  const onChangeRef = React.useRef(onChange);
  const readOnlyCompartment = React.useRef(new Compartment());
  React.useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  // Created once; value, read-only mode and diagnostics are applied by the effects below.
  React.useEffect(() => {
    if (!host.current) return;
    const editor = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: value,
        extensions: [
          lineNumbers(),
          highlightActiveLineGutter(),
          highlightActiveLine(),
          drawSelection(),
          history(),
          indentOnInput(),
          bracketMatching(),
          yaml(),
          syntaxHighlighting(classHighlighter),
          lintGutter(),
          theme,
          keymap.of([...defaultKeymap, ...historyKeymap, ...lintKeymap]),
          EditorState.tabSize.of(2),
          readOnlyCompartment.current.of(EditorState.readOnly.of(readOnly)),
          EditorView.contentAttributes.of({
            "aria-labelledby": labelledBy,
            ...(describedBy ? { "aria-describedby": describedBy } : {}),
          }),
          ...(placeholder ? [placeholderText(placeholder)] : []),
          EditorView.updateListener.of((update) => {
            if (!update.docChanged || update.transactions.some((tr) => tr.annotation(external))) return;
            onChangeRef.current?.(update.state.doc.toString());
          }),
        ],
      }),
    });
    view.current = editor;
    return () => {
      editor.destroy();
      view.current = null;
    };
    // oxlint-disable-next-line react/exhaustive-deps -- created once; later changes go through the effects below
  }, []);

  React.useEffect(() => {
    const editor = view.current;
    if (!editor || editor.state.doc.toString() === value) return;
    editor.dispatch({
      changes: { from: 0, to: editor.state.doc.length, insert: value },
      annotations: external.of(true),
    });
  }, [value]);

  React.useEffect(() => {
    view.current?.dispatch({
      effects: readOnlyCompartment.current.reconfigure(EditorState.readOnly.of(readOnly)),
    });
  }, [readOnly]);

  React.useEffect(() => {
    const editor = view.current;
    if (!editor) return;
    editor.dispatch(setDiagnostics(editor.state, toDiagnostics(editor.state.doc, diagnostics ?? [])));
  }, [diagnostics]);

  React.useImperativeHandle(
    ref,
    () => ({
      focus: () => view.current?.focus(),
      goTo: (line, column) => {
        const editor = view.current;
        if (!editor) return;
        const { from } = position(editor.state.doc, line, column);
        editor.dispatch({
          selection: EditorSelection.cursor(from),
          effects: EditorView.scrollIntoView(from, { y: "center" }),
        });
        editor.focus();
      },
    }),
    [],
  );

  return <div ref={host} className={cn("code-editor", className)} />;
}
