import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import App from "@/App";
import type { User } from "@/lib/api";

import { fakeApi, type Routes } from "./fake-api";
import { adminUser } from "./fixtures";
import { baseRoutes } from "./pages";

interface Options {
  /** The signed-in user; null renders signed out. */
  user?: User | null;
  routes?: Routes;
  /** The project picked in the switcher; null = "All projects" (global admins). */
  activeProject?: number | null;
}

/** Renders the whole app at `path` against a fake API, as `user`. */
export function renderApp(path: string, { user = adminUser(), routes = {}, activeProject = 1 }: Options = {}) {
  localStorage.setItem("ansideck.activeProject", activeProject === null ? "all" : String(activeProject));
  const api = fakeApi({ ...baseRoutes(user), ...routes });
  const view = render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
  return { ...view, api, user: userEvent.setup(), screen };
}

/** Picks an option in a Radix Select by its label. */
export async function choose(user: ReturnType<typeof userEvent.setup>, trigger: HTMLElement, option: string) {
  await user.click(trigger);
  await user.click(await screen.findByRole("option", { name: option }));
}
