export function shortSha(commit: string | null): string {
  return commit ? commit.slice(0, 8) : "";
}

/** A link to a commit on its forge (GitLab's path differs from GitHub's and Gitea's). */
export function commitLink(webUrl: string | null, commit: string | null): string | null {
  if (!webUrl || !commit) return null;
  const separator = webUrl.toLowerCase().includes("gitlab") ? "/-/commit/" : "/commit/";
  return `${webUrl.replace(/\/+$/, "")}${separator}${commit}`;
}

/** ssh:// or scp-style user@host:path (what needs an SSH deploy key). */
export function isSshUrl(url: string): boolean {
  const value = url.trim();
  return value.startsWith("ssh://") || (/^[^/:]+@[^/:]+:/.test(value) && !value.includes("://"));
}
