/** Only public PDS surfaces are reachable through the public Worker. */
export function permitted(url: URL, host: string, handleDomain: string): boolean {
  if (url.protocol !== "https:" || url.port) return false;
  // Reject encodings rather than guessing how each downstream router decodes them.
  if (url.pathname.includes("%") || url.pathname.includes("\\")) return false;
  if (url.hostname !== host) {
    const suffix = `.${handleDomain}`;
    const label = url.hostname.endsWith(suffix) ? url.hostname.slice(0, -suffix.length) : "";
    return /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
      && url.pathname === "/.well-known/atproto-did";
  }
  const p = url.pathname;
  return !(/^\/(admin|metrics|internal|debug)(\/|$)/.test(p)
    || p.startsWith("/xrpc/vlpds.admin.")
    || p.startsWith("/xrpc/vlpds.internal."));
}

export function forwarded(request: Request): Request {
  const headers = new Headers(request.headers);
  // Never let callers impersonate the operator or provide a forged proxy chain.
  for (const name of [...headers.keys()]) {
    if (/^(forwarded|x-forwarded-|x-real-ip|tailscale-|remote-user|cf-access-)/i.test(name)) headers.delete(name);
  }
  const ip = request.headers.get("cf-connecting-ip");
  if (ip) headers.set("x-forwarded-for", ip);
  headers.set("x-forwarded-proto", "https");
  headers.set("host", new URL(request.url).hostname);
  return new Request(request, { headers });
}

/** The private container transport accepts HTTP; public URLs remain HTTPS. */
export function containerRequest(request: Request): Request {
  const url = new URL(request.url);
  url.protocol = "http:";
  return new Request(url, request);
}
