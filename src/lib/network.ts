export type Handler = (request: Request) => Promise<Response>;
export type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface Entry {
  origin: string;
  method: string;
  path: string;
  request: string;
  status: number;
  response: string;
}

export interface Network {
  fetch: Fetch;
  log: Entry[];
  mount(origin: string, handler: Handler): void;
  listen(listener: (entry: Entry) => void): void;
}

export function createNetwork(): Network {
  const handlers = new Map<string, Handler>();
  const listeners: ((entry: Entry) => void)[] = [];
  const log: Entry[] = [];

  const fetch: Fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const handler = handlers.get(url.origin);
    if (!handler) throw new TypeError(`fetch failed: nobody answers at ${url.origin}`);

    const sent = await request.clone().text();
    const response = await handler(request);
    const entry: Entry = {
      origin: url.origin,
      method: request.method,
      path: url.pathname,
      request: sent,
      status: response.status,
      response: await response.clone().text(),
    };
    log.push(entry);
    listeners.forEach((listener) => listener(entry));
    return response;
  };

  return {
    fetch,
    log,
    mount: (origin, handler) => void handlers.set(origin, handler),
    listen: (listener) => void listeners.push(listener),
  };
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
}
