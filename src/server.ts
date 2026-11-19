import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createIssuer } from './lib/issuer.ts';
import type { Handler } from './lib/network.ts';
import { createVerifier } from './lib/verifier.ts';

export interface Served {
  origin: string;
  close(): Promise<void>;
}

export function serve(handler: Handler, port = 0): Promise<Served> {
  const server = createServer(async (incoming, outgoing) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of incoming) chunks.push(chunk);
      const hasBody = incoming.method !== 'GET' && incoming.method !== 'HEAD';
      const request = new Request(`http://${incoming.headers.host}${incoming.url}`, {
        method: incoming.method,
        headers: incoming.headers as Record<string, string>,
        body: hasBody ? Buffer.concat(chunks) : undefined,
      });
      const response = await handler(request);
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      outgoing.writeHead(500).end();
    }
  });

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const { port: bound } = server.address() as AddressInfo;
      resolve({
        origin: `http://127.0.0.1:${bound}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

if (import.meta.main) {
  const card = {
    vct: 'urn:example:resident-card',
    name: 'Resident card',
    disclosable: ['given_name', 'family_name', 'birthdate', 'locality', 'age_over_18'],
  };
  let issuerHandler: Handler;
  let verifierHandler: Handler;
  const issuerServer = await serve((request) => issuerHandler(request), 4001);
  const verifierServer = await serve((request) => verifierHandler(request), 4002);
  const issuer = await createIssuer({ origin: issuerServer.origin, name: 'City Hall', credentials: { 'resident-card': card } });
  const verifier = createVerifier({
    origin: verifierServer.origin,
    name: 'Cinema',
    trustedIssuers: [issuerServer.origin],
    fetch,
  });
  issuerHandler = issuer.handle;
  verifierHandler = verifier.handle;

  const offer = issuer.offer('resident-card', {
    given_name: 'Ana',
    family_name: 'García',
    birthdate: '1990-04-12',
    locality: 'Barcelona',
    age_over_18: true,
  });
  const request = verifier.request({ id: 'card', vct: card.vct, claims: ['age_over_18'] });
  console.log(`Issuer   ${issuerServer.origin}`);
  console.log(`Verifier ${verifierServer.origin}\n`);
  console.log(`Credential offer:\n${offer.uri}\n`);
  console.log(`Presentation request:\n${request.uri}`);
}
