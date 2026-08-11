/**
 * The checks that are easier — or only possible — with a real TLS stack.
 *
 * The hand-written prober cannot finish a handshake, so anything that lives
 * after it (the certificate chain of a TLS 1.3-only server, ALPN in TLS 1.3,
 * session resumption, the trust verdict against the Mozilla CA list) is done
 * here with Node's own `tls` module.
 *
 * Certificates are never rejected: an expired or untrusted certificate is the
 * interesting case, not an error, so verification is asked for and reported
 * rather than enforced.
 */

import tls from 'node:tls';

import { pace } from '@sharapov/service-kit';

const DEFAULT_ALPN = ['h2', 'http/1.1'];

/**
 * One full handshake.
 * @returns {Promise<object>} always resolves; failures come back as `{ ok:false, error }`
 */
export async function tlsInspect({
  host, ip, port = 443, servername, timeout = 10000,
  alpn = DEFAULT_ALPN, session, minVersion, maxVersion, triggerTicket = false,
}) {
  await pace();
  return new Promise(resolve => {
    const started = Date.now();
    let settled = false;
    let ocspResponse = null;
    let ticket = null;

    const options = {
      host: ip || host,
      port,
      servername: servername ?? (host && !/^\d|:/.test(host) ? host : undefined),
      rejectUnauthorized: false,
      requestOCSP: true,
      ALPNProtocols: alpn,
      session,
      timeout,
    };
    if (minVersion) options.minVersion = minVersion;
    if (maxVersion) options.maxVersion = maxVersion;

    let socket;
    try {
      socket = tls.connect(options);
    } catch (err) {
      return resolve({ ok: false, error: err.message });
    }

    const finish = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(value);
    };

    const timer = setTimeout(() => finish({ ok: false, error: 'timeout' }), timeout);

    socket.on('OCSPResponse', response => { ocspResponse = response; });
    socket.on('session', value => { ticket = value; });
    socket.on('error', err => finish({ ok: false, error: err.code || err.message }));

    socket.on('secureConnect', () => {
      const cipher = socket.getCipher() || {};
      const result = {
        ok: true,
        protocol: socket.getProtocol(),
        cipher: cipher.name,
        cipherStandard: cipher.standardName,
        cipherVersion: cipher.version,
        alpnProtocol: socket.alpnProtocol || null,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        ephemeralKey: socket.getEphemeralKeyInfo?.() || null,
        sessionReused: socket.isSessionReused(),
        chain: peerChain(socket),
        ocspResponse,
        elapsedMs: Date.now() - started,
      };

      // A TLS 1.3 ticket arrives after the handshake, and plenty of servers
      // only send one once the client has said something. When resumption is
      // what is being measured, an ordinary request is made to draw it out.
      if (!ticket && (triggerTicket || result.protocol === 'TLSv1.3')) {
        if (triggerTicket) {
          const name = servername || host;
          socket.write(`GET / HTTP/1.1\r\nHost: ${name}\r\nUser-Agent: myssl\r\nConnection: close\r\n\r\n`);
          socket.resume();
        }
        const wait = triggerTicket ? 1500 : 300;
        const ticketTimer = setTimeout(() => finish({ ...result, session: ticket, ocspResponse }), wait);
        socket.once('session', value => {
          clearTimeout(ticketTimer);
          finish({ ...result, session: value, ocspResponse });
        });
        return;
      }
      finish({ ...result, session: ticket, ocspResponse });
    });
  });
}

/** The chain exactly as the peer presented it, in DER. */
function peerChain(socket) {
  const chain = [];
  const seen = new Set();
  let cert = socket.getPeerCertificate(true);
  while (cert && cert.raw && !seen.has(cert.fingerprint256)) {
    seen.add(cert.fingerprint256);
    chain.push(Buffer.from(cert.raw));
    cert = cert.issuerCertificate;
  }
  return chain;
}

/**
 * Does the server let a client skip a full handshake next time?
 *
 * Two connections: the first collects a session, the second offers it back.
 * Node reports whether the server accepted it.
 */
export async function checkResumption(target) {
  const first = await tlsInspect({ ...target, triggerTicket: true });
  if (!first.ok) return { supported: null, reason: first.error };
  if (!first.session) return { supported: false, reason: 'no-session-issued' };

  const second = await tlsInspect({ ...target, session: first.session });
  if (!second.ok) return { supported: null, reason: second.error };

  return {
    supported: Boolean(second.sessionReused),
    protocol: second.protocol,
  };
}

/**
 * Renegotiation initiated by the client. A server that allows it can be made to
 * burn CPU on demand; TLS 1.3 removed the feature altogether.
 */
export async function checkRenegotiation({ host, ip, port = 443, servername, timeout = 8000 }) {
  await pace();
  return new Promise(resolve => {
    let settled = false;
    const done = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(value);
    };

    const socket = tls.connect({
      host: ip || host, port,
      servername: servername ?? host,
      rejectUnauthorized: false,
      maxVersion: 'TLSv1.2',
      timeout,
    });
    const timer = setTimeout(() => done({ supported: null, reason: 'timeout' }), timeout);

    socket.on('error', err => done({ supported: false, reason: err.code || err.message }));
    socket.on('secureConnect', () => {
      if (socket.getProtocol() === 'TLSv1.3') return done({ supported: false, reason: 'tls13' });
      let started;
      try {
        started = socket.renegotiate({ rejectUnauthorized: false }, err => {
          done(err ? { supported: false, reason: err.code || err.message } : { supported: true });
        });
      } catch (err) {
        return done({ supported: false, reason: err.message });
      }
      if (started === false) done({ supported: false, reason: 'refused-locally' });
    });
  });
}
