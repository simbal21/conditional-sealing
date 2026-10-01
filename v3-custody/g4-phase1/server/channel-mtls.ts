import type { IncomingMessage } from "node:http";
import type { ServerOptions } from "node:https";

export interface ChannelIdentity {
  readonly authenticated: boolean;
  readonly fingerprint256?: string;
  readonly subject?: string;
}

export function mtlsServerOptions(options: ServerOptions): ServerOptions {
  return {
    ...options,
    minVersion: "TLSv1.3",
    requestCert: true,
    rejectUnauthorized: true,
  };
}

export function getChannelIdentity(request: IncomingMessage): ChannelIdentity {
  const socket = request.socket as IncomingMessage["socket"] & {
    authorized?: boolean;
    getPeerCertificate?: () => { fingerprint256?: string; subject?: Record<string, string> };
  };
  const cert = socket.getPeerCertificate?.();
  return {
    authenticated: socket.authorized === true,
    fingerprint256: cert?.fingerprint256,
    subject: cert?.subject === undefined ? undefined : JSON.stringify(cert.subject),
  };
}

export function assertAuthorizedChannel(identity: ChannelIdentity, expectedFingerprint256?: string): void {
  if (!identity.authenticated) throw new Error("G4 channel mTLS authentication required");
  if (expectedFingerprint256 !== undefined && identity.fingerprint256 !== expectedFingerprint256) {
    throw new Error("G4 channel identity does not match G4AuthorityRegistry entry");
  }
}
