import { writeAll, Reader } from "./deps.ts";
import { readN } from "./utils.ts";

export const SOCKS_VERSION = 5;
export const USERNAME_PASSWORD_AUTH_VERSION = 1;
export enum AddrType {
  IPv4 = 1,
  DomainName = 3,
  IPv6 = 4,
}
export enum AuthMethod {
  NoAuth = 0,
  UsernamePassword = 2,
  NoneAcceptable = 0xff,
}
export enum ReplyStatus {
  Success = 0,
  GeneralError,
  RulesetError,
  NetworkUnreachable,
  HostUnreachable,
  ConnectionRefused,
  TTLExpired,
  UnsupportedCommand,
  UnsupportedAddress,
}
export enum Command {
  Connect = 1,
  Bind,
  UdpAssociate,
}

function decodeError(status: number) {
  switch (status) {
    case ReplyStatus.GeneralError:
      return "general SOCKS server failure";
    case ReplyStatus.RulesetError:
      return "connection not allowed by ruleset";
    case ReplyStatus.NetworkUnreachable:
      return "Network unreachable";
    case ReplyStatus.HostUnreachable:
      return "Host unreachable";
    case ReplyStatus.ConnectionRefused:
      return "Connection refused";
    case ReplyStatus.TTLExpired:
      return "TTL expired";
    case ReplyStatus.UnsupportedCommand:
      return "Command not supported";
    case ReplyStatus.UnsupportedAddress:
      return "Address type not supported";
    default:
      return "unknown SOCKS error";
  }
}

const v4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}/;
const v6Pattern = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
function serializeAddress(hostname: string, port: number) {
  const portBytes = [port >> 8, port % 256];
  if (v4Pattern.test(hostname)) {
    return Uint8Array.from([
      AddrType.IPv4,
      ...hostname.split(".").map(Number),
      ...portBytes,
    ]);
  }
  if (v6Pattern.test(hostname)) {
    return Uint8Array.from([
      AddrType.IPv6,
      ...hostname.split(":").flatMap((x) => {
        const num = parseInt(x, 16);
        return [num >> 8, num % 256];
      }),
      ...portBytes,
    ]);
  }

  const bytes = new TextEncoder().encode(hostname);
  return Uint8Array.from([
    AddrType.DomainName,
    bytes.length,
    ...bytes,
    ...portBytes,
  ]);
}

async function deserializeAddress(r: Reader) {
  const [type] = await readN(r, 1);
  const hostname = await (async () => {
    if (type === AddrType.IPv4) {
      const parts = [...(await readN(r, 4))];
      return { value: parts.map(String).join("."), length: 4 };
    }
    if (type === AddrType.IPv6) {
      const parts = [];
      const buff = await readN(r, 16);
      for (let i = 0; i < buff.length; i += 2) {
        parts.push((buff[i] << 8) + buff[i + 1]);
      }
      return { value: parts.map(String).join(":"), length: 16 };
    }
    if (type === AddrType.DomainName) {
      const [length] = await readN(r, 1);
      return {
        value: new TextDecoder().decode(await readN(r, length)),
        length: length + 1,
      };
    }

    throw new Error(`unexpected address type: ${type}`);
  })();

  const [portUpper, portLower] = await readN(r, 2);
  const port = (portUpper << 8) + portLower;
  return { hostname: hostname.value, port, bytesRead: hostname.length + 3 };
}

interface AddrConfig {
  hostname: string;
  port?: number;
}

interface AuthConfig {
  username: string;
  password: string;
}

export type ClientConfig = AddrConfig | (AddrConfig & AuthConfig);

export class Client {
  #config: Required<ClientConfig>;

  constructor(config: ClientConfig) {
    this.#config = {
      ...config,
      port: config.port ?? 1080,
    };
  }

  #connectAndRequest = async (cmd: Command, hostname: string, port: number) => {
    // @ts-ignore: lib
    const conn = await Deno.connect({
      hostname: this.#config.hostname,
      port: this.#config.port,
    });

    // handle auth negotiation
    const methods = [AuthMethod.NoAuth];
    if ("username" in this.#config) {
      methods.push(AuthMethod.UsernamePassword);
    }
    await writeAll(
      conn,
      Uint8Array.from([SOCKS_VERSION, methods.length, ...methods]),
    );
    const [negotiationVersion, method] = await readN(conn, 2);
    if (
      negotiationVersion !== SOCKS_VERSION ||
      method === AuthMethod.NoneAcceptable
    ) {
      try {
        conn.close();
      } catch {
        // ignore
      }
      throw new Error(
        negotiationVersion !== SOCKS_VERSION
          ? `unsupported SOCKS version number: ${negotiationVersion}`
          : "no acceptable authentication methods",
      );
    }

    if (method === AuthMethod.UsernamePassword) {
      const cfg = this.#config as AddrConfig & AuthConfig;
      const te = new TextEncoder();
      const username = te.encode(cfg.username);
      const password = te.encode(cfg.password);
      await writeAll(
        conn,
        Uint8Array.from([
          USERNAME_PASSWORD_AUTH_VERSION,
          username.length,
          ...username,
          password.length,
          ...password,
        ]),
      );
      const [authVersion, status] = await readN(conn, 2);
      if (
        authVersion !== USERNAME_PASSWORD_AUTH_VERSION ||
        status !== ReplyStatus.Success
      ) {
        try {
          conn.close();
        } catch {
          // ignore
        }
        throw new Error(
          authVersion !== USERNAME_PASSWORD_AUTH_VERSION
            ? `unsupported authentication version number: ${authVersion}`
            : "authentication failed",
        );
      }
    }

    // handle actual message
    await writeAll(
      conn,
      Uint8Array.from([
        SOCKS_VERSION,
        cmd,
        0,
        ...serializeAddress(hostname, port),
      ]),
    );
    const [replyVersion, status, _] = await readN(conn, 3);
    if (replyVersion !== SOCKS_VERSION || status !== ReplyStatus.Success) {
      try {
        conn.close();
      } catch {
        // ignore
      }
      throw new Error(
        replyVersion !== SOCKS_VERSION
          ? `unsupported SOCKS version number: ${replyVersion}`
          : decodeError(status),
      );
    }

    return {
      conn,
      ...(await deserializeAddress(conn)),
    };
  };

  // @ts-ignore: lib
  async connect(opts: Deno.ConnectOptions): Promise<Deno.TcpConn> {
    const remoteAddr = {
      hostname: opts.hostname ?? "127.0.0.1",
      port: opts.port,
      transport: "tcp",
    } as const;
    const { conn, hostname, port } = await this.#connectAndRequest(
      Command.Connect,
      remoteAddr.hostname,
      remoteAddr.port,
    );
    const localAddr = {
      hostname,
      port,
      transport: "tcp",
    } as const;

    return {
      setKeepAlive(keepalive?: boolean) {
        conn.setKeepAlive(keepalive);
      },
      setNoDelay(nodelay?: boolean) {
        conn.setNoDelay(nodelay);
      },
      get localAddr() {
        return localAddr;
      },
      get remoteAddr() {
        return remoteAddr;
      },
      get rid() {
        return conn.rid;
      },
      get readable() {
        return conn.readable;
      },
      get writable() {
        return conn.writable;
      },
      read: conn.read.bind(conn),
      write: conn.write.bind(conn),
      close: conn.close.bind(conn),
      closeWrite: conn.closeWrite.bind(conn),
      // @ts-ignore: lib
    } as unknown as Deno.TcpConn;
  }
}
