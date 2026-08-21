"use strict";

const fs = require("node:fs");
const path = require("node:path");
const tdl = require("tdl");
const { getTdjson } = require("prebuilt-tdlib");

const TEST_API_ID = 94575;
const TEST_API_HASH = "a3406de8d171bb422bb6ddf3bbd800e2";
const SECRET_PATH = "/run/mtproxy/users.conf";
const PROXY_TIMEOUT_MS = 15_000;

function fail(message) {
  process.stderr.write(`probe: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(argv) {
  if (argv.length !== 4 || argv[0] !== "--domain" || argv[2] !== "--secrets-file" || argv[3] !== SECRET_PATH) {
    throw new Error("invalid invocation");
  }
  const domain = argv[1];
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain)) {
    throw new Error("invalid domain");
  }
  return domain.toLowerCase();
}

function parseSecrets(contents) {
  const records = contents.trimEnd().split("\n");
  if (records.length === 0 || records[0] === "") throw new Error("no secrets configured");
  const seen = new Set();
  return records.map((record) => {
    const match = /^([A-Za-z0-9_-]{1,64})=([0-9a-f]{32})$/.exec(record);
    if (!match || seen.has(match?.[1])) throw new Error("invalid secrets file");
    seen.add(match[1]);
    return match[2];
  });
}

function fakeTlsSecret(secret, domain) {
  return Buffer.from(`ee${secret}${Buffer.from(domain, "ascii").toString("hex")}`, "hex").toString("base64");
}

async function withTimeout(promise) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("timeout")), PROXY_TIMEOUT_MS);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function checkSecret(client, secret, domain) {
  const added = await withTimeout(client.invoke({
    _: "addProxy",
    proxy: {
      _: "proxy",
      server: domain,
      port: 443,
      type: { _: "proxyTypeMtproto", secret: fakeTlsSecret(secret, domain) },
    },
    enable: false,
  }));
  try {
    await withTimeout(client.invoke({ _: "pingProxy", proxy: added.proxy }));
  } finally {
    await client.invoke({ _: "removeProxy", proxy_id: added.id }).catch(() => undefined);
  }
}

async function main() {
  const domain = parseArguments(process.argv.slice(2));
  const secrets = parseSecrets(fs.readFileSync(SECRET_PATH, "utf8"));
  tdl.configure({ tdjson: getTdjson(), verbosityLevel: 0 });
  const client = tdl.createClient({
    apiId: TEST_API_ID,
    apiHash: TEST_API_HASH,
    databaseDirectory: path.join("/tmp", "tdlib-db"),
    filesDirectory: path.join("/tmp", "tdlib-files"),
    tdlibParameters: {
      use_message_database: false,
      use_secret_chats: false,
      system_language_code: "en",
      device_model: "mtproxy-respq-probe",
      system_version: "container",
      application_version: "1.0.0",
      enable_storage_optimizer: false,
      api_id: TEST_API_ID,
      api_hash: TEST_API_HASH,
      database_directory: path.join("/tmp", "tdlib-db"),
      files_directory: path.join("/tmp", "tdlib-files"),
    },
  });
  try {
    for (const secret of secrets) await checkSecret(client, secret, domain);
  } finally {
    await client.close().catch(() => undefined);
  }
  process.stdout.write(`probe: verified ${secrets.length} configured proxy secret(s)\n`);
}

main().catch(() => fail("MTProto proxy verification failed"));
