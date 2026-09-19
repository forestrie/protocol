// Verify the frozen golden sets and the cross-language fixtures with the
// published verifier, pinned in package.json. Run from anywhere:
//   npm ci --prefix scripts/verify-golden && node scripts/verify-golden/verify.mjs
// Expected results are stated in vectors/README.md; this script asserts them.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  decodeGrantResponse,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import { calculateRoot } from "@forestrie/merklelog";
import {
  checkpointConsistencyProof,
  importEs256PublicKeyFromGrantDataXy64,
  parseReceipt,
  verifyCheckpointChain,
  verifyGrantReceiptOffline,
} from "@forestrie/receipt-verify";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VECTORS = join(ROOT, "vectors");
const hex = (h) => new Uint8Array(Buffer.from(h, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const uuidBytes = (u) => hex(u.replace(/-/g, ""));
const read = (...p) => new Uint8Array(readFileSync(join(VECTORS, ...p)));
const readJson = (...p) => JSON.parse(readFileSync(join(VECTORS, ...p), "utf8"));
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

let failures = 0;
const check = (label, ok, detail = "") => {
  console.log(`${ok ? "ok  " : "FAIL"} ${label}${ok || !detail ? "" : `: ${detail}`}`);
  if (!ok) failures++;
};

// --- fixtures: the published codec must accept every positive vector and reject every negative one
for (const v of readJson("fixtures", "grant_vectors.json")) {
  let ok = false, detail = "";
  try {
    const { grant, idtimestamp } = decodeGrantResponse(hex(v.expected_cbor_hex));
    ok =
      toHex(idtimestamp) === v.idtimestamp_hex.padStart(16, "0") &&
      toHex(grant.grantData) === v.grant_data_hex &&
      grant.maxHeight === v.max_height &&
      grant.minGrowth === v.min_growth;
    if (!ok) detail = "decoded fields differ from the vector's inputs";
  } catch (e) {
    detail = e.message;
  }
  check(`grant_vectors.json: decodes: ${v.description}`, ok, detail);
}
for (const v of readJson("fixtures", "grant_vectors_negative.json")) {
  let rejected = false, detail = "accepted";
  try {
    decodeGrantResponse(hex(v.cbor_hex));
  } catch (e) {
    rejected = true;
    detail = e.message;
  }
  check(`grant_vectors_negative.json: rejected: ${v.description}`, rejected, detail);
}

// --- golden grant receipt: verifies from this repository alone
{
  const m = readJson("golden", "manifest.json");
  const genesisCbor = read("golden", "grant-genesis.cbor");
  const receiptCbor = read("golden", "grant-receipt.cbor");
  check("golden: grant-genesis.cbor digest matches manifest", sha256(genesisCbor) === m.genesisSha256);
  check("golden: grant-receipt.cbor digest matches manifest", sha256(receiptCbor) === m.receiptSha256);
  const grant = {
    logId: uuidBytes(m.logId),
    ownerLogId: uuidBytes(m.ownerLogId),
    grant: hex(m.grantFlagsHex),
    maxHeight: m.maxHeight,
    minGrowth: m.minGrowth,
    grantData: hex(m.grantDataHex),
  };
  const idtimestampBe8 = hex(m.idtimestampBe8Hex);
  const run = (input) => verifyGrantReceiptOffline({ genesisCbor, receiptCbor, grant, idtimestampBe8, ...input });
  const clean = await run({});
  check("golden: clean receipt verifies at stage binding", clean.ok === true && clean.stage === "binding", JSON.stringify(clean));
  const tamperedReceipt = receiptCbor.slice();
  tamperedReceipt[tamperedReceipt.length - 1] ^= 0xff;
  const r1 = await run({ receiptCbor: tamperedReceipt });
  check("golden: flipped receipt byte fails signature_invalid", !r1.ok && r1.reason === "signature_invalid", JSON.stringify(r1));
  const tamperedGenesis = genesisCbor.slice();
  tamperedGenesis[tamperedGenesis.length - 1] ^= 0xff;
  const r2 = await run({ genesisCbor: tamperedGenesis });
  check("golden: flipped genesis byte fails genesis_invalid", !r2.ok && r2.reason === "genesis_invalid", JSON.stringify(r2));
  const wrongIdts = idtimestampBe8.slice();
  wrongIdts[7] ^= 0x01;
  const r3 = await run({ idtimestampBe8: wrongIdts });
  check("golden: wrong idtimestamp fails signature_invalid", !r3.ok && r3.reason === "signature_invalid", JSON.stringify(r3));
}

// --- burial bundle: the chain folds, the old peak is buried yet proven
{
  const m = readJson("golden", "burial", "manifest.json");
  const checkpoints = m.checkpointFiles.map((f) => read("golden", "burial", f));
  const receiptCbor = read("golden", "burial", "burial-receipt.cbor");
  checkpoints.forEach((cp, i) => check(`burial: ${m.checkpointFiles[i]} digest matches manifest`, sha256(cp) === m.checkpointSha256[i]));
  check("burial: burial-receipt.cbor digest matches manifest", sha256(receiptCbor) === m.receiptSha256);
  const key = await importEs256PublicKeyFromGrantDataXy64(hex(m.publicKeyXyHex));
  const verifySignature = (bytes, detachedPayload) => verifyCoseSign1WithParsedKey(bytes, key, { detachedPayload });
  const fold = checkpoints.map((cp) => checkpointConsistencyProof(cp)).map((p) => `${p.treeSize1}->${p.treeSize2}`).join(" ");
  check("burial: fold is 0->3 3->7 7->10 10->15", fold === "0->3 3->7 7->10 10->15", fold);
  const chain = await verifyCheckpointChain({ checkpoints, verifySignature });
  check("burial: chain verifies", chain.ok === true, JSON.stringify(chain.ok ? {} : chain));
  if (chain.ok) {
    check("burial: final accumulator matches manifest", JSON.stringify(chain.accumulator.map(toHex)) === JSON.stringify(m.finalAccumulatorHex));
    const buried = hex(m.buriedPeakHex);
    check("burial: buried peak absent from final accumulator", !chain.accumulator.some((p) => same(p, buried)));
    check("burial: buried peak present in link 0", chain.links[0].accumulator.some((p) => same(p, buried)));
    const { proof } = parseReceipt(receiptCbor);
    const leafIdx = proof.leafIndex ?? proof.mmrIndex;
    check("burial: receipt leaf index matches manifest", String(leafIdx) === m.leafMmrIndex);
    const hasher = {
      chunks: [],
      reset() { this.chunks = []; },
      update(data) { this.chunks.push(data); },
      async digest() { return new Uint8Array(createHash("sha256").update(Buffer.concat(this.chunks)).digest()); },
    };
    const peak = await calculateRoot(hasher, hex(m.leafHashHex), proof, leafIdx);
    check("burial: receipt path recomputes the buried peak", same(peak, buried));
    check("burial: receipt signature verifies over the recomputed peak", await verifySignature(receiptCbor, peak));
    const tampered = receiptCbor.slice();
    tampered[tampered.length - 1] ^= 0xff;
    check("burial: flipped receipt byte fails signature", !(await verifySignature(tampered, peak)));
  }
  for (let i = 0; i < checkpoints.length; i++) {
    const mutated = checkpoints.map((cp) => cp.slice());
    mutated[i][mutated[i].length - 1] ^= 0xff;
    const r = await verifyCheckpointChain({ checkpoints: mutated, verifySignature });
    check(`burial: flipped byte in ${m.checkpointFiles[i]} breaks the fold at link ${i}`, !r.ok && r.at === i);
  }
}

console.log(`${failures ? "FAIL" : "OK"}: ${failures} failure(s)`);
process.exit(failures ? 1 : 0);
