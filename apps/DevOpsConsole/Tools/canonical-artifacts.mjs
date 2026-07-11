import crypto from 'node:crypto';
import { promises as fsp } from 'node:fs';
import path from 'node:path';

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export const PROVENANCE_SCHEMA = Object.freeze({
  schema_version: 1,
  artifact_type: 'test-fixture-snapshot',
  source: 'isolated-test-fixture',
});

export const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

export function pngDimensions(data) {
  if (!Buffer.isBuffer(data) || data.length < 33 || !data.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error('invalid PNG signature');
  }
  if (data.subarray(12, 16).toString('ascii') !== 'IHDR' || data.readUInt32BE(8) !== 13) {
    throw new Error('PNG does not start with a valid IHDR chunk');
  }
  const width = data.readUInt32BE(16);
  const height = data.readUInt32BE(20);
  if (width < 1 || height < 1) throw new Error('PNG dimensions must be positive');
  return { width, height };
}

async function sourceEvidence(repoRoot, sourceFiles) {
  const records = [];
  for (const relative of [...sourceFiles].sort()) {
    const normalized = relative.split(path.sep).join('/');
    if (path.isAbsolute(relative) || normalized.startsWith('../')) {
      throw new Error(`source path must be repository-relative: ${relative}`);
    }
    const bytes = await fsp.readFile(path.join(repoRoot, relative));
    records.push({ path: normalized, sha256: sha256(bytes) });
  }
  const aggregate = records.map((item) => `${item.path}\0${item.sha256}\n`).join('');
  return { records, digest: sha256(Buffer.from(aggregate, 'utf8')) };
}

export async function buildProvenance({
  pngPath,
  repoRoot,
  fixtureId,
  generator,
  viewport,
  sourceFiles,
}) {
  const data = await fsp.readFile(pngPath);
  const { width, height } = pngDimensions(data);
  const source = await sourceEvidence(repoRoot, sourceFiles);
  return {
    ...PROVENANCE_SCHEMA,
    fixture_id: fixtureId,
    generator,
    width,
    height,
    sha256: sha256(data),
    viewport: { width: viewport.width, height: viewport.height },
    source_sha256: source.digest,
    source_files: source.records,
  };
}

export async function writeProvenance(options) {
  const provenance = await buildProvenance(options);
  const sidecar = `${options.pngPath}.provenance.json`;
  await fsp.writeFile(sidecar, `${JSON.stringify(provenance, null, 2)}\n`, 'utf8');
  return { sidecar, provenance };
}

export async function verifyArtifactPair(pngPath) {
  const data = await fsp.readFile(pngPath);
  const { width, height } = pngDimensions(data);
  const sidecar = `${pngPath}.provenance.json`;
  let provenance;
  try {
    provenance = JSON.parse(await fsp.readFile(sidecar, 'utf8'));
  } catch (error) {
    throw new Error(`missing or invalid provenance sidecar for ${path.basename(pngPath)}: ${error.message}`);
  }
  for (const [key, value] of Object.entries(PROVENANCE_SCHEMA)) {
    if (provenance[key] !== value) throw new Error(`provenance ${key} is invalid for ${path.basename(pngPath)}`);
  }
  for (const key of ['fixture_id', 'generator', 'source_sha256']) {
    if (typeof provenance[key] !== 'string' || !provenance[key]) {
      throw new Error(`provenance ${key} is missing for ${path.basename(pngPath)}`);
    }
  }
  if (provenance.sha256 !== sha256(data)) throw new Error(`provenance hash mismatch for ${path.basename(pngPath)}`);
  if (provenance.width !== width || provenance.height !== height) {
    throw new Error(`provenance dimensions mismatch for ${path.basename(pngPath)}`);
  }
  if (provenance.viewport?.width !== width || provenance.viewport?.height !== height) {
    throw new Error(`provenance viewport mismatch for ${path.basename(pngPath)}`);
  }
  if (!Array.isArray(provenance.source_files) || provenance.source_files.length === 0) {
    throw new Error(`provenance source_files is missing for ${path.basename(pngPath)}`);
  }
  return provenance;
}
