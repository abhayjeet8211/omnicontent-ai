/**
 * Verification Test Suite for Storage Service & Temporary File Lifecycle
 */

import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import {
  createTemporaryFile,
  cleanupTempFile,
  sanitizeFilename,
  saveUploadedFile,
} from '../lib/storage';
import { SecurityValidationService } from '../lib/security';
import { parseDocumentBuffer } from '../lib/parsers/document';

let passedCount = 0;
let failedCount = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  \x1b[32m✔ PASS\x1b[0m: ${testName}`);
    passedCount++;
  } else {
    console.error(`  \x1b[31m✖ FAIL\x1b[0m: ${testName}${detail ? ` - ${detail}` : ''}`);
    failedCount++;
  }
}

async function runStorageLifecycleTests() {
  console.log('\n============================================================');
  console.log('📦  STORAGE SERVICE & TEMPORARY FILE LIFECYCLE TEST SUITE');
  console.log('============================================================\n');

  // -------------------------------------------------------------
  // Test 1: Temporary File Creation in os.tmpdir()
  // -------------------------------------------------------------
  console.log('\x1b[36m[Test 1] Temporary File Creation & Location\x1b[0m');
  const sampleBuffer = Buffer.from('%PDF-1.4 sample pdf content for testing temporary storage');
  const tempPath = await createTemporaryFile(sampleBuffer, 'OmniContent-AI_85c25823d1a7.pdf');

  const tempDir = os.tmpdir();
  assert(
    tempPath.startsWith(path.resolve(tempDir)),
    `Temporary file created strictly inside os.tmpdir(): ${tempPath}`
  );

  let fileExists = false;
  try {
    await fs.access(tempPath);
    fileExists = true;
  } catch {
    fileExists = false;
  }
  assert(fileExists, 'Temporary file successfully written to disk');

  // -------------------------------------------------------------
  // Test 2: Guaranteed Cleanup Lifecycle (Success Case)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test 2] Temporary File Cleanup Lifecycle (Success)\x1b[0m');
  await cleanupTempFile(tempPath);

  let existsAfterCleanup = true;
  try {
    await fs.access(tempPath);
  } catch {
    existsAfterCleanup = false;
  }
  assert(!existsAfterCleanup, 'Temporary file successfully deleted after cleanupTempFile()');

  // -------------------------------------------------------------
  // Test 3: Graceful ENOENT Handling (Idempotent Cleanup)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test 3] Graceful ENOENT Cleanup Handling\x1b[0m');
  let threwException = false;
  try {
    await cleanupTempFile(tempPath); // Call again on non-existent file
  } catch (err) {
    threwException = true;
  }
  assert(!threwException, 'cleanupTempFile handles ENOENT gracefully without throwing');

  // -------------------------------------------------------------
  // Test 4: Path Traversal Protection in Temporary Filename
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test 4] Path Traversal Protection on Temporary Filename\x1b[0m');
  const maliciousName = '../../../../etc/passwd';
  const sanitized = sanitizeFilename(maliciousName);
  assert(
    !sanitized.includes('/') && !sanitized.includes('..'),
    `Sanitized malicious name safe: ${sanitized}`
  );

  const maliciousTempPath = await createTemporaryFile(sampleBuffer, maliciousName);
  assert(
    maliciousTempPath.startsWith(path.resolve(tempDir)),
    'Path traversal attempt safely bound within os.tmpdir()'
  );
  await cleanupTempFile(maliciousTempPath);

  // -------------------------------------------------------------
  // Test 5: End-to-End Upload & Parse Lifecycle Simulation (PDF/DOCX/TXT/PNG)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test 5] End-to-End Upload Lifecycle with try/finally Cleanup\x1b[0m');

  const validPngBuf = Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
    0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
    0x15, 0xc4, 0x89,
  ]);

  const testFiles = [
    { name: 'test_doc.pdf', mime: 'application/pdf', buffer: Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF') },
    { name: 'test_text.txt', mime: 'text/plain', buffer: Buffer.from('Plain text document content for verification') },
    { name: 'test_image.png', mime: 'image/png', buffer: validPngBuf },
  ];

  for (const testFile of testFiles) {
    const fileBuf = testFile.buffer;
    let lifecycleTempPath: string | null = null;
    let processedSuccessfully = false;

    try {
      // 1. Create temp file
      lifecycleTempPath = await createTemporaryFile(fileBuf, testFile.name);
      
      // 2. Security validation
      const secRes = await SecurityValidationService.validateUploadedFile(fileBuf, testFile.name, testFile.mime);
      assert(secRes.accepted, `Security validation passed for ${testFile.name}`);

      // 3. Process document
      const parsed = await parseDocumentBuffer(fileBuf, secRes.scanResult.sanitizedFilename, secRes.scanResult.detectedMimeType);
      assert(!!parsed.metadata, `Parsed metadata generated for ${testFile.name}`);

      // 4. Save file via abstraction
      const stored = await saveUploadedFile(fileBuf, secRes.scanResult.sanitizedFilename, secRes.scanResult.detectedMimeType);
      assert(!!stored.url, `Stored file URL generated: ${stored.url}`);

      processedSuccessfully = true;
    } finally {
      // 5. Cleanup temp file
      if (lifecycleTempPath) {
        await cleanupTempFile(lifecycleTempPath);
        let existsEnd = true;
        try {
          await fs.access(lifecycleTempPath);
        } catch {
          existsEnd = false;
        }
        assert(!existsEnd, `Lifecycle temp file deleted after processing ${testFile.name}`);
      }
    }

    assert(processedSuccessfully, `Entire lifecycle completed cleanly for ${testFile.name}`);
  }

  // -------------------------------------------------------------
  // Test 6: Production Fallback (No EROFS Exception)
  // -------------------------------------------------------------
  console.log('\n\x1b[36m[Test 6] Storage Abstraction Production Fallback\x1b[0m');
  const prevEnv = process.env.NODE_ENV;
  (process.env as Record<string, string | undefined>).NODE_ENV = 'production';

  try {
    const prodResult = await saveUploadedFile(sampleBuffer, 'report.pdf', 'application/pdf');
    assert(!prodResult.url.includes('/var/task/public/uploads'), 'Production URL does not use /var/task/public/uploads');
    assert(!!prodResult.url, `Production URL generated safely: ${prodResult.url}`);
  } finally {
    (process.env as Record<string, string | undefined>).NODE_ENV = prevEnv;
  }

  console.log('\n============================================================');
  console.log(`TEST SUMMARY: ${passedCount} Passed, ${failedCount} Failed`);
  console.log('============================================================\n');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runStorageLifecycleTests().catch((err) => {
  console.error('Fatal storage test error:', err);
  process.exit(1);
});
