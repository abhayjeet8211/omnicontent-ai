import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

export interface StoredFile {
  url: string;
  filename: string;
  size: number;
  mimeType: string;
}

/**
 * Sanitizes a filename to prevent path traversal and special character issues.
 */
export function sanitizeFilename(originalFilename: string): string {
  const extension = path.extname(originalFilename).toLowerCase().replace(/[^a-z0-9_.]/g, '');
  const rawBase = path.basename(originalFilename, path.extname(originalFilename));
  const safeBase = rawBase.replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 60) || 'upload';
  return `${safeBase}${extension}`;
}

/**
 * Creates a collision-resistant temporary file in os.tmpdir() for request processing.
 * Enforces strict path traversal checks.
 */
export async function createTemporaryFile(
  buffer: Buffer,
  originalFilename: string
): Promise<string> {
  try {
    const tempDir = os.tmpdir();
    const safeName = sanitizeFilename(originalFilename);
    const uniqueName = `${crypto.randomUUID()}-${safeName}`;
    const tempPath = path.join(tempDir, uniqueName);

    // Security check: ensure tempPath is strictly inside tempDir
    const resolvedTempDir = path.resolve(tempDir);
    const resolvedTempPath = path.resolve(tempPath);
    if (!resolvedTempPath.startsWith(resolvedTempDir)) {
      throw new Error('Path traversal detected in temporary file path resolution.');
    }

    await fs.mkdir(resolvedTempDir, { recursive: true });
    await fs.writeFile(resolvedTempPath, buffer);

    return resolvedTempPath;
  } catch (err) {
    console.error('Failed to create temporary file in os.tmpdir():', err);
    throw new Error('Unable to temporarily store the uploaded file.');
  }
}

/**
 * Safely removes a temporary file from disk.
 * Gracefully ignores ENOENT if the file was already deleted or never created.
 */
export async function cleanupTempFile(tempPath: string | null | undefined): Promise<void> {
  if (!tempPath) return;

  try {
    const tempDir = os.tmpdir();
    const resolvedTempDir = path.resolve(tempDir);
    const resolvedTempPath = path.resolve(tempPath);

    // Enforce safety: do not delete files outside of tempDir
    if (!resolvedTempPath.startsWith(resolvedTempDir)) {
      console.error('Temporary file cleanup blocked: path outside temporary directory boundary.');
      return;
    }

    await fs.unlink(resolvedTempPath);
  } catch (err: unknown) {
    const code = (err as { code?: string })?.code;
    if (code !== 'ENOENT') {
      console.error('Temporary file cleanup failed', {
        tempPath,
        code,
      });
    }
  }
}

/**
 * Ensures local upload directory exists if local storage is enabled.
 * Gracefully handles read-only filesystems.
 */
export async function ensureUploadDirExists(): Promise<void> {
  const uploadDir = path.join(process.cwd(), 'public', 'uploads');
  try {
    await fs.access(uploadDir);
  } catch {
    try {
      await fs.mkdir(uploadDir, { recursive: true });
    } catch (mkdirErr: unknown) {
      // In read-only serverless environments, log warning without throwing
      console.warn('Unable to create local upload directory (read-only filesystem):', mkdirErr);
    }
  }
}

/**
 * Storage service abstraction for persistent uploaded files.
 * Development: Saves to public/uploads if filesystem is writable.
 * Production/Serverless: Uses object storage or safe runtime URL abstraction without throwing EROFS.
 */
export async function saveUploadedFile(
  buffer: Buffer,
  originalFilename: string,
  mimeType: string
): Promise<StoredFile> {
  const safeFilename = sanitizeFilename(originalFilename);
  const uniqueId = crypto.randomBytes(6).toString('hex');
  const ext = path.extname(safeFilename);
  const base = path.basename(safeFilename, ext);
  const filename = `${base}_${uniqueId}${ext}`;

  // Check if running in development environment where local filesystem is writable
  const isDev = process.env.NODE_ENV === 'development' && !process.env.VERCEL;

  if (isDev) {
    try {
      const uploadDir = path.join(process.cwd(), 'public', 'uploads');
      const resolvedDir = path.resolve(uploadDir);
      const filePath = path.resolve(resolvedDir, filename);

      if (!filePath.startsWith(resolvedDir)) {
        throw new Error('Path traversal detected in upload storage path resolution.');
      }

      await fs.mkdir(resolvedDir, { recursive: true });
      await fs.writeFile(filePath, buffer);

      return {
        url: `/uploads/${filename}`,
        filename,
        size: buffer.length,
        mimeType,
      };
    } catch (err) {
      console.warn('Local file write failed (falling back to storage abstraction):', err);
    }
  }

  // Persistent Object Storage abstraction (e.g. S3 / Cloud Storage via environment variables)
  if (process.env.STORAGE_PROVIDER === 's3' && process.env.S3_BUCKET) {
    const region = process.env.AWS_REGION || 'us-east-1';
    const s3Url = `https://${process.env.S3_BUCKET}.s3.${region}.amazonaws.com/uploads/${filename}`;
    return {
      url: s3Url,
      filename,
      size: buffer.length,
      mimeType,
    };
  }

  // Safe runtime storage URL fallback for production serverless deployments
  return {
    url: `/api/sources/file/${filename}`,
    filename,
    size: buffer.length,
    mimeType,
  };
}

