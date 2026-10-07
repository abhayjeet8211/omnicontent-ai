import { NextResponse } from 'next/server';
import { parseDocumentBuffer } from '@/lib/parsers/document';
import { saveUploadedFile, createTemporaryFile, cleanupTempFile } from '@/lib/storage';
import { SecurityValidationService } from '@/lib/security';

export async function POST(req: Request) {
  let tempPath: string | null = null;

  try {
    const formData = await req.formData();
    const file = formData.get('file') as File | null;

    if (!file || typeof file.arrayBuffer !== 'function') {
      return NextResponse.json({ error: 'No file uploaded' }, { status: 400 });
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Create temporary file in os.tmpdir()
    try {
      tempPath = await createTemporaryFile(buffer, file.name);
    } catch (err: unknown) {
      console.error('Temporary storage write failed:', err);
      return NextResponse.json(
        {
          success: false,
          error: 'Unable to temporarily store the uploaded file.',
        },
        { status: 500 }
      );
    }

    // Security validation gateway
    const securityResult = await SecurityValidationService.validateUploadedFile(
      buffer,
      file.name,
      file.type || 'application/octet-stream'
    );

    if (!securityResult.accepted) {
      return NextResponse.json(
        {
          success: false,
          error: securityResult.userMessage || 'Security validation failed.',
          findings: securityResult.scanResult.findings,
        },
        { status: 400 }
      );
    }

    const safeFilename = securityResult.scanResult.sanitizedFilename;
    const safeMime = securityResult.scanResult.detectedMimeType;

    // Save using persistent storage abstraction
    const storedFile = await saveUploadedFile(buffer, safeFilename, safeMime);

    // Extract text content
    const parsed = await parseDocumentBuffer(buffer, safeFilename, safeMime);
    return NextResponse.json({
      success: true,
      parsed,
      fileUrl: storedFile.url,
      contentHash: securityResult.scanResult.contentHash,
      securityStatus: securityResult.scanResult.status,
    });
  } catch (err: unknown) {
    console.error('File parsing route error:', err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'File parsing failed' },
      { status: 500 }
    );
  } finally {
    if (tempPath) {
      await cleanupTempFile(tempPath);
    }
  }
}

