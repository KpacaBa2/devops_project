/**
 * Два адаптера хранилища на фронтенде (без эмуляции Google Drive на бэкенде):
 * 1. GoogleDriveStorageAdapter — работает напрямую из браузера с Google Drive API v3 (scope: drive.file).
 * 2. SandboxStorageAdapter     — работает по простому REST с /api/sandbox/objects (для CI/CD и локальных тестов).
 */

export class GoogleDriveStorageAdapter {
  /**
   * @param {() => Promise<string>} getAccessTokenFn функция получения свежего access_token из памяти вкладки
   */
  constructor(getAccessTokenFn) {
    this.getAccessToken = getAccessTokenFn;
  }

  async putEncryptedObject(name, cpv1Uint8Array) {
    const token = await this.getAccessToken();
    const metadata = { name, mimeType: 'application/octet-stream' };
    const boundary = '-------cpv1_boundary_' + crypto.randomUUID();

    const metaPart =
      `--${boundary}\r\n` +
      `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
      `${JSON.stringify(metadata)}\r\n` +
      `--${boundary}\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`;
    const closePart = `\r\n--${boundary}--`;

    const body = new Blob([metaPart, cpv1Uint8Array, closePart]);
    const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': `multipart/related; boundary=${boundary}`,
      },
      body,
    });

    if (!res.ok) {
      throw new Error(`GDRIVE_UPLOAD_FAILED_${res.status}`);
    }
    return res.json(); // { id, name, mimeType }
  }

  async getEncryptedObject(fileId) {
    const token = await this.getAccessToken();
    const res = await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      throw new Error(`GDRIVE_DOWNLOAD_FAILED_${res.status}`);
    }
    return new Uint8Array(await res.arrayBuffer());
  }
}

export class SandboxStorageAdapter {
  constructor(baseUrl = '/api/sandbox/objects') {
    this.baseUrl = baseUrl;
  }

  async putEncryptedObject(name, cpv1Uint8Array) {
    const res = await fetch(this.baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Object-Name': name,
      },
      body: cpv1Uint8Array,
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `SANDBOX_UPLOAD_FAILED_${res.status}`);
    }
    return res.json(); // { id, name, size }
  }

  async getEncryptedObject(objectId) {
    const res = await fetch(`${this.baseUrl}/${encodeURIComponent(objectId)}`);
    if (!res.ok) {
      throw new Error(`SANDBOX_DOWNLOAD_FAILED_${res.status}`);
    }
    return new Uint8Array(await res.arrayBuffer());
  }
}
