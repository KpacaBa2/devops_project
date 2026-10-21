/**
 * Модуль клиентской криптографии CPV1 (Web Crypto API)
 * Использует только стандартные примитивы: PBKDF2-HMAC-SHA256 и AES-256-GCM.
 * Первые 5 байт ("CPV1" + 0x01) передаются в AAD (Additional Authenticated Data).
 */

export const CPV1_AAD = new Uint8Array([0x43, 0x50, 0x56, 0x31, 0x01]); // "CPV1\x01"
export const IV_LENGTH = 12;
export const GCM_TAG_BITS = 128;
export const PBKDF2_ITERATIONS = 600000;

/**
 * Выводит ключ KEK (Key Encryption Key) из пароля пользователя и 16-байтной соли.
 */
export async function deriveKekFromPassword(password, saltUint8, iterations = PBKDF2_ITERATIONS) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltUint8,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Генерирует случайный 256-битный мастер-ключ DEK (Data Encryption Key).
 */
export async function generateDek() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Шифрует буфер открытых данных в бинарный контейнер CPV1:
 * [5 байт AAD: "CPV1\x01"] + [12 байт IV] + [Ciphertext + 16 байт GCM Auth Tag]
 */
export async function encryptCpv1(plaintextBuffer, dekCryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: CPV1_AAD,
      tagLength: GCM_TAG_BITS,
    },
    dekCryptoKey,
    plaintextBuffer
  );

  const cipherBytes = new Uint8Array(ciphertextBuffer);
  const out = new Uint8Array(CPV1_AAD.byteLength + iv.byteLength + cipherBytes.byteLength);
  out.set(CPV1_AAD, 0);
  out.set(iv, CPV1_AAD.byteLength);
  out.set(cipherBytes, CPV1_AAD.byteLength + iv.byteLength);
  return out;
}

/**
 * Проверяет заголовок CPV1\x01 и расшифровывает контейнер с проверкой AAD и GCM-тега.
 */
export async function decryptCpv1(packetUint8, dekCryptoKey) {
  if (packetUint8.byteLength < CPV1_AAD.byteLength + IV_LENGTH + 16) {
    throw new Error('INVALID_CPV1_PACKET_TOO_SHORT');
  }

  const header = packetUint8.slice(0, CPV1_AAD.byteLength);
  for (let i = 0; i < CPV1_AAD.byteLength; i++) {
    if (header[i] !== CPV1_AAD[i]) {
      throw new Error('INVALID_CPV1_HEADER_OR_VERSION');
    }
  }

  const iv = packetUint8.slice(CPV1_AAD.byteLength, CPV1_AAD.byteLength + IV_LENGTH);
  const ciphertextWithTag = packetUint8.slice(CPV1_AAD.byteLength + IV_LENGTH);

  const plainBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: header,
      tagLength: GCM_TAG_BITS,
    },
    dekCryptoKey,
    ciphertextWithTag
  );

  return new Uint8Array(plainBuffer);
}
