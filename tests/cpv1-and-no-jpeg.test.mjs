import test from 'node:test';
import assert from 'node:assert/strict';
import { CPV1_AAD, generateDek, encryptCpv1, decryptCpv1 } from '../web/src/crypto/cpv1.js';
import { inspectUploadedBuffer } from '../api/server.js';

// Тестовый буфер, начинающийся с сигнатуры настоящего JPEG (FF D8 FF E0 ...)
const SAMPLE_JPEG = new Uint8Array([
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xff, 0xd9,
]);

test('Главный тест: зашифрованный CPV1 объект не содержит открытый заголовок JPEG и начинается с CPV1\\x01', async () => {
  const dek = await generateDek();
  const encrypted = await encryptCpv1(SAMPLE_JPEG, dek);

  // 1. Размер должен увеличиться ровно на 5 (AAD) + 12 (IV) + 16 (GCM Tag) = 33 байта
  assert.equal(encrypted.byteLength, SAMPLE_JPEG.byteLength + 33);

  // 2. Первые 5 байт обязаны быть "CPV1\x01"
  assert.deepEqual(encrypted.slice(0, 5), CPV1_AAD);

  // 3. Первые 3 байта НЕ должны быть сигнатурой JPEG (FF D8 FF)
  assert.notDeepEqual(encrypted.slice(0, 3), new Uint8Array([0xff, 0xd8, 0xff]));

  // 4. Расшифровка возвращает исходный JPEG байт-в-байт
  const decrypted = await decryptCpv1(encrypted, dek);
  assert.deepEqual(decrypted, SAMPLE_JPEG);
});

test('Проверка AAD: изменение байта версии в заголовке CPV1 приводит к ошибке аутентификации AES-GCM', async () => {
  const dek = await generateDek();
  const encrypted = await encryptCpv1(SAMPLE_JPEG, dek);

  // Подменяем байт версии 0x01 -> 0x02
  const tampered = new Uint8Array(encrypted);
  tampered[4] = 0x02;

  await assert.rejects(async () => {
    await decryptCpv1(tampered, dek);
  });
});

test('Серверная проверка (Sandbox REST): открытый JPEG отвергается, а зашифрованный CPV1 принимается', async () => {
  // Попытка отправить незашифрованный JPEG
  const rawCheck = inspectUploadedBuffer(Buffer.from(SAMPLE_JPEG));
  assert.equal(rawCheck.ok, false);
  assert.equal(rawCheck.error, 'PLAINTEXT_JPEG_REJECTED');

  // Отправка зашифрованного CPV1
  const dek = await generateDek();
  const encrypted = await encryptCpv1(SAMPLE_JPEG, dek);
  const encCheck = inspectUploadedBuffer(Buffer.from(encrypted));
  assert.equal(encCheck.ok, true);
});
