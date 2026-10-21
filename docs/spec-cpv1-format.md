# Спецификация формата зашифрованного объекта `CPV1` (v1)

Все объекты данных (фотографии, миниатюры и файл-манифест `manifest.enc`), сохраняемые через `GoogleDriveStorageAdapter` или `SandboxStorageAdapter`, упаковываются в единый бинарный контейнер **`CPV1`**.

---

## 1. Бинарная структура файла (`.enc`)

Каждый зашифрованный файл имеет расширение `.enc`, MIME-тип `application/octet-stream` и состоит ровно из трех последовательных частей:

| Смещение (байты) | Длина (байты) | Поле | Описание |
| :--- | :--- | :--- | :--- |
| `0..3` | `4` | `Magic` | ASCII-строка `CPV1` (`0x43 0x50 0x56 0x31`). Гарантирует отличие от сигнатуры JPEG (`0xFF 0xD8 0xFF`). |
| `4` | `1` | `Version` | Версия формата: `0x01`. |
| `5..16` | `12` | `IV (Nonce)` | Случайный 96-битный вектор инициализации (`crypto.getRandomValues(new Uint8Array(12))`), уникальный для каждой операции шифрования. |
| `17..N-17` | `Переменная` | `Ciphertext` | Зашифрованные байты полезной нагрузки (`AES-256-GCM`). |
| `N-16..N-1` | `16` | `Auth Tag` | 128-битный тег аутентификации GCM (в Web Crypto API добавляется в конец буфера результата `crypto.subtle.encrypt` автоматически). |

* **Итоговый размер файла:** $\text{Размер открытых данных} + 5\text{ (Header)} + 12\text{ (IV)} + 16\text{ (Tag)} = \text{Размер} + 33\text{ байта}$.

---

## 2. Использование заголовка в AAD (Additional Authenticated Data)

Первые **5 байт** (`Magic` + `Version` = `0x43 0x50 0x56 0x31 0x01`) передаются в `AES-256-GCM` в качестве параметра `additionalData` (AAD):

```javascript
const CPV1_AAD = new Uint8Array([0x43, 0x50, 0x56, 0x31, 0x01]);

const ciphertextWithTag = await crypto.subtle.encrypt(
  {
    name: 'AES-GCM',
    iv: iv12Bytes,
    additionalData: CPV1_AAD,
    tagLength: 128,
  },
  dekKey,
  plaintextBuffer
);
```

Если злоумышленник или ошибка хранилища изменит хотя бы один байт в заголовке `CPV1\x01` или в `IV`, вызов `crypto.subtle.decrypt` завершится ошибкой проверки целостности (`OperationError`).

---

## 3. Структура `vault-meta.json` (открытые параметры хранилища)

Единственный незашифрованный служебный файл в хранилище, необходимый для восстановления доступа на новом устройстве или после очистки браузера:

```json
{
  "format": "CPV1",
  "version": 1,
  "createdAt": "2026-10-21T12:00:00Z",
  "kdf": {
    "algorithm": "PBKDF2",
    "hash": "SHA-256",
    "iterations": 600000,
    "saltBase64": "r4nd0m16Byt3S4ltInB4s364=="
  },
  "wrappedKey": {
    "algorithm": "AES-256-GCM",
    "aadHex": "4350563101",
    "ivBase64": "12Byt3IvB4s364==",
    "ciphertextBase64": "48Byt3sOfWr4pp3dD3kAnd16Byt3GcmT4g=="
  },
  "manifestObjectId": "manifest_object_id"
}
```

---

## 4. Структура `manifest.enc` (внутри `CPV1`)

После расшифровки `manifest.enc` ключом `DEK` получается UTF-8 JSON со списком фотографий и их миниатюрами:

```json
{
  "version": 1,
  "updatedAt": "2026-10-21T12:05:00Z",
  "items": [
    {
      "id": "b6d9f1a0-4c1b-4f88-9c12-001122334455",
      "blobObjectId": "drive_or_sandbox_id_123",
      "originalName": "cat-test.jpg",
      "mimeType": "image/jpeg",
      "sizeBytes": 184320,
      "createdAt": "2026-10-21T12:04:58Z",
      "thumbnailDataUrl": "data:image/jpeg;base64,/9j/4AAQSkZJRg..."
    }
  ]
}
```
