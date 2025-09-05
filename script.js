// Mengimpor fungsi ML-KEM (Kyber) level 768 dari pustaka @noble/post-quantum
// Ini sesuai dengan keamanan setara AES-192, keseimbangan yang baik antara keamanan dan kinerja.
import { ml_kem768 } from 'https://esm.sh/@noble/post-quantum@0.5.1/ml-kem.js';

document.addEventListener('DOMContentLoaded', () => {

    // --- DOM Element Selection ---
    const tabButtons = document.querySelectorAll('.tab-button');
    const contentSections = document.querySelectorAll('.content-section');
    
    // Key Generation elements
    const generateBtn = document.getElementById('generateBtn');
    const genPublicKeyEl = document.getElementById('genPublicKey');
    const genPrivateKeyEl = document.getElementById('genPrivateKey');
    const copyGenPublicBtn = document.getElementById('copyGenPublicBtn');
    const copyGenPrivateBtn = document.getElementById('copyGenPrivateBtn');

    // Encryption elements
    const publicKeyEl = document.getElementById('publicKey');
    const plainTextEl = document.getElementById('plainText');
    const encryptBtn = document.getElementById('encryptBtn');
    const encryptedTextEl = document.getElementById('encryptedText');
    const copyEncryptedBtn = document.getElementById('copyEncryptedBtn');

    // Decryption elements
    const privateKeyEl = document.getElementById('privateKey');
    const cipherTextEl = document.getElementById('cipherText');
    const decryptBtn = document.getElementById('decryptBtn');
    const decryptedTextEl = document.getElementById('decryptedText');
    const copyDecryptedBtn = document.getElementById('copyDecryptedBtn');

    // --- Tab Switching Logic ---
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            tabButtons.forEach(btn => btn.classList.remove('active'));
            contentSections.forEach(sec => sec.classList.remove('active'));
            button.classList.add('active');
            const targetTab = button.getAttribute('data-tab');
            document.getElementById(`${targetTab}-view`).classList.add('active');
        });
    });
    
    // --- Reusable Copy Function ---
    const setupCopyButton = (button, textarea) => {
        button.addEventListener('click', () => {
            const textToCopy = textarea.value;
            if (!textToCopy || textToCopy.startsWith('ERROR:')) return;
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalText = button.textContent;
                button.textContent = 'Tersalin!';
                button.classList.add('copied');
                setTimeout(() => {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            });
        });
    };

    // --- Helper Functions for Key Conversion ---
    const arrayBufferToBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const base64ToUint8Array = (base64) => Uint8Array.from(atob(base64), c => c.charCodeAt(0));

    // ===================================================================
    //                  CRYPTO LOGIC (HIBRIDA)
    // ===================================================================

    async function generateEcdhKeys() {
        return await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-384" },
            true, // extractable
            ["deriveKey"]
        );
    }

    function generateKyberKeys() {
        return ml_kem768.keygen();
    }

    async function deriveHybridKey(ecdhSecretKey, kyberSecretBytes) {
        const ecdhSecretBytes = new Uint8Array(await window.crypto.subtle.exportKey('raw', ecdhSecretKey));
        
        const combinedSecret = new Uint8Array(ecdhSecretBytes.length + kyberSecretBytes.length);
        combinedSecret.set(ecdhSecretBytes, 0);
        combinedSecret.set(kyberSecretBytes, ecdhSecretBytes.length);

        const importedKey = await window.crypto.subtle.importKey(
            'raw', combinedSecret, { name: 'HKDF' }, false, ['deriveKey']
        );

        return await window.crypto.subtle.deriveKey(
            { name: 'HKDF', salt: new Uint8Array(), info: new Uint8Array(), hash: 'SHA-256' },
            importedKey,
            { name: 'AES-GCM', length: 256 },
            false, // non-extractable
            ['encrypt', 'decrypt']
        );
    }

    async function encryptMessage(key, plaintext) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedPlaintext = new TextEncoder().encode(plaintext);
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, key, encodedPlaintext
        );
        return { iv, ciphertext };
    }

    async function decryptMessage(key, iv, ciphertext) {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, key, ciphertext
        );
        return new TextDecoder().decode(decrypted);
    }

    // --- Key Generation Logic ---
    generateBtn.addEventListener('click', async () => {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Membuat Kunci...';
        [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = 'Harap tunggu, proses pembuatan kunci hibrida...');

        try {
            const [ecdhKeyPair, kyberKeyPair] = await Promise.all([
                generateEcdhKeys(),
                generateKyberKeys()
            ]);

            const ecdhPublicKeyJwk = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey);
            const ecdhPrivateKeyJwk = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey);

            const hybridPublicKey = {
                ecdh: ecdhPublicKeyJwk,
                kyber: arrayBufferToBase64(kyberKeyPair.publicKey)
            };
            const hybridPrivateKey = {
                ecdh: ecdhPrivateKeyJwk,
                kyber: arrayBufferToBase64(kyberKeyPair.secretKey)
            };

            genPublicKeyEl.value = JSON.stringify(hybridPublicKey, null, 2);
            genPrivateKeyEl.value = JSON.stringify(hybridPrivateKey, null, 2);

        } catch (error) {
            alert(`Gagal membuat kunci: ${error.message}`);
            [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = '');
        } finally {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Buat Pasangan Kunci Hibrida Baru';
        }
    });

    // --- Encryption Logic ---
    encryptBtn.addEventListener('click', async () => {
        const recipientPublicKeysJSON = publicKeyEl.value.trim();
        const plainText = plainTextEl.value;
        if (!recipientPublicKeysJSON || !plainText) {
            alert('Harap isi Kunci Publik Hibrida penerima dan Teks Biasa.');
            return;
        }

        try {
            const recipientPublicKeys = JSON.parse(recipientPublicKeysJSON);
            const recipientEcdhPublicKey = await window.crypto.subtle.importKey(
                'jwk', recipientPublicKeys.ecdh, { name: "ECDH", namedCurve: "P-384" }, true, []
            );
            const recipientKyberPublicKey = base64ToUint8Array(recipientPublicKeys.kyber);

            const senderEcdhKeyPair = await generateEcdhKeys();
            
            const ecdhSharedSecret = await window.crypto.subtle.deriveKey(
                { name: "ECDH", public: recipientEcdhPublicKey },
                senderEcdhKeyPair.privateKey,
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );

            const { cipherText: kyberCipherText, sharedSecret: kyberSharedSecret } = ml_kem768.encapsulate(recipientKyberPublicKey);

            const hybridKey = await deriveHybridKey(ecdhSharedSecret, kyberSharedSecret);

            const { iv, ciphertext } = await encryptMessage(hybridKey, plainText);

            const senderEcdhPublicKeyJwk = await window.crypto.subtle.exportKey('jwk', senderEcdhKeyPair.publicKey);
            const payload = {
                senderEcdhPublicKey: senderEcdhPublicKeyJwk,
                kyberCipherText: arrayBufferToBase64(kyberCipherText),
                iv: arrayBufferToBase64(iv),
                ciphertext: arrayBufferToBase64(ciphertext)
            };
            
            encryptedTextEl.value = btoa(JSON.stringify(payload));

        } catch (error) {
            alert(`Terjadi kesalahan saat enkripsi: ${error.message}`);
            encryptedTextEl.value = '';
        }
    });
    
    // --- Decryption Logic ---
    decryptBtn.addEventListener('click', async () => {
        const privateKeysJSON = privateKeyEl.value.trim();
        const encryptedPayloadB64 = cipherTextEl.value.trim();
        if (!privateKeysJSON || !encryptedPayloadB64) {
            alert('Harap isi Kunci Privat Hibrida Anda dan Ciphertext.');
            return;
        }
        decryptedTextEl.value = '';

        try {
            const privateKeys = JSON.parse(privateKeysJSON);
            const recipientEcdhPrivateKey = await window.crypto.subtle.importKey(
                'jwk', privateKeys.ecdh, { name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey"]
            );
            const recipientKyberPrivateKey = base64ToUint8Array(privateKeys.kyber);

            const payload = JSON.parse(atob(encryptedPayloadB64));
            const senderEcdhPublicKey = await window.crypto.subtle.importKey(
                'jwk', payload.senderEcdhPublicKey, { name: "ECDH", namedCurve: "P-384" }, true, []
            );
            const kyberCipherText = base64ToUint8Array(payload.kyberCipherText);
            const iv = base64ToUint8Array(payload.iv);
            const ciphertext = base64ToUint8Array(payload.ciphertext);

            const ecdhSharedSecret = await window.crypto.subtle.deriveKey(
                { name: "ECDH", public: senderEcdhPublicKey },
                recipientEcdhPrivateKey,
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
            
            const kyberSharedSecret = ml_kem768.decapsulate(kyberCipherText, recipientKyberPrivateKey);

            const hybridKey = await deriveHybridKey(ecdhSharedSecret, kyberSharedSecret);

            const decryptedText = await decryptMessage(hybridKey, iv, ciphertext);

            decryptedTextEl.value = decryptedText;

        } catch (error) {
            decryptedTextEl.value = `ERROR: ${error.message}. Pastikan Kunci Privat dan Ciphertext valid.`;
        }
    });

    // --- Setup all Copy Buttons ---
    setupCopyButton(copyGenPublicBtn, genPublicKeyEl);
    setupCopyButton(copyGenPrivateBtn, genPrivateKeyEl);
    setupCopyButton(copyEncryptedBtn, encryptedTextEl);
    setupCopyButton(copyDecryptedBtn, decryptedTextEl);
});
