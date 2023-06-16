import './style.css'
import { decrypt, encrypt, register } from "./encryptor.ts";

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div id="content-container">
    <div class="row">
      <div class="textarea-group">
        <label for="encrypt-input">Data to encrypt:</label>
        <textarea id="encrypt-input" spellcheck="false"></textarea>
      </div>
      <div class="button-container">
        <button id="encrypt-button" class="transformation">Encrypt</button>
      </div>
      <div class="textarea-group">
        <label for="encrypt-output">Encrypted data:</label>
        <textarea id="encrypt-output" readonly spellcheck="false"></textarea>
      </div>
    </div>
    <div class="row line"></div>
    <div class="row">
      <div class="textarea-group">
        <label for="decrypt-input">Data to decrypt:</label>
        <textarea id="decrypt-input" spellcheck="false"></textarea>
      </div>
      <div class="button-container">
        <button id="decrypt-button" class="transformation">Decrypt</button>
      </div>
      <div class="textarea-group">
        <label for="decrypt-output">Decrypted data:</label>
        <textarea id="decrypt-output" readonly spellcheck="false"></textarea>
      </div>
    </div>
  </div>
`

const salt = new Uint8Array([9, 0, 1, 2]).buffer;
const nonce = crypto.getRandomValues(new Uint8Array(12));

let registerData: {rawId: BufferSource, transports: string[]};

document.getElementById('register-button')!.addEventListener('click', async () => {
  registerData = await register(salt);
});

document.getElementById('encrypt-button')!.addEventListener('click', async () => {
  const toEncrypt = (document.getElementById('encrypt-input') as HTMLTextAreaElement)!.value;
  const encrypted = await encrypt(salt, toEncrypt, nonce, registerData.rawId, registerData.transports);
  (document.getElementById('encrypt-output') as HTMLTextAreaElement)!.value = encrypted;
});

document.getElementById('decrypt-button')!.addEventListener('click', async () => {
  const toDecrypt = (document.getElementById('decrypt-input') as HTMLTextAreaElement)!.value;
  const decrypted = await decrypt(salt, toDecrypt, nonce, registerData.rawId, registerData.transports);
  console.log(decrypted);
  (document.getElementById('decrypt-output') as HTMLTextAreaElement)!.value = decrypted;
});
