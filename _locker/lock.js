#!/usr/bin/env node
/*
 * lock.js — נועל הצעת מחיר עם קוד גישה אמיתי (הצפנת AES-256).
 *
 * שימוש:
 *   node _locker/lock.js <קובץ-מקור.html> [קוד-גישה]
 *
 * דוגמה:
 *   node _locker/lock.js pisga.html
 *      -> מייצר קוד אקראי ומדפיס אותו
 *   node _locker/lock.js pisga.html pesach2026
 *      -> משתמש בקוד שבחרת
 *
 * הפלט: קובץ נעול עם סיומת אקראית בכתובת (למשל pisga-7fk2qx.html),
 * שמכיל רק טקסט מוצפן. בלי הקוד אי אפשר לראות כלום — גם לא בקוד המקור.
 *
 * לסגירת גישה: פשוט מוחקים את הקובץ הנעול (git rm + push) -> 404 לכולם.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ── קלט ──────────────────────────────────────────────
const srcArg = process.argv[2];
if (!srcArg) {
  console.error('שגיאה: חסר שם קובץ.\nשימוש: node _locker/lock.js <קובץ.html> [קוד-גישה]');
  process.exit(1);
}
const srcPath = path.resolve(srcArg);
if (!fs.existsSync(srcPath)) {
  console.error('שגיאה: הקובץ לא נמצא: ' + srcPath);
  process.exit(1);
}

// קוד גישה: או מהפרמטר, או נוצר אקראית (קריא, בלי תווים מבלבלים)
function makeCode() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'; // בלי i,l,o,0,1
  const bytes = crypto.randomBytes(8);
  let out = '';
  for (let i = 0; i < 8; i++) out += alphabet[bytes[i] % alphabet.length];
  return out.slice(0, 4) + '-' + out.slice(4); // למשל "k7x2-q9mn"
}
const passcode = process.argv[3] || makeCode();

// ── הצפנה ────────────────────────────────────────────
const plaintext = fs.readFileSync(srcPath); // ה-HTML המלא
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const ITER = 200000;
const key = crypto.pbkdf2Sync(passcode, salt, ITER, 32, 'sha256');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();
// פורמט: salt(16) | iv(12) | ciphertext | tag(16)  -> base64
const payload = Buffer.concat([salt, iv, enc, tag]).toString('base64');

// ── שם הקובץ הנעול (כתובת אקראית, לא ניתנת לניחוש) ──
const base = path.basename(srcArg).replace(/\.html?$/i, '');
const suffix = crypto.randomBytes(3).toString('hex'); // 6 תווים
const outName = `${base}-${suffix}.html`;
const outPath = path.join(path.dirname(srcPath), outName);

// ── מעקב פתיחה (beacon) ──────────────────────────────
// כשהלקוח מזין את הקוד הנכון וההצעה נפתחת בפועל, נשלחת קריאה שקטה
// ל-BrandOS שמפעילה התראת טלגרם ("ההצעה נפתחה"). לא נורה כשנוחתים
// רק על מסך הקוד — רק על פענוח מוצלח. אפשר לכבות עם PROPOSAL_PING_URL=off.
const PING_BASE = process.env.PROPOSAL_PING_URL
  || 'https://brandos.hagitantebi.co.il/api/proposal-ping';
const pingUrl = PING_BASE === 'off'
  ? ''
  : `${PING_BASE}?via=locker&p=${encodeURIComponent(base)}`;

// ── מסך הנעילה (gate) ────────────────────────────────
const gate = `<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>הצעה פרטית · Brand Worlds Studio</title>
<link href="https://fonts.googleapis.com/css2?family=Heebo:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Heebo',sans-serif; min-height:100vh; display:flex;
    align-items:center; justify-content:center; padding:24px;
    background:linear-gradient(135deg,#F9F6F0 0%,#FFFFFF 50%,#EDE8DC 100%); color:#161517; }
  .card { width:100%; max-width:420px; background:#fff; border:1px solid #EDE8DC;
    border-radius:20px; padding:44px 36px; text-align:center;
    box-shadow:0 30px 80px rgba(22,21,23,.10); }
  .mark { width:54px; height:54px; margin:0 auto 22px; border-radius:50%;
    background:linear-gradient(135deg,#C89E4A,#A07830); display:flex;
    align-items:center; justify-content:center; }
  .mark svg { width:24px; height:24px; fill:none; stroke:#fff; stroke-width:2; }
  h1 { font-size:21px; font-weight:600; margin-bottom:8px; letter-spacing:-.01em; }
  p.sub { font-size:14.5px; color:#6B6150; line-height:1.6; margin-bottom:26px; }
  input { width:100%; padding:14px 16px; font-family:inherit; font-size:16px;
    text-align:center; letter-spacing:.06em; border:1.5px solid #E2DBCB;
    border-radius:12px; background:#FBF9F4; color:#161517; outline:none; transition:.2s; }
  input:focus { border-color:#C89E4A; background:#fff; }
  button { width:100%; margin-top:14px; padding:14px; font-family:inherit; font-size:16px;
    font-weight:600; color:#fff; background:linear-gradient(135deg,#C89E4A,#A07830);
    border:none; border-radius:12px; cursor:pointer; transition:.2s; }
  button:hover { filter:brightness(1.05); }
  button:disabled { opacity:.5; cursor:default; }
  .err { color:#C0392B; font-size:13.5px; margin-top:14px; min-height:18px; }
  .foot { margin-top:24px; font-size:12px; color:#A89B82; letter-spacing:.04em; }
</style>
</head>
<body>
  <div class="card">
    <div class="mark">
      <svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
    </div>
    <h1>ההצעה הזו פרטית</h1>
    <p class="sub">הזיני את קוד הגישה שקיבלת כדי לצפות בהצעה.</p>
    <form id="f" autocomplete="off">
      <input id="code" type="password" inputmode="text" placeholder="קוד גישה" autofocus>
      <button id="btn" type="submit">פתחי את ההצעה</button>
    </form>
    <div class="err" id="err"></div>
    <div class="foot">Brand Worlds Studio</div>
  </div>

<script>
const PAYLOAD = "${payload}";
const ITER = ${ITER};
const f = document.getElementById('f');
const codeEl = document.getElementById('code');
const errEl = document.getElementById('err');
const btn = document.getElementById('btn');

function b64ToBytes(b64){ const bin=atob(b64); const a=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i); return a; }

f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  errEl.textContent=''; btn.disabled=true; btn.textContent='מפענח…';
  try{
    const raw=b64ToBytes(PAYLOAD);
    const salt=raw.slice(0,16), iv=raw.slice(16,28), data=raw.slice(28);
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(codeEl.value),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:ITER,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
    const buf=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,data);
    const html=new TextDecoder().decode(buf);
    // beacon: הצעה נפתחה בפועל (קוד נכון). נורה לפני document.write
    // שמוחק את ה-DOM. נכשל בשקט — לעולם לא חוסם את הצפייה.
    try{ var PING=${JSON.stringify(pingUrl)};
      if(PING){ if(navigator.sendBeacon){navigator.sendBeacon(PING);}else{new Image().src=PING;} }
    }catch(_){}
    document.open(); document.write(html); document.close();
  }catch(err){
    btn.disabled=false; btn.textContent='פתחי את ההצעה';
    errEl.textContent='קוד שגוי. נסי שוב.';
    codeEl.select();
  }
});
</script>
</body>
</html>`;

fs.writeFileSync(outPath, gate, 'utf8');

// ── סיכום למסך ───────────────────────────────────────
console.log('');
console.log('  ✓ הצעה נעולה נוצרה');
console.log('  ─────────────────────────────────────────');
console.log('  קובץ:        ' + outName);
console.log('  קוד גישה:    ' + passcode);
console.log('  ─────────────────────────────────────────');
console.log('  כתובת (אחרי push):');
console.log('  https://hagitadigital.github.io/pitches/' + outName);
console.log('');
console.log('  שלחי ללקוח את הכתובת + הקוד (בוואטסאפ, בנפרד).');
console.log('  לסגירת גישה בעתיד: מוחקים את הקובץ ' + outName + ' ודוחפים.');
console.log('');
