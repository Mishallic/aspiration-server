import crypto from 'node:crypto';
import express from 'express';

// Minimal server-rendered pages the verification and reset emails link to. They work
// on their own, and a client app can take over by setting EMAIL_VERIFIED_REDIRECT_URL
// and PASSWORD_RESET_URL to its own screens instead.

const escape = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const layout = (title, body, { nonce } = {}) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escape(title)}</title>
<style${nonce ? ` nonce="${nonce}"` : ''}>
  body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f7f9;color:#111;margin:0;
    display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
  .card{background:#fff;max-width:400px;width:100%;padding:32px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
  h1{font-size:20px;margin:0 0 12px}p{color:#444;line-height:1.5;margin:0 0 16px}
  label{display:block;font-size:14px;font-weight:600;margin:0 0 6px}
  input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #ccc;border-radius:8px;font-size:15px}
  button{margin-top:16px;width:100%;background:#111;color:#fff;border:0;padding:12px;border-radius:8px;
    font-size:15px;font-weight:600;cursor:pointer}button:disabled{opacity:.5;cursor:default}
  .ok{color:#15803d}.err{color:#b91c1c;font-size:14px;min-height:18px;margin-top:8px}
</style></head><body><div class="card">${body}</div></body></html>`;

export function pageRoutes(ctx) {
  const { config, services } = ctx;
  const router = express.Router();

  const pageCsp = (nonce) =>
    `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; form-action 'none'; base-uri 'none'`;

  router.get('/verify-email', async (req, res) => {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const user = await services.emailFlows.verifyEmail(token);

    if (user && config.email.verifiedRedirectUrl) {
      return res.redirect(config.email.verifiedRedirectUrl);
    }
    const nonce = crypto.randomBytes(16).toString('base64');
    res.set('Content-Security-Policy', pageCsp(nonce));
    const body = user
      ? `<h1 class="ok">Email confirmed</h1><p>Thanks, ${escape(user.email)} is now confirmed. You can return to ${escape(config.appName)}.</p>`
      : '<h1>Link not valid</h1><p>This confirmation link is invalid or has expired. Request a new one from the app.</p>';
    res.status(user ? 200 : 400).type('html').send(layout('Confirm your email', body, { nonce }));
  });

  router.get('/reset-password', (req, res) => {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const nonce = crypto.randomBytes(16).toString('base64');
    res.set('Content-Security-Policy', pageCsp(nonce));

    const body = `<h1>Choose a new password</h1>
<p>Enter a new password for your ${escape(config.appName)} account.</p>
<form id="f"><label for="pw">New password</label>
<input id="pw" type="password" minlength="8" maxlength="256" autocomplete="new-password" required>
<div id="err" class="err"></div><button id="b" type="submit">Set new password</button></form>
<div id="done" style="display:none"><h1 class="ok">Password updated</h1>
<p>Your password has been changed. You can now sign in to ${escape(config.appName)}.</p></div>
<script nonce="${nonce}">
const token=${JSON.stringify(token)};
const f=document.getElementById('f'),err=document.getElementById('err'),b=document.getElementById('b');
f.addEventListener('submit',async(e)=>{e.preventDefault();err.textContent='';b.disabled=true;
  try{const r=await fetch('/v1/auth/password/reset',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({token,newPassword:document.getElementById('pw').value})});
    if(r.status===204){f.style.display='none';document.getElementById('done').style.display='block';return;}
    const d=await r.json().catch(()=>({}));err.textContent=(d.error&&d.error.message)||'Could not reset the password.';
  }catch{err.textContent='Network error, please try again.';}
  b.disabled=false;});
</script>`;
    res.type('html').send(layout('Reset your password', body, { nonce }));
  });

  return router;
}
