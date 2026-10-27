// Runs after `npx cap add android`: adds permissions, deep links, and
// security hardening to the generated Android project.
import fs from 'node:fs';

const manifestPath = 'android/app/src/main/AndroidManifest.xml';
let m = fs.readFileSync(manifestPath, 'utf8');

const perms = [
  'android.permission.INTERNET',
  'android.permission.CAMERA',
  'android.permission.RECORD_AUDIO',
  'android.permission.MODIFY_AUDIO_SETTINGS',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.VIBRATE',
];
for (const p of perms) {
  if (!m.includes(`"${p}"`)) m = m.replace('</manifest>', `    <uses-permission android:name="${p}" />\n</manifest>`);
}
m = m.replace('</manifest>', '    <uses-feature android:name="android.hardware.camera" android:required="false" />\n</manifest>');

// Beacon deep links: https://wekonet.app/b/... (verified App Link) + wekonet://b
const filters = `
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="wekonet.app" android:pathPrefix="/b" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="wekonet" android:host="b" />
            </intent-filter>`;
if (!m.includes('android:scheme="wekonet"')) {
  m = m.replace(/(<activity[\s\S]*?android:name="\.MainActivity"[\s\S]*?>)/, `$1${filters}`);
}

// Hardening: no backups of keys/history, no cleartext traffic.
m = m.replace(/android:allowBackup="true"/, 'android:allowBackup="false"');
if (!m.includes('android:usesCleartextTraffic')) m = m.replace('<application', '<application android:usesCleartextTraffic="false" android:fullBackupContent="false" android:dataExtractionRules="@xml/data_extraction_rules"');
fs.writeFileSync(manifestPath, m);

fs.mkdirSync('android/app/src/main/res/xml', { recursive: true });
fs.writeFileSync('android/app/src/main/res/xml/data_extraction_rules.xml', `<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
  <cloud-backup><exclude domain="root" /><exclude domain="database" /><exclude domain="sharedpref" /><exclude domain="file" /></cloud-backup>
  <device-transfer><exclude domain="root" /><exclude domain="database" /><exclude domain="sharedpref" /><exclude domain="file" /></device-transfer>
</data-extraction-rules>
`);

// Block screenshots / screen recording of calls and the recents thumbnail.
const actPath = (() => {
  const base = 'android/app/src/main/java';
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(`${d}/${e.name}`) : [`${d}/${e.name}`]);
  return walk(base).find((f) => f.endsWith('MainActivity.java'));
})();
if (actPath) {
  let a = fs.readFileSync(actPath, 'utf8');
  if (!a.includes('FLAG_SECURE')) {
    a = a.replace(/public class MainActivity extends BridgeActivity \{\s*\}/, `public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(android.os.Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE);
    }
}`);
    fs.writeFileSync(actPath, a);
  }
}
console.log('Android project patched for WeKoNet');
