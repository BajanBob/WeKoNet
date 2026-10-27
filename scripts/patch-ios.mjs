// Runs after `npx cap add ios`: usage strings, wekonet:// scheme, associated
// domain for Universal Links, and background audio for calls.
import fs from 'node:fs';
import plist from 'plist';

const APP_HOST = new URL(process.env.VITE_APP_BASE || 'https://wekonet-relay.onrender.com/b/').host;

const p = 'ios/App/App/Info.plist';
const info = plist.parse(fs.readFileSync(p, 'utf8'));
info.NSCameraUsageDescription = 'WeKoNet uses the camera for end-to-end encrypted video calls.';
info.NSMicrophoneUsageDescription = 'WeKoNet uses the microphone for end-to-end encrypted calls.';
info.NSLocationWhenInUseUsageDescription = 'WeKoNet shares your location only when you start location sharing or SOS.';
info.CFBundleURLTypes = [{ CFBundleURLName: 'app.wekonet.beacon', CFBundleURLSchemes: ['wekonet'] }];
info.ITSAppUsesNonExemptEncryption = true; // strong crypto → export compliance documentation needed
info.UIBackgroundModes = ['audio', 'voip'];
fs.writeFileSync(p, plist.build(info));

const ent = 'ios/App/App/App.entitlements';
fs.writeFileSync(ent, plist.build({ 'com.apple.developer.associated-domains': [`applinks:${APP_HOST}`] }));
console.log('iOS project patched for WeKoNet (set your Team + signing in Xcode)');
