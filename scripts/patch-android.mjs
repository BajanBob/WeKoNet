// Runs after `npx cap add android`: adds permissions, deep links, and
// security hardening to the generated Android project.
import fs from 'node:fs';

const APP_HOST = new URL(process.env.VITE_APP_BASE || 'https://wekonet-relay.onrender.com/b/').host;
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
  // Keep calls and lingering beacon rooms alive in the background (like WhatsApp)
  'android.permission.FOREGROUND_SERVICE',
  'android.permission.FOREGROUND_SERVICE_MICROPHONE',
  'android.permission.FOREGROUND_SERVICE_CAMERA',
  'android.permission.FOREGROUND_SERVICE_SPECIAL_USE',
  'android.permission.POST_NOTIFICATIONS',
  'android.permission.WAKE_LOCK',
];
for (const p of perms) {
  if (!m.includes(`"${p}"`)) m = m.replace('</manifest>', `    <uses-permission android:name="${p}" />\n</manifest>`);
}
m = m.replace('</manifest>', '    <uses-feature android:name="android.hardware.camera" android:required="false" />\n</manifest>');

// Beacon deep links: https://<APP_HOST>/b/... (App Link) + wekonet://b
const filters = `
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="${APP_HOST}" android:pathPrefix="/b" />
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
if (!m.includes('.KeepAliveService')) {
  m = m.replace('</application>', `        <service
            android:name=".KeepAliveService"
            android:exported="false"
            android:foregroundServiceType="microphone|camera|specialUse">
            <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="Keeps an end-to-end encrypted call or open beacon room connected while the app is in the background" />
        </service>
    </application>`);
}
fs.writeFileSync(manifestPath, m);

fs.mkdirSync('android/app/src/main/res/xml', { recursive: true });
fs.writeFileSync('android/app/src/main/res/xml/data_extraction_rules.xml', `<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
  <cloud-backup><exclude domain="root" /><exclude domain="database" /><exclude domain="sharedpref" /><exclude domain="file" /></cloud-backup>
  <device-transfer><exclude domain="root" /><exclude domain="database" /><exclude domain="sharedpref" /><exclude domain="file" /></device-transfer>
</data-extraction-rules>
`);

// MainActivity: block screenshots / screen recording of calls and the recents
// thumbnail, and register the KeepAlive plugin.
const actPath = (() => {
  const base = 'android/app/src/main/java';
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(`${d}/${e.name}`) : [`${d}/${e.name}`]);
  return walk(base).find((f) => f.endsWith('MainActivity.java'));
})();
if (actPath) {
  const dir = actPath.slice(0, actPath.lastIndexOf('/'));
  const pkg = /package\s+([\w.]+);/.exec(fs.readFileSync(actPath, 'utf8'))[1];

  fs.writeFileSync(actPath, `package ${pkg};

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(android.os.Bundle savedInstanceState) {
        registerPlugin(KeepAlivePlugin.class);
        super.onCreate(savedInstanceState);
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE);
    }
}
`);

  fs.writeFileSync(`${dir}/KeepAlivePlugin.java`, `package ${pkg};

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "KeepAlive")
public class KeepAlivePlugin extends Plugin {
    @PluginMethod
    public void start(PluginCall call) {
        Context ctx = getContext();
        if (Build.VERSION.SDK_INT >= 33 && getActivity() != null
                && ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(getActivity(), new String[] { Manifest.permission.POST_NOTIFICATIONS }, 7301);
        }
        Intent i = new Intent(ctx, KeepAliveService.class);
        i.putExtra("text", call.getString("text", "WeKoNet is connected"));
        try {
            ContextCompat.startForegroundService(ctx, i);
            call.resolve();
        } catch (Exception e) {
            call.reject("Background mode unavailable: " + e.getMessage());
        }
    }

    @PluginMethod
    public void stop(PluginCall call) {
        getContext().stopService(new Intent(getContext(), KeepAliveService.class));
        call.resolve();
    }
}
`);

  fs.writeFileSync(`${dir}/KeepAliveService.java`, `package ${pkg};

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import androidx.core.app.NotificationCompat;
import androidx.core.app.ServiceCompat;
import androidx.core.content.ContextCompat;

/** Foreground service that keeps WeKoNet's call / beacon room connected in the background. */
public class KeepAliveService extends Service {
    private static final String CHANNEL = "wekonet_connected";
    private static final int ID = 4711;
    private PowerManager.WakeLock wakeLock;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String text = intent != null && intent.getStringExtra("text") != null ? intent.getStringExtra("text") : "WeKoNet is connected";
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Connected calls", NotificationManager.IMPORTANCE_LOW));
        }
        Intent open = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = new NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(getApplicationInfo().icon)
            .setContentTitle("WeKoNet")
            .setContentText(text + " · end-to-end encrypted")
            .setContentIntent(pi)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build();

        int type = 0;
        if (Build.VERSION.SDK_INT >= 30) {
            if (granted(Manifest.permission.RECORD_AUDIO)) type |= ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
            if (granted(Manifest.permission.CAMERA)) type |= ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA;
        }
        if (Build.VERSION.SDK_INT >= 34) type |= ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE;
        try {
            ServiceCompat.startForeground(this, ID, n, type);
        } catch (Exception e) {
            // e.g. microphone not usable from the background on this Android version
            ServiceCompat.startForeground(this, ID, n, Build.VERSION.SDK_INT >= 34 ? ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE : 0);
        }

        if (wakeLock == null) {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "WeKoNet:connected");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire(24L * 60 * 60 * 1000); // safety cap; released when the call / beacon ends
        }
        return START_NOT_STICKY;
    }

    private boolean granted(String perm) {
        return ContextCompat.checkSelfPermission(this, perm) == PackageManager.PERMISSION_GRANTED;
    }

    @Override
    public void onDestroy() {
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        wakeLock = null;
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
`);
}
console.log('Android project patched for WeKoNet');
