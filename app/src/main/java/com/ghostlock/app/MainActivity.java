package com.ghostlock.app;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Insets;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.system.ErrnoException;
import android.system.Os;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainActivity extends Activity {
    private static final String TAG = "GhostLockXring";
    private static final String BINARY_NAME = "libghostlock.so";
    private static final String KSUD_NAME = "ksud";
    private static final String PREFERENCES_NAME = "root-settings";
    private static final String PREFERENCE_ROOT_IMPLEMENTATION = "root-implementation";
    private static final int COLOR_RED = 0xFFFF6B6B;
    private static final int COLOR_GREEN = 0xFF5FD68A;
    private static final int COLOR_YELLOW = 0xFFFFC94D;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final StringBuilder logBuffer = new StringBuilder();
    /** File sink for crash diagnostics; null until a writable path is found. */
    private FileOutputStream logStream;
    private File logFile;
    private long lastSyncMs;

    /** Preferred crash-log locations, most useful first. */
    private static final String LOG_PREFIX = "ghostlock-";
    private static final long LOG_SYNC_INTERVAL_MS = 150;
    private TextView deviceInfo;
    private TextView statusInfo;
    private TextView logView;
    private View statusDot;
    private View statusChip;
    private LinearLayout kernelChip;
    private TextView kernelChipText;
    private ScrollView logScroll;
    private Button runButton;
    private Button copyButton;
    private Button kernelSuButton;
    private Button reSukiSuButton;
    private Button installManagerButton;
    private View rootView;
    private RootImplementation selectedRootImplementation;

    /**
     * Mirrors the offset tables under src/kernels: only these uname builds are supported.
     */
    private static boolean isKernelSupported() {
        String version = System.getProperty("os.version", "");
        for (String supported : SupportedKernels.UNAMES) {
            if (supported.equals(version)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the value when it looks like a real device name, else null.
     */
    private static String validDeviceName(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        if (v.isEmpty()) {
            return null;
        }
        String lower = v.toLowerCase(Locale.ROOT);
        if (lower.contains("unknown") || lower.contains("null")) {
            return null;
        }
        return v;
    }

    @SuppressLint("PrivateApi")
    private static String getSystemProperty(String key) {
        try {
            Class<?> props = Class.forName("android.os.SystemProperties");
            Object value = props.getMethod("get", String.class).invoke(null, key);
            return value instanceof String ? (String) value : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    /**
     * Color a whole log line by its leading marker. The native binary only
     * colors the "[..]" prefix (message text stays default) and the script log
     * is plain text, so per-line coloring is what makes the log readable.
     */
    private static CharSequence colorize(String line) {
        int color = markerColor(line);
        if (color == -1) {
            return line;
        }
        SpannableStringBuilder sb = new SpannableStringBuilder(line);
        sb.setSpan(new ForegroundColorSpan(color), 0, line.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return sb;
    }

    private static int markerColor(String line) {
        if (line.startsWith("[+]")) return COLOR_GREEN;
        if (line.startsWith("[-]") || line.startsWith("[!]")) return COLOR_RED;
        if (line.startsWith("[*]")) return COLOR_YELLOW;
        if (line.startsWith("error") || line.startsWith("Error")) return COLOR_RED;
        if (line.startsWith("warning")) return COLOR_YELLOW;
        return -1;
    }

    private static String stripAnsi(String input) {
        return input.replaceAll("\u001B\\[[;\\d]*m", "");
    }

    private static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) >= 0) {
            out.write(buf, 0, n);
        }
        out.flush();
    }

    private static void copyFile(File src, File dst) throws IOException {
        try (InputStream in = new FileInputStream(src); OutputStream out = new FileOutputStream(dst, false)) {
            copyStream(in, out);
        }
    }

    private static void setViewColor(View view, int color) {
        if (view.getBackground() instanceof GradientDrawable) {
            ((GradientDrawable) view.getBackground().mutate()).setColor(color);
        } else {
            view.setBackgroundTintList(ColorStateList.valueOf(color));
        }
    }

    private static String firstValidProperty(String... keys) {
        for (String key : keys) {
            String value = validDeviceName(getSystemProperty(key));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setupSystemBars();

        rootView = findViewById(R.id.root);
        deviceInfo = findViewById(R.id.deviceInfo);
        statusInfo = findViewById(R.id.statusInfo);
        statusDot = findViewById(R.id.statusDot);
        statusChip = findViewById(R.id.statusChip);
        logView = findViewById(R.id.logView);
        logScroll = findViewById(R.id.logScroll);
        runButton = findViewById(R.id.runButton);
        copyButton = findViewById(R.id.copyButton);
        kernelSuButton = findViewById(R.id.rootKernelSuButton);
        reSukiSuButton = findViewById(R.id.rootReSukiSuButton);
        installManagerButton = findViewById(R.id.installManagerButton);
        kernelChip = findViewById(R.id.kernelChip);
        kernelChipText = findViewById(R.id.kernelChipText);

        SharedPreferences preferences = getSharedPreferences(PREFERENCES_NAME, MODE_PRIVATE);
        selectedRootImplementation = RootImplementation.fromPreference(
                preferences.getString(PREFERENCE_ROOT_IMPLEMENTATION, null));

        applyWindowInsetsPadding();
        deviceInfo.setText(buildDeviceSummary());
        applyKernelStatus();
        refreshRootImplementationUi();
        setRunState(RunState.IDLE, getString(R.string.status_idle));

        runButton.setOnClickListener(v -> startExploit());
        copyButton.setOnClickListener(v -> copyLogs());
        kernelSuButton.setOnClickListener(v -> selectRootImplementation(RootImplementation.KERNEL_SU));
        reSukiSuButton.setOnClickListener(v -> selectRootImplementation(RootImplementation.RESUKI_SU));
        installManagerButton.setOnClickListener(v -> installSelectedManager());

        // Crash logs go to Download/, which needs all-files access on Android 11+.
        ensureLogPermission();
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    /**
     * Create the crash log as soon as the app is visible, so the log path can be
     * verified before anything risky runs, and so returning from the
     * all-files-access settings page picks up the newly granted permission.
     */
    @Override
    protected void onResume() {
        super.onResume();
        initLogFile();
    }

    private void setupSystemBars() {
        Window window = getWindow();
        int barColor = getColor(R.color.status_bar);

        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS | WindowManager.LayoutParams.FLAG_TRANSLUCENT_NAVIGATION);
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(barColor);
        window.setNavigationBarColor(getColor(R.color.nav_bar));

        window.setStatusBarContrastEnforced(false);
        window.setNavigationBarContrastEnforced(false);

        WindowInsetsController controller = window.getInsetsController();
        if (controller != null) {
            int lightStatus = getResources().getBoolean(R.bool.window_light_status_bar) ? WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS : 0;
            int lightNav = getResources().getBoolean(R.bool.window_light_navigation_bar) ? WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS : 0;
            controller.setSystemBarsAppearance(lightStatus | lightNav, WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
        }
    }

    private void applyWindowInsetsPadding() {
        rootView.setOnApplyWindowInsetsListener((v, insets) -> {
            int top;
            int bottom;
            Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
            top = bars.top;
            bottom = bars.bottom;
            int side = dp(20);
            v.setPadding(side, top + dp(12), side, bottom + dp(12));
            return insets;
        });
        rootView.requestApplyInsets();
    }

    private String buildDeviceSummary() {
        return getString(R.string.device_label) + ": " + resolveDeviceName() + "\n" + getString(R.string.kernel_label) + ": " + System.getProperty("os.version", "unknown");
    }

    private void applyKernelStatus() {
        boolean ok = isKernelSupported();
        int color = getColor(ok ? R.color.status_success : R.color.status_error);
        int bg = getColor(ok ? R.color.status_success_bg : R.color.status_error_bg);
        kernelChipText.setText(ok ? R.string.kernel_supported : R.string.kernel_unsupported);
        kernelChipText.setTextColor(color);
        setViewColor(kernelChip, bg);
    }

    private void selectRootImplementation(RootImplementation implementation) {
        if (running.get() || selectedRootImplementation == implementation) {
            return;
        }
        selectedRootImplementation = implementation;
        getSharedPreferences(PREFERENCES_NAME, MODE_PRIVATE)
                .edit()
                .putString(PREFERENCE_ROOT_IMPLEMENTATION, implementation.preferenceValue)
                .apply();
        refreshRootImplementationUi();
    }

    private void refreshRootImplementationUi() {
        styleRootImplementationButton(kernelSuButton,
                selectedRootImplementation == RootImplementation.KERNEL_SU);
        styleRootImplementationButton(reSukiSuButton,
                selectedRootImplementation == RootImplementation.RESUKI_SU);
    }

    private void styleRootImplementationButton(Button button, boolean selected) {
        button.setBackgroundResource(selected ? R.drawable.bg_miui_primary : R.drawable.bg_miui_outline);
        button.setTextColor(getColor(selected ? android.R.color.white : R.color.accent));
    }

    private void installSelectedManager() {
        if (!getPackageManager().canRequestPackageInstalls()) {
            try {
                Intent settings = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:" + getPackageName()));
                startActivity(settings);
                Toast.makeText(this, R.string.allow_manager_install, Toast.LENGTH_LONG).show();
            } catch (Throwable t) {
                Toast.makeText(this, R.string.manager_install_failed, Toast.LENGTH_SHORT).show();
            }
            return;
        }

        RootImplementation implementation = selectedRootImplementation;
        try {
            File directory = new File(getCacheDir(), ManagerApkProvider.CACHE_DIRECTORY);
            if (!directory.isDirectory() && !directory.mkdirs()) {
                throw new IOException("unable to create manager cache");
            }
            File apk = new File(directory, implementation.managerFileName);
            try (InputStream in = getAssets().open(implementation.managerAssetPath);
                 OutputStream out = new FileOutputStream(apk, false)) {
                copyStream(in, out);
            }

            Uri uri = new Uri.Builder()
                    .scheme("content")
                    .authority(getPackageName() + ".apkprovider")
                    .appendPath(implementation.managerFileName)
                    .build();
            Intent install = new Intent(Intent.ACTION_INSTALL_PACKAGE)
                    .setData(uri)
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(install);
        } catch (Throwable t) {
            appendLog("[!] manager install failed: " + t.getMessage());
            Toast.makeText(this, R.string.manager_install_failed, Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Sales/market name of the device, matching the language of the current region.
     */
    private String resolveDeviceName() {
        boolean cn = "CN".equalsIgnoreCase(Locale.getDefault().getCountry());
        String marketName = firstValidProperty("ro.product.marketname", "ro.product.vendor.marketname");
        return marketName != null ? marketName : Build.MANUFACTURER + " " + Build.MODEL;
    }

    private void startExploit() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        setRunState(RunState.RUNNING, getString(R.string.status_running));
        initLogFile();
        if (isLogWritable()) {
            appendLog("[*] log file: " + logFile.getAbsolutePath());
        } else {
            ensureLogPermission();
            appendLog("[!] unable to open a log file yet; grant all-files access and retry");
        }
        appendLog("[*] start");
        RootImplementation implementation = selectedRootImplementation;
        worker.execute(() -> {
            int code = 1;
            try {
                File workDir = getFilesDir();
                File binary = resolveBinary();
                File ksud = prepareKsud(workDir, implementation);
                if (ksud != null) {
                    appendLog("[+] " + implementation.displayName + " ksud ready");
                } else {
                    appendLog("[!] ksud not found");
                }
                code = runBinary(binary, workDir);
                appendLog((code == 0 ? "[+] " : "[!] ") + "exit code=" + code);
            } catch (Throwable t) {
                appendLog("[!] error: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            } finally {
                int finalCode = code;
                syncLog();
                closeLog();
                ui.post(() -> {
                    running.set(false);
                    if (finalCode == 0) {
                        setRunState(RunState.SUCCESS, getString(R.string.status_success));
                    } else {
                        setRunState(RunState.FAILED, getString(R.string.status_failed) + " (" + finalCode + ")");
                    }
                });
            }
        });
    }

    private void setRunState(RunState state, String text) {
        statusInfo.setText(text);
        runButton.setEnabled(state != RunState.RUNNING);
        kernelSuButton.setEnabled(state != RunState.RUNNING);
        reSukiSuButton.setEnabled(state != RunState.RUNNING);
        installManagerButton.setEnabled(state != RunState.RUNNING);
        runButton.setText(state == RunState.RUNNING ? R.string.action_running : R.string.action_run);

        int color;
        int chipBg = switch (state) {
            case RUNNING -> {
                color = getColor(R.color.status_running);
                yield getColor(R.color.status_running_bg);
            }
            case SUCCESS -> {
                color = getColor(R.color.status_success);
                yield getColor(R.color.status_success_bg);
            }
            case FAILED -> {
                color = getColor(R.color.status_error);
                yield getColor(R.color.status_error_bg);
            }
            default -> {
                color = getColor(R.color.status_idle);
                yield getColor(R.color.status_idle_bg);
            }
        };

        statusInfo.setTextColor(color);
        if (statusDot.getBackground() instanceof GradientDrawable) {
            ((GradientDrawable) statusDot.getBackground().mutate()).setColor(color);
        } else {
            statusDot.setBackgroundTintList(ColorStateList.valueOf(color));
        }

        if (statusChip.getBackground() instanceof GradientDrawable) {
            ((GradientDrawable) statusChip.getBackground().mutate()).setColor(chipBg);
        } else {
            statusChip.setBackgroundTintList(ColorStateList.valueOf(chipBg));
        }
    }

    private File resolveBinary() throws IOException {
        File packaged = new File(getApplicationInfo().nativeLibraryDir, BINARY_NAME);
        if (packaged.isFile()) {
            appendLog("[+] GhostLock native ready (" + packaged.length() + " bytes)");
            return packaged;
        }
        throw new IOException("missing native binary: " + packaged.getAbsolutePath());
    }

    private boolean isXringO1Device() {
        String[] values = {
                Build.HARDWARE,
                getSystemProperty("ro.boot.hardware"),
                getSystemProperty("ro.hardware")
        };
        for (String value : values) {
            String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
            if ("o1".equals(normalized) || "o1_asic".equals(normalized) ||
                    normalized.startsWith("o1_")) {
                return true;
            }
        }
        return false;
    }

    private File prepareKsud(File workDir, RootImplementation implementation) throws IOException {
        File out = new File(workDir, KSUD_NAME);
        appendLog("[*] selected root implementation: " + implementation.displayName);
        File source = new File(getApplicationInfo().nativeLibraryDir,
                implementation.packagedKsudName);
        if (!source.isFile()) {
            if (out.isFile() && !out.delete()) {
                appendLog("[!] unable to remove stale ksud");
            }
            throw new IOException(implementation.displayName + " XRING ksud is missing");
        }
        appendLog("[*] using bundled XRING ksud: " + source.getName()
                + " (" + source.length() + " bytes)");
        copyFile(source, out);
        if (out.length() != source.length()) {
            throw new IOException("incomplete ksud copy");
        }
        try {
            Os.chmod(out.getAbsolutePath(), 448);
        } catch (ErrnoException e) {
            throw new IOException("unable to make ksud executable", e);
        }
        return out;
    }

    private int runBinary(File binary, File workDir) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(binary.getAbsolutePath());
        pb.directory(workDir);
        pb.redirectErrorStream(true);
        pb.environment().put("GHOSTLOCK_HOME", workDir.getAbsolutePath());
        pb.environment().put("TMPDIR", workDir.getAbsolutePath());
        pb.environment().put("HOME", workDir.getAbsolutePath());
        if (isXringO1Device()) {
            pb.environment().put("GHOSTLOCK_CORE", "2");
            appendLog("[*] Xiaomi XRING O1 detected; using CPU 2");
        }

        Process process = pb.start();
        Thread reader = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    appendLog(line);
                }
            } catch (IOException ignored) {
            }
        }, "ghostlock-reader");
        reader.setDaemon(true);
        reader.start();

        boolean finished = process.waitFor(300, TimeUnit.SECONDS);
        if (!finished) {
            process.destroy();
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        }
        // Drain buffered output, then force-unblock the reader: a late-load
        // daemon (zygisk) can inherit our pipe and keep it open forever.
        try {
            reader.join(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        try {
            process.getInputStream().close();
        } catch (IOException ignored) {
        }
        try {
            reader.join(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        appendKsudLogTail(workDir);
        return finished ? process.exitValue() : -1;
    }

    /**
     * Show any late-load log lines (root-owned, chmod 644) the binary could
     * not stream to us before it was killed by the vendor root guard.
     */
    private void appendKsudLogTail(File workDir) {
        List<String> lines = new ArrayList<>();
        List<File> logFiles = List.of(
                new File(workDir, ".ghostlock_ksu.log"),
                new File("/data/local/tmp/xring_loader.log"));
        for (File logFile : logFiles) {
            if (!logFile.isFile()) continue;
            try (BufferedReader r = new BufferedReader(new FileReader(logFile))) {
                String line;
                while ((line = r.readLine()) != null) lines.add(line);
            } catch (IOException ignored) {
                // The root-owned log may not be readable from the app domain.
            }
        }
        if (lines.isEmpty()) return;
        String joined;
        synchronized (logBuffer) {
            joined = logBuffer.toString();
        }
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || joined.contains(t)) {
                continue;
            }
            appendLog(line);
        }
    }

    private void copyLogs() {
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        if (cm == null) {
            return;
        }
        String text;
        synchronized (logBuffer) {
            text = logBuffer.toString();
        }
        cm.setPrimaryClip(ClipData.newPlainText("ghostlock-log", text));
        Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show();
    }

    /**
     * Open the crash-log sink. Prefers the public Download directory; falls
     * back to the app-specific external dir, then internal storage.
     *
     * <p>The native binary can panic the kernel at any moment, so every line
     * is flushed immediately and fsynced at a short interval. Otherwise the
     * dirty page cache never reaches storage before the device resets.
     */
    private synchronized void initLogFile() {
        if (logStream != null) {
            return;
        }
        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
        String name = LOG_PREFIX + stamp + ".log";

        List<File> candidates = new ArrayList<>();
        try {
            File downloads = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS);
            if (downloads != null) {
                candidates.add(new File(downloads, name));
            }
        } catch (Throwable ignored) {
            // Deprecated on newer SDKs; the literal path below is the fallback.
        }
        candidates.add(new File("/storage/emulated/0/Download", name));
        File external = getExternalFilesDir(null);
        if (external != null) {
            candidates.add(new File(external, name));
        }
        candidates.add(new File(getFilesDir(), name));

        for (File candidate : candidates) {
            try {
                File dir = candidate.getParentFile();
                if (dir != null && !dir.isDirectory() && !dir.mkdirs()) {
                    continue;
                }
                FileOutputStream out = new FileOutputStream(candidate, true);
                out.flush();
                logStream = out;
                logFile = candidate;
                break;
            } catch (Throwable ignored) {
                // Try the next candidate.
            }
        }
        if (logStream == null) {
            return;
        }

        StringBuilder header = new StringBuilder();
        header.append("# GhostLock crash log\n");
        header.append("# started=")
                .append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date()))
                .append('\n');
        header.append("# device=").append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append('\n');
        header.append("# build=").append(Build.DISPLAY).append('\n');
        header.append("# fingerprint=").append(Build.FINGERPRINT).append('\n');
        header.append("# kernel=").append(System.getProperty("os.version", "unknown")).append('\n');
        header.append("# sdk=").append(Build.VERSION.SDK_INT).append('\n');
        header.append("# path=").append(logFile.getAbsolutePath()).append('\n');
        try {
            logStream.write(header.toString().getBytes(StandardCharsets.UTF_8));
            logStream.flush();
            logStream.getFD().sync();
            lastSyncMs = System.currentTimeMillis();
        } catch (Throwable ignored) {
            // Keep going: the logger still works even if the header failed.
        }
    }

    private boolean isLogWritable() {
        return logStream != null;
    }

    /** Append one line to the crash log and keep it durable. */
    private synchronized void writeLogLine(String line) {
        if (logStream == null || line == null) {
            return;
        }
        try {
            logStream.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            logStream.flush();
            long now = System.currentTimeMillis();
            if (now - lastSyncMs >= LOG_SYNC_INTERVAL_MS) {
                logStream.getFD().sync();
                lastSyncMs = now;
            }
        } catch (Throwable ignored) {
            // Never let logging break the exploit flow.
        }
    }

    /** Force pending lines to disk, e.g. right before an expected hang. */
    private synchronized void syncLog() {
        if (logStream == null) {
            return;
        }
        try {
            logStream.flush();
            logStream.getFD().sync();
            lastSyncMs = System.currentTimeMillis();
        } catch (Throwable ignored) {
        }
    }

    private synchronized void closeLog() {
        if (logStream == null) {
            return;
        }
        try {
            logStream.flush();
            logStream.getFD().sync();
            logStream.close();
        } catch (Throwable ignored) {
        }
        logStream = null;
    }

    /** All-files access is required to write into the public Download dir. */
    private void ensureLogPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return;
        }
        try {
            if (Environment.isExternalStorageManager()) {
                return;
            }
            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        } catch (Throwable t) {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            } catch (Throwable ignored) {
                // Nothing else we can do; initLogFile() falls back on its own.
            }
        }
    }

    private void appendLog(String line) {
        if (line == null) {
            return;
        }
        // Persist the raw line before any cosmetic filtering: a kernel panic can
        // strike at any moment, so nothing should be dropped from the crash log.
        writeLogLine(stripAnsi(line));
        final String normalized = normalizeLoaderLine(line);
        if (normalized == null) {
            return;
        }
        final String msg = normalized.endsWith("\n") ? normalized : normalized + "\n";
        final String plain = stripAnsi(msg);
        synchronized (logBuffer) {
            logBuffer.append(plain);
        }
        final CharSequence display = colorize(plain);
        ui.post(() -> {
            logView.append(display);
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        });
        android.util.Log.i(TAG, plain.trim());
    }

    /** Collapse the 77 preload's seven-step presentation into the same
     * marker-based diagnostics used by the 118 GhostLock binary. */
    private static String normalizeLoaderLine(String raw) {
        String plain = stripAnsi(raw);
        String line = plain.trim();
        if (line.matches("\\[\\d+/7\\].*") || line.contains("stage=") && line.contains("/7") ||
                line.startsWith("OK ...") || line.startsWith("FAILED ...") ||
                line.startsWith("总耗时：") || line.startsWith("日志已保存在：")) {
            return null;
        }
        if (line.startsWith("玄戒O1系列提权-") || line.startsWith("机型：") ||
                line.startsWith("内核版本：")) {
            return null;
        }
        if (line.equals("酷安@ayyya")) {
            return "[+] 酷安@ayyya";
        }
        if (line.startsWith("错误：")) {
            return "[!] " + line.substring(3).trim();
        }
        if (line.startsWith("____") || line.startsWith("|  _ ") ||
                line.startsWith("| | ") || line.startsWith("| |_|") ||
                line.startsWith("|____")) {
            return null;
        }
        return plain;
    }

    private int dp(int value) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(value * density);
    }

    private enum RunState {
        IDLE, RUNNING, SUCCESS, FAILED
    }

    private enum RootImplementation {
        KERNEL_SU("kernelsu", "KernelSU",
                "managers/kernelsu.apk", "kernelsu.apk", "libksud_kernelsu.so"),
        RESUKI_SU("resukisu", "ReSukiSU",
                "managers/resukisu.apk", "resukisu.apk", "libksud_resukisu.so");

        final String preferenceValue;
        final String displayName;
        final String managerAssetPath;
        final String managerFileName;
        final String packagedKsudName;

        RootImplementation(String preferenceValue, String displayName,
                           String managerAssetPath, String managerFileName,
                           String packagedKsudName) {
            this.preferenceValue = preferenceValue;
            this.displayName = displayName;
            this.managerAssetPath = managerAssetPath;
            this.managerFileName = managerFileName;
            this.packagedKsudName = packagedKsudName;
        }

        static RootImplementation fromPreference(String value) {
            for (RootImplementation implementation : values()) {
                if (implementation.preferenceValue.equals(value)) {
                    return implementation;
                }
            }
            return KERNEL_SU;
        }
    }
}
