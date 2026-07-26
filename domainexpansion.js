'use strict';

// Java API Monitor
// A standalone, Java-layer Frida activity logger. It observes selected Android
// and Java framework APIs without changing arguments or return values.

// Configuration
const CONFIG = {
    maxStringLength: 500,
    maxBytePreview: 64,
    deoptimizeBootImage: true,
    // Disabled because full deoptimization can be expensive and disruptive.
    deoptimizeEverythingFallback: false,
    logSettingsCaller: false,
    duplicateWindowMs: 2000,
    maxCollectionPreview: 8
};

// Logging utilities
const MONITOR = {
    guards: Object.create(null),
    duplicates: Object.create(null),
    installedHooks: 0
};

function logLine(category, message) {
    try {
        console.log('[' + category + '] ' + message);
    } catch (_) {
        // Observation must never break the target application's API call.
    }
}

function conciseError(error) {
    try {
        const text = String(error);
        const firstLine = text.split(/\r?\n/, 1)[0];
        return truncate(firstLine, 240);
    } catch (_) {
        return '<unknown error>';
    }
}

function truncate(value, limit) {
    const maximum = typeof limit === 'number' ? limit : CONFIG.maxStringLength;
    let text;
    try {
        if (value === null) {
            return 'null';
        }
        if (value === undefined) {
            return 'undefined';
        }
        text = String(value);
    } catch (_) {
        return '<unprintable>';
    }
    if (text.length <= maximum) {
        return text;
    }
    return text.substring(0, maximum) + '…(+' + (text.length - maximum) + ' chars)';
}

function quoted(value, limit) {
    if (value === null || value === undefined) {
        return String(value);
    }
    const text = truncate(value, limit)
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\r/g, '\\r')
        .replace(/\n/g, '\\n')
        .replace(/\t/g, '\\t');
    return '"' + text + '"';
}

function arrayLength(value) {
    try {
        return value === null || value === undefined ? 0 : value.length;
    } catch (_) {
        return 0;
    }
}

function textLength(value) {
    try {
        return value === null || value === undefined ? 0 : String(value).length;
    } catch (_) {
        return 0;
    }
}

function bytePreview(bytes, previewLimit) {
    try {
        if (bytes === null || bytes === undefined) {
            return 'length=0 preview=<null>';
        }
        const total = bytes.length;
        const limit = Math.min(
            total,
            typeof previewLimit === 'number' ? previewLimit : CONFIG.maxBytePreview
        );
        let hex = '';
        for (let i = 0; i < limit; i++) {
            const value = bytes[i] & 0xff;
            if (i > 0) {
                hex += ' ';
            }
            hex += ('0' + value.toString(16)).slice(-2);
        }
        if (total > limit) {
            hex += ' …';
        }
        return 'length=' + total + ' preview=' + (hex || '<empty>');
    } catch (_) {
        return 'length=? preview=<unavailable>';
    }
}

function stringArrayPreview(values) {
    try {
        if (values === null || values === undefined) {
            return 'null';
        }
        const count = values.length;
        const rendered = [];
        const limit = Math.min(count, CONFIG.maxCollectionPreview);
        for (let i = 0; i < limit; i++) {
            rendered.push(quoted(values[i], 160));
        }
        if (count > limit) {
            rendered.push('…(+' + (count - limit) + ')');
        }
        return '[' + rendered.join(', ') + ']';
    } catch (_) {
        return '[<unavailable>]';
    }
}

function javaListPreview(list) {
    try {
        if (list === null || list === undefined) {
            return 'null';
        }
        const count = list.size();
        const rendered = [];
        const limit = Math.min(count, CONFIG.maxCollectionPreview);
        for (let i = 0; i < limit; i++) {
            rendered.push(quoted(list.get(i), 160));
        }
        if (count > limit) {
            rendered.push('…(+' + (count - limit) + ')');
        }
        return '[' + rendered.join(', ') + ']';
    } catch (_) {
        return '[<unavailable>]';
    }
}

function javaSetPreview(set) {
    try {
        if (set === null || set === undefined) {
            return 'null';
        }
        const count = set.size();
        const rendered = [];
        const iterator = set.iterator();
        let seen = 0;
        while (iterator.hasNext() && seen < CONFIG.maxCollectionPreview) {
            rendered.push(quoted(iterator.next(), 160));
            seen++;
        }
        if (count > seen) {
            rendered.push('…(+' + (count - seen) + ')');
        }
        return '[' + rendered.join(', ') + ']';
    } catch (_) {
        return '[<unavailable>]';
    }
}

function redactHeader(name, value) {
    const header = truncate(name, 120);
    const lower = header.toLowerCase();
    if (lower === 'authorization' ||
        lower === 'cookie' ||
        lower === 'set-cookie' ||
        lower === 'proxy-authorization') {
        const text = truncate(value, 32);
        return text.length === 0 ? '<redacted>' : text.substring(0, 12) + '…<redacted>';
    }
    return truncate(value, 200);
}

function shouldSuppress(key, windowMs) {
    const now = Date.now();
    const interval = typeof windowMs === 'number' ? windowMs : CONFIG.duplicateWindowMs;
    const previous = MONITOR.duplicates[key];
    MONITOR.duplicates[key] = now;
    if (previous !== undefined && now - previous < interval) {
        return true;
    }

    const keys = Object.keys(MONITOR.duplicates);
    if (keys.length > 1000) {
        for (let i = 0; i < keys.length; i++) {
            if (now - MONITOR.duplicates[keys[i]] > 60000) {
                delete MONITOR.duplicates[keys[i]];
            }
        }
    }
    return false;
}

function withGuard(name, originalCall, observedCall) {
    if (MONITOR.guards[name]) {
        return originalCall();
    }
    MONITOR.guards[name] = true;
    try {
        return observedCall();
    } finally {
        MONITOR.guards[name] = false;
    }
}

// Safe hook helpers
function findOverload(target, methodName, signature) {
    if (!target || !target[methodName]) {
        throw new Error('method unavailable');
    }
    return target[methodName].overload.apply(target[methodName], signature);
}

function installExact(label, target, methodName, signature, makeImplementation) {
    try {
        const overload = findOverload(target, methodName, signature);
        overload.implementation = makeImplementation(overload);
        MONITOR.installedHooks++;
        logLine('HOOK', 'Installed ' + label);
        return 1;
    } catch (error) {
        logLine('HOOK', 'Skipped ' + label + ': ' + conciseError(error));
        return 0;
    }
}

function useClass(name) {
    try {
        return Java.use(name);
    } catch (error) {
        logLine('HOOK', 'Skipped ' + name + ': class unavailable');
        return null;
    }
}

function runGroup(name, installer) {
    try {
        const hooks = installer();
        if (hooks > 0) {
            logLine('HOOK', name + ' group ready (' + hooks + ' hooks)');
            return true;
        }
        logLine('HOOK', name + ' group unavailable');
    } catch (error) {
        logLine('HOOK', name + ' group skipped: ' + conciseError(error));
    }
    return false;
}

function sensitiveSettingKey(key) {
    const text = truncate(key, 120).toLowerCase();
    return text === 'adb_enabled' ||
        text === 'development_settings_enabled' ||
        text === 'adb_wifi_enabled';
}

function emphasizedSettingKey(key) {
    const text = truncate(key, 120).toLowerCase();
    return sensitiveSettingKey(text) ||
        text === 'install_non_market_apps' ||
        text === 'android_id' ||
        text === 'mock_location' ||
        text === 'accessibility_enabled' ||
        text === 'enabled_accessibility_services';
}

function logSettingsCaller(key) {
    if (!CONFIG.logSettingsCaller || !sensitiveSettingKey(key) || MONITOR.guards.settingsCaller) {
        return;
    }
    MONITOR.guards.settingsCaller = true;
    try {
        const Exception = Java.use('java.lang.Exception');
        const stack = Exception.$new().getStackTrace();
        for (let i = 0; i < stack.length; i++) {
            const className = truncate(stack[i].getClassName(), 180);
            const methodName = truncate(stack[i].getMethodName(), 120);
            if (className.indexOf('android.provider.Settings') === 0 ||
                className.indexOf('java.lang.Exception') === 0) {
                continue;
            }
            logLine('SETTINGS', '          caller: ' + className + '.' + methodName);
            break;
        }
    } catch (error) {
        logLine('HOOK', 'Settings caller unavailable: ' + conciseError(error));
    } finally {
        MONITOR.guards.settingsCaller = false;
    }
}

// Settings hooks
function installSettingsHooks() {
    let hooks = 0;
    const families = [
        ['Global', 'android.provider.Settings$Global'],
        ['Secure', 'android.provider.Settings$Secure'],
        ['System', 'android.provider.Settings$System']
    ];

    families.forEach(function (family) {
        const label = family[0];
        const Settings = useClass(family[1]);
        if (!Settings) {
            return;
        }

        hooks += installExact(
            'Settings.' + label + '.getInt(ContentResolver,String)',
            Settings,
            'getInt',
            ['android.content.ContentResolver', 'java.lang.String'],
            function (original) {
                return function (resolver, key) {
                    const result = original.call(this, resolver, key);
                    const marker = emphasizedSettingKey(key) ? ' [sensitive]' : '';
                    logLine('SETTINGS', label + '.getInt(' + quoted(key, 160) + ') -> ' + result + marker);
                    logSettingsCaller(key);
                    return result;
                };
            }
        );

        hooks += installExact(
            'Settings.' + label + '.getInt(ContentResolver,String,int)',
            Settings,
            'getInt',
            ['android.content.ContentResolver', 'java.lang.String', 'int'],
            function (original) {
                return function (resolver, key, defaultValue) {
                    const result = original.call(this, resolver, key, defaultValue);
                    const marker = emphasizedSettingKey(key) ? ' [sensitive]' : '';
                    logLine(
                        'SETTINGS',
                        label + '.getInt(' + quoted(key, 160) + ', default=' + defaultValue + ') -> ' +
                        result + marker
                    );
                    logSettingsCaller(key);
                    return result;
                };
            }
        );

        hooks += installExact(
            'Settings.' + label + '.getString(ContentResolver,String)',
            Settings,
            'getString',
            ['android.content.ContentResolver', 'java.lang.String'],
            function (original) {
                return function (resolver, key) {
                    const result = original.call(this, resolver, key);
                    const marker = emphasizedSettingKey(key) ? ' [sensitive]' : '';
                    logLine(
                        'SETTINGS',
                        label + '.getString(' + quoted(key, 160) + ') -> ' + quoted(result) + marker
                    );
                    logSettingsCaller(key);
                    return result;
                };
            }
        );
    });
    return hooks;
}

// Debugger and system-property hooks
function installDebuggerHooks() {
    let hooks = 0;
    const Debug = useClass('android.os.Debug');
    if (!Debug) {
        return hooks;
    }

    ['isDebuggerConnected', 'waitingForDebugger'].forEach(function (methodName) {
        hooks += installExact(
            'Debug.' + methodName + '()',
            Debug,
            methodName,
            [],
            function (original) {
                return function () {
                    const result = original.call(this);
                    logLine('DEBUG', methodName + '() -> ' + result);
                    return result;
                };
            }
        );
    });
    return hooks;
}

function installSystemPropertyHooks() {
    let hooks = 0;
    const Properties = useClass('android.os.SystemProperties');
    if (!Properties) {
        return hooks;
    }

    hooks += installExact(
        'SystemProperties.get(String)',
        Properties,
        'get',
        ['java.lang.String'],
        function (original) {
            return function (key) {
                const result = original.call(this, key);
                logLine('PROPERTY', 'get(' + quoted(key, 180) + ') -> ' + quoted(result));
                return result;
            };
        }
    );
    hooks += installExact(
        'SystemProperties.get(String,String)',
        Properties,
        'get',
        ['java.lang.String', 'java.lang.String'],
        function (original) {
            return function (key, defaultValue) {
                const result = original.call(this, key, defaultValue);
                logLine(
                    'PROPERTY',
                    'get(' + quoted(key, 180) + ', default=' + quoted(defaultValue, 160) + ') -> ' +
                    quoted(result)
                );
                return result;
            };
        }
    );

    [
        ['getInt', 'int'],
        ['getLong', 'long'],
        ['getBoolean', 'boolean']
    ].forEach(function (entry) {
        const methodName = entry[0];
        const defaultType = entry[1];
        hooks += installExact(
            'SystemProperties.' + methodName + '(String,' + defaultType + ')',
            Properties,
            methodName,
            ['java.lang.String', defaultType],
            function (original) {
                return function (key, defaultValue) {
                    const result = original.call(this, key, defaultValue);
                    logLine(
                        'PROPERTY',
                        methodName + '(' + quoted(key, 180) + ', default=' + defaultValue + ') -> ' + result
                    );
                    return result;
                };
            }
        );
    });
    return hooks;
}

// Filesystem hooks
function installFilesystemHooks() {
    let hooks = 0;
    const File = useClass('java.io.File');
    if (!File) {
        return hooks;
    }

    [
        'exists',
        'canRead',
        'canWrite',
        'isFile',
        'isDirectory',
        'length',
        'delete',
        'mkdir',
        'mkdirs'
    ].forEach(function (methodName) {
        hooks += installExact(
            'File.' + methodName + '()',
            File,
            methodName,
            [],
            function (original) {
                return function () {
                    const self = this;
                    return withGuard(
                        'file',
                        function () {
                            return original.call(self);
                        },
                        function () {
                            let path = '<unknown>';
                            try {
                                path = truncate(self.getAbsolutePath(), 360);
                            } catch (_) {
                                path = '<path unavailable>';
                            }
                            const result = original.call(self);
                            const duplicateKey = 'file|' + methodName + '|' + path + '|' + result;
                            if (!shouldSuppress(duplicateKey)) {
                                logLine('FILE', methodName + '(' + quoted(path, 360) + ') -> ' + result);
                            }
                            return result;
                        }
                    );
                };
            }
        );
    });

    hooks += installExact(
        'File.list()',
        File,
        'list',
        [],
        function (original) {
            return function () {
                const self = this;
                return withGuard(
                    'file',
                    function () {
                        return original.call(self);
                    },
                    function () {
                        const path = truncate(self.getAbsolutePath(), 360);
                        const result = original.call(self);
                        const count = result === null ? 'null' : result.length;
                        if (!shouldSuppress('file|list|' + path + '|' + count)) {
                            logLine('FILE', 'list(' + quoted(path, 360) + ') -> count=' + count);
                        }
                        return result;
                    }
                );
            };
        }
    );

    hooks += installExact(
        'File.listFiles()',
        File,
        'listFiles',
        [],
        function (original) {
            return function () {
                const self = this;
                return withGuard(
                    'file',
                    function () {
                        return original.call(self);
                    },
                    function () {
                        const path = truncate(self.getAbsolutePath(), 360);
                        const result = original.call(self);
                        const count = result === null ? 'null' : result.length;
                        if (!shouldSuppress('file|listFiles|' + path + '|' + count)) {
                            logLine('FILE', 'listFiles(' + quoted(path, 360) + ') -> count=' + count);
                        }
                        return result;
                    }
                );
            };
        }
    );
    return hooks;
}

// Command-execution hooks
function installCommandExecutionHooks() {
    let hooks = 0;
    const Runtime = useClass('java.lang.Runtime');
    if (Runtime) {
        hooks += installExact(
            'Runtime.exec(String)',
            Runtime,
            'exec',
            ['java.lang.String'],
            function (original) {
                return function (command) {
                    logLine('EXEC', 'Runtime.exec(' + quoted(command, 400) + ')');
                    return original.call(this, command);
                };
            }
        );
        hooks += installExact(
            'Runtime.exec(String,String[])',
            Runtime,
            'exec',
            ['java.lang.String', '[Ljava.lang.String;'],
            function (original) {
                return function (command, environment) {
                    logLine(
                        'EXEC',
                        'Runtime.exec(' + quoted(command, 400) + ', envCount=' + arrayLength(environment) + ')'
                    );
                    return original.call(this, command, environment);
                };
            }
        );
        hooks += installExact(
            'Runtime.exec(String,String[],File)',
            Runtime,
            'exec',
            ['java.lang.String', '[Ljava.lang.String;', 'java.io.File'],
            function (original) {
                return function (command, environment, directory) {
                    let cwd = 'null';
                    try {
                        cwd = directory === null ? 'null' : quoted(directory.getAbsolutePath(), 300);
                    } catch (_) {
                        cwd = '<unavailable>';
                    }
                    logLine(
                        'EXEC',
                        'Runtime.exec(' + quoted(command, 400) + ', envCount=' +
                        arrayLength(environment) + ', cwd=' + cwd + ')'
                    );
                    return original.call(this, command, environment, directory);
                };
            }
        );
        hooks += installExact(
            'Runtime.exec(String[])',
            Runtime,
            'exec',
            ['[Ljava.lang.String;'],
            function (original) {
                return function (command) {
                    logLine('EXEC', 'Runtime.exec(' + stringArrayPreview(command) + ')');
                    return original.call(this, command);
                };
            }
        );
        hooks += installExact(
            'Runtime.exec(String[],String[])',
            Runtime,
            'exec',
            ['[Ljava.lang.String;', '[Ljava.lang.String;'],
            function (original) {
                return function (command, environment) {
                    logLine(
                        'EXEC',
                        'Runtime.exec(' + stringArrayPreview(command) +
                        ', envCount=' + arrayLength(environment) + ')'
                    );
                    return original.call(this, command, environment);
                };
            }
        );
        hooks += installExact(
            'Runtime.exec(String[],String[],File)',
            Runtime,
            'exec',
            ['[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File'],
            function (original) {
                return function (command, environment, directory) {
                    let cwd = 'null';
                    try {
                        cwd = directory === null ? 'null' : quoted(directory.getAbsolutePath(), 300);
                    } catch (_) {
                        cwd = '<unavailable>';
                    }
                    logLine(
                        'EXEC',
                        'Runtime.exec(' + stringArrayPreview(command) +
                        ', envCount=' + arrayLength(environment) + ', cwd=' + cwd + ')'
                    );
                    return original.call(this, command, environment, directory);
                };
            }
        );
    }

    const ProcessBuilder = useClass('java.lang.ProcessBuilder');
    if (ProcessBuilder) {
        hooks += installExact(
            'ProcessBuilder.start()',
            ProcessBuilder,
            'start',
            [],
            function (original) {
                return function () {
                    let command = '[<unavailable>]';
                    try {
                        command = javaListPreview(this.command());
                    } catch (_) {
                        // Keep the unavailable marker.
                    }
                    logLine('EXEC', 'ProcessBuilder(' + command + ').start()');
                    return original.call(this);
                };
            }
        );
    }
    return hooks;
}

// Package-manager hooks
function packageListSummary(list, fieldName) {
    try {
        if (list === null || list === undefined) {
            return 'count=null';
        }
        const count = list.size();
        const names = [];
        const limit = Math.min(count, CONFIG.maxCollectionPreview);
        for (let i = 0; i < limit; i++) {
            const item = list.get(i);
            let name = '<unknown>';
            try {
                if (fieldName === 'activityInfo' && item.activityInfo.value) {
                    name = item.activityInfo.value.packageName.value;
                } else if (item[fieldName]) {
                    name = item[fieldName].value;
                }
            } catch (_) {
                name = '<unknown>';
            }
            names.push(quoted(name, 140));
        }
        if (count > limit) {
            names.push('…(+' + (count - limit) + ')');
        }
        return 'count=' + count + (names.length ? ' packages=[' + names.join(', ') + ']' : '');
    } catch (_) {
        return 'count=?';
    }
}

function packageFlagsText(flags) {
    try {
        if (flags === null || flags === undefined) {
            return 'null';
        }
        if (typeof flags === 'number') {
            return String(flags);
        }
        if (flags.getValue) {
            return String(flags.getValue());
        }
        return truncate(flags, 80);
    } catch (_) {
        return '?';
    }
}

function installPackageManagerHooks() {
    let hooks = 0;
    const PackageManager = useClass('android.app.ApplicationPackageManager');
    if (!PackageManager) {
        return hooks;
    }

    function installPackageLookup(methodName, flagType) {
        hooks += installExact(
            'ApplicationPackageManager.' + methodName + '(String,' + flagType + ')',
            PackageManager,
            methodName,
            ['java.lang.String', flagType],
            function (original) {
                return function (packageName, flags) {
                    logLine(
                        'PACKAGE',
                        methodName + '(' + quoted(packageName, 220) + ', flags=' +
                        packageFlagsText(flags) + ')'
                    );
                    return original.call(this, packageName, flags);
                };
            }
        );
    }

    installPackageLookup('getPackageInfo', 'int');
    installPackageLookup('getPackageInfo', 'android.content.pm.PackageManager$PackageInfoFlags');
    installPackageLookup('getApplicationInfo', 'int');
    installPackageLookup('getApplicationInfo', 'android.content.pm.PackageManager$ApplicationInfoFlags');

    hooks += installExact(
        'ApplicationPackageManager.getInstallerPackageName(String)',
        PackageManager,
        'getInstallerPackageName',
        ['java.lang.String'],
        function (original) {
            return function (packageName) {
                const result = original.call(this, packageName);
                logLine(
                    'PACKAGE',
                    'getInstallerPackageName(' + quoted(packageName, 220) + ') -> ' + quoted(result, 220)
                );
                return result;
            };
        }
    );

    hooks += installExact(
        'ApplicationPackageManager.getInstallSourceInfo(String)',
        PackageManager,
        'getInstallSourceInfo',
        ['java.lang.String'],
        function (original) {
            return function (packageName) {
                const result = original.call(this, packageName);
                let installing = '<unavailable>';
                try {
                    installing = quoted(result.getInstallingPackageName(), 220);
                } catch (_) {
                    // Older or vendor-modified implementations may differ.
                }
                logLine(
                    'PACKAGE',
                    'getInstallSourceInfo(' + quoted(packageName, 220) + ') -> installing=' + installing
                );
                return result;
            };
        }
    );

    function installListQuery(methodName, flagType, fieldName) {
        hooks += installExact(
            'ApplicationPackageManager.' + methodName + '(' + flagType + ')',
            PackageManager,
            methodName,
            [flagType],
            function (original) {
                return function (flags) {
                    const result = original.call(this, flags);
                    logLine(
                        'PACKAGE',
                        methodName + '(flags=' + packageFlagsText(flags) + ') -> ' +
                        packageListSummary(result, fieldName)
                    );
                    return result;
                };
            }
        );
    }

    installListQuery('getInstalledPackages', 'int', 'packageName');
    installListQuery(
        'getInstalledPackages',
        'android.content.pm.PackageManager$PackageInfoFlags',
        'packageName'
    );
    installListQuery('getInstalledApplications', 'int', 'packageName');
    installListQuery(
        'getInstalledApplications',
        'android.content.pm.PackageManager$ApplicationInfoFlags',
        'packageName'
    );

    function installIntentQuery(flagType) {
        hooks += installExact(
            'ApplicationPackageManager.queryIntentActivities(Intent,' + flagType + ')',
            PackageManager,
            'queryIntentActivities',
            ['android.content.Intent', flagType],
            function (original) {
                return function (intent, flags) {
                    const result = original.call(this, intent, flags);
                    logLine(
                        'PACKAGE',
                        'queryIntentActivities(' + intentSummary(intent) + ', flags=' +
                        packageFlagsText(flags) + ') -> ' + packageListSummary(result, 'activityInfo')
                    );
                    return result;
                };
            }
        );
    }

    installIntentQuery('int');
    installIntentQuery('android.content.pm.PackageManager$ResolveInfoFlags');
    return hooks;
}

// SharedPreferences hooks
function installSharedPreferencesHooks() {
    let hooks = 0;
    const Preferences = useClass('android.app.SharedPreferencesImpl');
    const Editor = useClass('android.app.SharedPreferencesImpl$EditorImpl');

    if (Preferences) {
        const preferenceReads = [
            ['getString', 'java.lang.String', function (value) { return quoted(value); }],
            ['getBoolean', 'boolean', function (value) { return String(value); }],
            ['getInt', 'int', function (value) { return String(value); }],
            ['getLong', 'long', function (value) { return String(value); }],
            ['getFloat', 'float', function (value) { return String(value); }]
        ];

        preferenceReads.forEach(function (entry) {
            const methodName = entry[0];
            const valueType = entry[1];
            const render = entry[2];
            hooks += installExact(
                'SharedPreferencesImpl.' + methodName + '(String,' + valueType + ')',
                Preferences,
                methodName,
                ['java.lang.String', valueType],
                function (original) {
                    return function (key, defaultValue) {
                        const self = this;
                        return withGuard(
                            'preferences',
                            function () {
                                return original.call(self, key, defaultValue);
                            },
                            function () {
                                const result = original.call(self, key, defaultValue);
                                logLine(
                                    'PREF',
                                    methodName + '(' + quoted(key, 180) + ', default=' +
                                    render(defaultValue) + ') -> ' + render(result)
                                );
                                return result;
                            }
                        );
                    };
                }
            );
        });

        hooks += installExact(
            'SharedPreferencesImpl.getStringSet(String,Set)',
            Preferences,
            'getStringSet',
            ['java.lang.String', 'java.util.Set'],
            function (original) {
                return function (key, defaultValue) {
                    const self = this;
                    return withGuard(
                        'preferences',
                        function () {
                            return original.call(self, key, defaultValue);
                        },
                        function () {
                            const result = original.call(self, key, defaultValue);
                            logLine(
                                'PREF',
                                'getStringSet(' + quoted(key, 180) + ', default=' +
                                javaSetPreview(defaultValue) + ') -> ' + javaSetPreview(result)
                            );
                            return result;
                        }
                    );
                };
            }
        );

        hooks += installExact(
            'SharedPreferencesImpl.contains(String)',
            Preferences,
            'contains',
            ['java.lang.String'],
            function (original) {
                return function (key) {
                    const self = this;
                    return withGuard(
                        'preferences',
                        function () {
                            return original.call(self, key);
                        },
                        function () {
                            const result = original.call(self, key);
                            logLine('PREF', 'contains(' + quoted(key, 180) + ') -> ' + result);
                            return result;
                        }
                    );
                };
            }
        );
    }

    if (Editor) {
        const preferenceWrites = [
            ['putString', 'java.lang.String', function (value) { return quoted(value); }],
            ['putBoolean', 'boolean', function (value) { return String(value); }],
            ['putInt', 'int', function (value) { return String(value); }],
            ['putLong', 'long', function (value) { return String(value); }],
            ['putFloat', 'float', function (value) { return String(value); }]
        ];

        preferenceWrites.forEach(function (entry) {
            const methodName = entry[0];
            const valueType = entry[1];
            const render = entry[2];
            hooks += installExact(
                'SharedPreferencesImpl.EditorImpl.' + methodName + '(String,' + valueType + ')',
                Editor,
                methodName,
                ['java.lang.String', valueType],
                function (original) {
                    return function (key, value) {
                        const self = this;
                        return withGuard(
                            'preferences',
                            function () {
                                return original.call(self, key, value);
                            },
                            function () {
                                logLine(
                                    'PREF',
                                    methodName + '(' + quoted(key, 180) + ', ' + render(value) + ')'
                                );
                                return original.call(self, key, value);
                            }
                        );
                    };
                }
            );
        });

        hooks += installExact(
            'SharedPreferencesImpl.EditorImpl.putStringSet(String,Set)',
            Editor,
            'putStringSet',
            ['java.lang.String', 'java.util.Set'],
            function (original) {
                return function (key, value) {
                    const self = this;
                    return withGuard(
                        'preferences',
                        function () {
                            return original.call(self, key, value);
                        },
                        function () {
                            logLine(
                                'PREF',
                                'putStringSet(' + quoted(key, 180) + ', ' + javaSetPreview(value) + ')'
                            );
                            return original.call(self, key, value);
                        }
                    );
                };
            }
        );

        hooks += installExact(
            'SharedPreferencesImpl.EditorImpl.remove(String)',
            Editor,
            'remove',
            ['java.lang.String'],
            function (original) {
                return function (key) {
                    logLine('PREF', 'remove(' + quoted(key, 180) + ')');
                    return original.call(this, key);
                };
            }
        );

        ['clear', 'commit', 'apply'].forEach(function (methodName) {
            hooks += installExact(
                'SharedPreferencesImpl.EditorImpl.' + methodName + '()',
                Editor,
                methodName,
                [],
                function (original) {
                    return function () {
                        const result = original.call(this);
                        if (methodName === 'commit') {
                            logLine('PREF', 'commit() -> ' + result);
                        } else {
                            logLine('PREF', methodName + '()');
                        }
                        return result;
                    };
                }
            );
        });
    }
    return hooks;
}

// Network hooks
function connectionUrl(connection) {
    try {
        return quoted(connection.getURL().toString(), 420);
    } catch (_) {
        return '<URL unavailable>';
    }
}

function installNetworkHooks() {
    let hooks = 0;
    const URL = useClass('java.net.URL');
    if (URL) {
        hooks += installExact(
            'URL.$init(String)',
            URL,
            '$init',
            ['java.lang.String'],
            function (original) {
                return function (spec) {
                    const self = this;
                    return withGuard(
                        'url',
                        function () {
                            return original.call(self, spec);
                        },
                        function () {
                            const result = original.call(self, spec);
                            logLine('NETWORK', 'URL(' + quoted(spec, 420) + ')');
                            return result;
                        }
                    );
                };
            }
        );
        hooks += installExact(
            'URL.$init(URL,String)',
            URL,
            '$init',
            ['java.net.URL', 'java.lang.String'],
            function (original) {
                return function (context, spec) {
                    const self = this;
                    return withGuard(
                        'url',
                        function () {
                            return original.call(self, context, spec);
                        },
                        function () {
                            const result = original.call(self, context, spec);
                            logLine(
                                'NETWORK',
                                'URL(context=' + quoted(context, 300) + ', spec=' + quoted(spec, 420) + ')'
                            );
                            return result;
                        }
                    );
                };
            }
        );
        hooks += installExact(
            'URL.$init(String,String,String)',
            URL,
            '$init',
            ['java.lang.String', 'java.lang.String', 'java.lang.String'],
            function (original) {
                return function (protocol, host, file) {
                    const result = original.call(this, protocol, host, file);
                    logLine(
                        'NETWORK',
                        'URL(protocol=' + quoted(protocol, 40) + ', host=' + quoted(host, 220) +
                        ', file=' + quoted(file, 300) + ')'
                    );
                    return result;
                };
            }
        );
        hooks += installExact(
            'URL.$init(String,String,int,String)',
            URL,
            '$init',
            ['java.lang.String', 'java.lang.String', 'int', 'java.lang.String'],
            function (original) {
                return function (protocol, host, port, file) {
                    const result = original.call(this, protocol, host, port, file);
                    logLine(
                        'NETWORK',
                        'URL(protocol=' + quoted(protocol, 40) + ', host=' + quoted(host, 220) +
                        ', port=' + port + ', file=' + quoted(file, 300) + ')'
                    );
                    return result;
                };
            }
        );

        hooks += installExact(
            'URL.openConnection()',
            URL,
            'openConnection',
            [],
            function (original) {
                return function () {
                    const self = this;
                    return withGuard(
                        'url',
                        function () {
                            return original.call(self);
                        },
                        function () {
                            const target = quoted(self.toString(), 420);
                            const result = original.call(self);
                            logLine('NETWORK', 'openConnection(' + target + ')');
                            return result;
                        }
                    );
                };
            }
        );
        hooks += installExact(
            'URL.openConnection(Proxy)',
            URL,
            'openConnection',
            ['java.net.Proxy'],
            function (original) {
                return function (proxy) {
                    const self = this;
                    return withGuard(
                        'url',
                        function () {
                            return original.call(self, proxy);
                        },
                        function () {
                            const target = quoted(self.toString(), 420);
                            const result = original.call(self, proxy);
                            logLine('NETWORK', 'openConnection(' + target + ', proxy=' + truncate(proxy, 160) + ')');
                            return result;
                        }
                    );
                };
            }
        );
    }

    const HttpURLConnection = useClass('java.net.HttpURLConnection');
    if (HttpURLConnection) {
        hooks += installExact(
            'HttpURLConnection.setRequestMethod(String)',
            HttpURLConnection,
            'setRequestMethod',
            ['java.lang.String'],
            function (original) {
                return function (method) {
                    logLine('NETWORK', 'method ' + truncate(method, 32) + ' url=' + connectionUrl(this));
                    return original.call(this, method);
                };
            }
        );
    }

    const URLConnection = useClass('java.net.URLConnection');
    if (URLConnection) {
        ['setRequestProperty', 'addRequestProperty'].forEach(function (methodName) {
            hooks += installExact(
                'URLConnection.' + methodName + '(String,String)',
                URLConnection,
                methodName,
                ['java.lang.String', 'java.lang.String'],
                function (original) {
                    return function (name, value) {
                        logLine(
                            'NETWORK',
                            'header ' + truncate(name, 120) + ': ' + redactHeader(name, value) +
                            ' url=' + connectionUrl(this)
                        );
                        return original.call(this, name, value);
                    };
                }
            );
        });
        hooks += installExact(
            'URLConnection.connect()',
            URLConnection,
            'connect',
            [],
            function (original) {
                return function () {
                    logLine('NETWORK', 'connect ' + connectionUrl(this));
                    return original.call(this);
                };
            }
        );
    }
    return hooks;
}

// OkHttp hooks
function okhttpRequestSummary(request) {
    try {
        if (request === null || request === undefined) {
            return '<null request>';
        }
        return truncate(request.method(), 24) + ' ' + truncate(request.url().toString(), 440);
    } catch (_) {
        return '<request unavailable>';
    }
}

function installOkHttpHooks() {
    let hooks = 0;
    const Builder = useClass('okhttp3.Request$Builder');
    if (Builder) {
        hooks += installExact(
            'okhttp3.Request.Builder.url(String)',
            Builder,
            'url',
            ['java.lang.String'],
            function (original) {
                return function (url) {
                    logLine('OKHTTP', 'builder url ' + quoted(url, 440));
                    return original.call(this, url);
                };
            }
        );
        hooks += installExact(
            'okhttp3.Request.Builder.url(HttpUrl)',
            Builder,
            'url',
            ['okhttp3.HttpUrl'],
            function (original) {
                return function (url) {
                    logLine('OKHTTP', 'builder url ' + quoted(url, 440));
                    return original.call(this, url);
                };
            }
        );
        hooks += installExact(
            'okhttp3.Request.Builder.method(String,RequestBody)',
            Builder,
            'method',
            ['java.lang.String', 'okhttp3.RequestBody'],
            function (original) {
                return function (method, body) {
                    logLine('OKHTTP', 'builder method ' + truncate(method, 32));
                    return original.call(this, method, body);
                };
            }
        );
        ['addHeader', 'header'].forEach(function (methodName) {
            hooks += installExact(
                'okhttp3.Request.Builder.' + methodName + '(String,String)',
                Builder,
                methodName,
                ['java.lang.String', 'java.lang.String'],
                function (original) {
                    return function (name, value) {
                        logLine(
                            'OKHTTP',
                            'header ' + truncate(name, 120) + ': ' + redactHeader(name, value)
                        );
                        return original.call(this, name, value);
                    };
                }
            );
        });
    }

    const Client = useClass('okhttp3.OkHttpClient');
    if (Client) {
        hooks += installExact(
            'okhttp3.OkHttpClient.newCall(Request)',
            Client,
            'newCall',
            ['okhttp3.Request'],
            function (original) {
                return function (request) {
                    logLine('OKHTTP', okhttpRequestSummary(request));
                    return original.call(this, request);
                };
            }
        );
    }

    // OkHttp's Call is an interface. Hook the concrete RealCall variants when
    // present; versions move this class between packages.
    [
        'okhttp3.RealCall',
        'okhttp3.internal.connection.RealCall'
    ].forEach(function (className) {
        const RealCall = useClass(className);
        if (!RealCall) {
            return;
        }
        hooks += installExact(
            className + '.execute()',
            RealCall,
            'execute',
            [],
            function (original) {
                return function () {
                    let summary = '<request unavailable>';
                    try {
                        summary = okhttpRequestSummary(this.request());
                    } catch (_) {
                        // Keep the unavailable marker.
                    }
                    logLine('OKHTTP', 'execute ' + summary);
                    return original.call(this);
                };
            }
        );
        hooks += installExact(
            className + '.enqueue(Callback)',
            RealCall,
            'enqueue',
            ['okhttp3.Callback'],
            function (original) {
                return function (callback) {
                    let summary = '<request unavailable>';
                    try {
                        summary = okhttpRequestSummary(this.request());
                    } catch (_) {
                        // Keep the unavailable marker.
                    }
                    logLine('OKHTTP', 'enqueue ' + summary);
                    return original.call(this, callback);
                };
            }
        );
    });
    return hooks;
}

// WebView hooks
function installWebViewHooks() {
    let hooks = 0;
    const WebView = useClass('android.webkit.WebView');
    if (!WebView) {
        return hooks;
    }

    hooks += installExact(
        'WebView.loadUrl(String)',
        WebView,
        'loadUrl',
        ['java.lang.String'],
        function (original) {
            return function (url) {
                logLine('WEBVIEW', 'loadUrl(' + quoted(url, 440) + ')');
                return original.call(this, url);
            };
        }
    );
    hooks += installExact(
        'WebView.loadUrl(String,Map)',
        WebView,
        'loadUrl',
        ['java.lang.String', 'java.util.Map'],
        function (original) {
            return function (url, headers) {
                let count = '?';
                try {
                    count = headers === null ? 'null' : headers.size();
                } catch (_) {
                    // Keep unknown count.
                }
                logLine('WEBVIEW', 'loadUrl(' + quoted(url, 440) + ', headerCount=' + count + ')');
                return original.call(this, url, headers);
            };
        }
    );
    hooks += installExact(
        'WebView.postUrl(String,byte[])',
        WebView,
        'postUrl',
        ['java.lang.String', '[B'],
        function (original) {
            return function (url, postData) {
                logLine(
                    'WEBVIEW',
                    'postUrl(' + quoted(url, 440) + ', dataLength=' + arrayLength(postData) + ')'
                );
                return original.call(this, url, postData);
            };
        }
    );
    hooks += installExact(
        'WebView.loadData(String,String,String)',
        WebView,
        'loadData',
        ['java.lang.String', 'java.lang.String', 'java.lang.String'],
        function (original) {
            return function (data, mimeType, encoding) {
                logLine(
                    'WEBVIEW',
                    'loadData(data=' + quoted(data, 220) + ', mimeType=' + quoted(mimeType, 100) +
                    ', encoding=' + quoted(encoding, 80) + ')'
                );
                return original.call(this, data, mimeType, encoding);
            };
        }
    );
    hooks += installExact(
        'WebView.loadDataWithBaseURL(String,String,String,String,String)',
        WebView,
        'loadDataWithBaseURL',
        [
            'java.lang.String',
            'java.lang.String',
            'java.lang.String',
            'java.lang.String',
            'java.lang.String'
        ],
        function (original) {
            return function (baseUrl, data, mimeType, encoding, historyUrl) {
                logLine(
                    'WEBVIEW',
                    'loadDataWithBaseURL(base=' + quoted(baseUrl, 300) +
                    ', data=' + quoted(data, 220) + ', mimeType=' + quoted(mimeType, 100) +
                    ', encoding=' + quoted(encoding, 80) + ', history=' + quoted(historyUrl, 300) + ')'
                );
                return original.call(this, baseUrl, data, mimeType, encoding, historyUrl);
            };
        }
    );
    hooks += installExact(
        'WebView.evaluateJavascript(String,ValueCallback)',
        WebView,
        'evaluateJavascript',
        ['java.lang.String', 'android.webkit.ValueCallback'],
        function (original) {
            return function (script, callback) {
                logLine('WEBVIEW', 'evaluateJavascript(' + quoted(script, 300) + ')');
                return original.call(this, script, callback);
            };
        }
    );
    hooks += installExact(
        'WebView.addJavascriptInterface(Object,String)',
        WebView,
        'addJavascriptInterface',
        ['java.lang.Object', 'java.lang.String'],
        function (original) {
            return function (object, name) {
                let className = '<unknown>';
                try {
                    className = truncate(object.getClass().getName(), 180);
                } catch (_) {
                    // Keep unknown class.
                }
                logLine(
                    'WEBVIEW',
                    'addJavascriptInterface(name=' + quoted(name, 160) + ', class=' + className + ')'
                );
                return original.call(this, object, name);
            };
        }
    );
    hooks += installExact(
        'WebView.setWebViewClient(WebViewClient)',
        WebView,
        'setWebViewClient',
        ['android.webkit.WebViewClient'],
        function (original) {
            return function (client) {
                let className = 'null';
                try {
                    className = client === null ? 'null' : truncate(client.getClass().getName(), 180);
                } catch (_) {
                    className = '<unknown>';
                }
                logLine('WEBVIEW', 'setWebViewClient(' + className + ')');
                return original.call(this, client);
            };
        }
    );
    return hooks;
}

// Crypto and encoding hooks
function cryptoModeName(mode) {
    switch (Number(mode)) {
        case 1: return 'ENCRYPT_MODE';
        case 2: return 'DECRYPT_MODE';
        case 3: return 'WRAP_MODE';
        case 4: return 'UNWRAP_MODE';
        default: return String(mode);
    }
}

function installAndroidBase64Hooks(Base64) {
    let hooks = 0;
    hooks += installExact(
        'android.util.Base64.encode(byte[],int)',
        Base64,
        'encode',
        ['[B', 'int'],
        function (original) {
            return function (input, flags) {
                const result = original.call(this, input, flags);
                logLine(
                    'CRYPTO',
                    'Base64.encode inputLength=' + arrayLength(input) +
                    ' flags=' + flags + ' outputLength=' + arrayLength(result)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'android.util.Base64.encode(byte[],int,int,int)',
        Base64,
        'encode',
        ['[B', 'int', 'int', 'int'],
        function (original) {
            return function (input, offset, length, flags) {
                const result = original.call(this, input, offset, length, flags);
                logLine(
                    'CRYPTO',
                    'Base64.encode inputLength=' + length + ' offset=' + offset +
                    ' flags=' + flags + ' outputLength=' + arrayLength(result)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'android.util.Base64.encodeToString(byte[],int)',
        Base64,
        'encodeToString',
        ['[B', 'int'],
        function (original) {
            return function (input, flags) {
                const result = original.call(this, input, flags);
                logLine(
                    'CRYPTO',
                    'Base64.encodeToString inputLength=' + arrayLength(input) +
                    ' flags=' + flags + ' outputLength=' + arrayLength(result)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'android.util.Base64.decode(String,int)',
        Base64,
        'decode',
        ['java.lang.String', 'int'],
        function (original) {
            return function (input, flags) {
                const result = original.call(this, input, flags);
                logLine(
                    'CRYPTO',
                    'Base64.decode stringLength=' + textLength(input) +
                    ' flags=' + flags + ' output ' + bytePreview(result, 24)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'android.util.Base64.decode(byte[],int)',
        Base64,
        'decode',
        ['[B', 'int'],
        function (original) {
            return function (input, flags) {
                const result = original.call(this, input, flags);
                logLine(
                    'CRYPTO',
                    'Base64.decode inputLength=' + arrayLength(input) +
                    ' flags=' + flags + ' output ' + bytePreview(result, 24)
                );
                return result;
            };
        }
    );
    return hooks;
}

function installJavaBase64Hooks() {
    let hooks = 0;
    const Encoder = useClass('java.util.Base64$Encoder');
    const Decoder = useClass('java.util.Base64$Decoder');
    if (Encoder) {
        hooks += installExact(
            'java.util.Base64.Encoder.encode(byte[])',
            Encoder,
            'encode',
            ['[B'],
            function (original) {
                return function (input) {
                    const result = original.call(this, input);
                    logLine(
                        'CRYPTO',
                        'Base64.Encoder.encode inputLength=' + arrayLength(input) +
                        ' outputLength=' + arrayLength(result)
                    );
                    return result;
                };
            }
        );
        hooks += installExact(
            'java.util.Base64.Encoder.encodeToString(byte[])',
            Encoder,
            'encodeToString',
            ['[B'],
            function (original) {
                return function (input) {
                    const result = original.call(this, input);
                    logLine(
                        'CRYPTO',
                        'Base64.Encoder.encodeToString inputLength=' + arrayLength(input) +
                        ' outputLength=' + arrayLength(result)
                    );
                    return result;
                };
            }
        );
    }
    if (Decoder) {
        hooks += installExact(
            'java.util.Base64.Decoder.decode(byte[])',
            Decoder,
            'decode',
            ['[B'],
            function (original) {
                return function (input) {
                    const result = original.call(this, input);
                    logLine(
                        'CRYPTO',
                        'Base64.Decoder.decode inputLength=' + arrayLength(input) +
                        ' output ' + bytePreview(result, 24)
                    );
                    return result;
                };
            }
        );
        hooks += installExact(
            'java.util.Base64.Decoder.decode(String)',
            Decoder,
            'decode',
            ['java.lang.String'],
            function (original) {
                return function (input) {
                    const result = original.call(this, input);
                    logLine(
                        'CRYPTO',
                        'Base64.Decoder.decode stringLength=' + textLength(input) +
                        ' output ' + bytePreview(result, 24)
                    );
                    return result;
                };
            }
        );
    }
    return hooks;
}

function installDigestHooks() {
    let hooks = 0;
    const Digest = useClass('java.security.MessageDigest');
    if (!Digest) {
        return hooks;
    }

    [
        ['java.lang.String'],
        ['java.lang.String', 'java.lang.String'],
        ['java.lang.String', 'java.security.Provider']
    ].forEach(function (signature) {
        hooks += installExact(
            'MessageDigest.getInstance(' + signature.join(',') + ')',
            Digest,
            'getInstance',
            signature,
            function (original) {
                if (signature.length === 1) {
                    return function (algorithm) {
                        const result = original.call(this, algorithm);
                        logLine('CRYPTO', 'MessageDigest.getInstance(' + quoted(algorithm, 100) + ')');
                        return result;
                    };
                }
                return function (algorithm, provider) {
                    const result = original.call(this, algorithm, provider);
                    logLine(
                        'CRYPTO',
                        'MessageDigest.getInstance(' + quoted(algorithm, 100) +
                        ', provider=' + truncate(provider, 100) + ')'
                    );
                    return result;
                };
            }
        );
    });

    hooks += installExact(
        'MessageDigest.update(byte[])',
        Digest,
        'update',
        ['[B'],
        function (original) {
            return function (input) {
                const self = this;
                return withGuard(
                    'crypto',
                    function () {
                        return original.call(self, input);
                    },
                    function () {
                        let algorithm = '?';
                        try { algorithm = truncate(self.getAlgorithm(), 80); } catch (_) {}
                        logLine('CRYPTO', 'MessageDigest.update algorithm=' + algorithm + ' ' + bytePreview(input, 24));
                        return original.call(self, input);
                    }
                );
            };
        }
    );
    hooks += installExact(
        'MessageDigest.update(byte[],int,int)',
        Digest,
        'update',
        ['[B', 'int', 'int'],
        function (original) {
            return function (input, offset, length) {
                logLine(
                    'CRYPTO',
                    'MessageDigest.update offset=' + offset + ' inputLength=' + length +
                    ' bufferLength=' + arrayLength(input)
                );
                return original.call(this, input, offset, length);
            };
        }
    );
    hooks += installExact(
        'MessageDigest.digest()',
        Digest,
        'digest',
        [],
        function (original) {
            return function () {
                const result = original.call(this);
                logLine('CRYPTO', 'MessageDigest.digest output ' + bytePreview(result, 24));
                return result;
            };
        }
    );
    hooks += installExact(
        'MessageDigest.digest(byte[])',
        Digest,
        'digest',
        ['[B'],
        function (original) {
            return function (input) {
                const result = original.call(this, input);
                logLine(
                    'CRYPTO',
                    'MessageDigest.digest inputLength=' + arrayLength(input) +
                    ' output ' + bytePreview(result, 24)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'MessageDigest.digest(byte[],int,int)',
        Digest,
        'digest',
        ['[B', 'int', 'int'],
        function (original) {
            return function (buffer, offset, length) {
                const written = original.call(this, buffer, offset, length);
                logLine(
                    'CRYPTO',
                    'MessageDigest.digest outputOffset=' + offset + ' capacity=' + length +
                    ' written=' + written + ' bufferLength=' + arrayLength(buffer)
                );
                return written;
            };
        }
    );
    return hooks;
}

function installMacHooks() {
    let hooks = 0;
    const Mac = useClass('javax.crypto.Mac');
    if (!Mac) {
        return hooks;
    }

    [
        ['java.lang.String'],
        ['java.lang.String', 'java.lang.String'],
        ['java.lang.String', 'java.security.Provider']
    ].forEach(function (signature) {
        hooks += installExact(
            'Mac.getInstance(' + signature.join(',') + ')',
            Mac,
            'getInstance',
            signature,
            function (original) {
                if (signature.length === 1) {
                    return function (algorithm) {
                        const result = original.call(this, algorithm);
                        logLine('CRYPTO', 'Mac.getInstance(' + quoted(algorithm, 100) + ')');
                        return result;
                    };
                }
                return function (algorithm, provider) {
                    const result = original.call(this, algorithm, provider);
                    logLine(
                        'CRYPTO',
                        'Mac.getInstance(' + quoted(algorithm, 100) +
                        ', provider=' + truncate(provider, 100) + ')'
                    );
                    return result;
                };
            }
        );
    });

    hooks += installExact(
        'Mac.init(Key)',
        Mac,
        'init',
        ['java.security.Key'],
        function (original) {
            return function (key) {
                let algorithm = '?';
                try { algorithm = truncate(key.getAlgorithm(), 100); } catch (_) {}
                logLine('CRYPTO', 'Mac.init keyAlgorithm=' + algorithm);
                return original.call(this, key);
            };
        }
    );
    hooks += installExact(
        'Mac.init(Key,AlgorithmParameterSpec)',
        Mac,
        'init',
        ['java.security.Key', 'java.security.spec.AlgorithmParameterSpec'],
        function (original) {
            return function (key, params) {
                let algorithm = '?';
                try { algorithm = truncate(key.getAlgorithm(), 100); } catch (_) {}
                logLine('CRYPTO', 'Mac.init keyAlgorithm=' + algorithm + ' parameters=present');
                return original.call(this, key, params);
            };
        }
    );
    hooks += installExact(
        'Mac.update(byte[])',
        Mac,
        'update',
        ['[B'],
        function (original) {
            return function (input) {
                logLine('CRYPTO', 'Mac.update ' + bytePreview(input, 24));
                return original.call(this, input);
            };
        }
    );
    hooks += installExact(
        'Mac.update(byte[],int,int)',
        Mac,
        'update',
        ['[B', 'int', 'int'],
        function (original) {
            return function (input, offset, length) {
                logLine(
                    'CRYPTO',
                    'Mac.update offset=' + offset + ' inputLength=' + length +
                    ' bufferLength=' + arrayLength(input)
                );
                return original.call(this, input, offset, length);
            };
        }
    );
    hooks += installExact(
        'Mac.doFinal()',
        Mac,
        'doFinal',
        [],
        function (original) {
            return function () {
                const result = original.call(this);
                logLine('CRYPTO', 'Mac.doFinal output ' + bytePreview(result, 24));
                return result;
            };
        }
    );
    hooks += installExact(
        'Mac.doFinal(byte[])',
        Mac,
        'doFinal',
        ['[B'],
        function (original) {
            return function (input) {
                const result = original.call(this, input);
                logLine(
                    'CRYPTO',
                    'Mac.doFinal inputLength=' + arrayLength(input) +
                    ' output ' + bytePreview(result, 24)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'Mac.doFinal(byte[],int)',
        Mac,
        'doFinal',
        ['[B', 'int'],
        function (original) {
            return function (output, offset) {
                const result = original.call(this, output, offset);
                logLine(
                    'CRYPTO',
                    'Mac.doFinal outputBufferLength=' + arrayLength(output) + ' offset=' + offset
                );
                return result;
            };
        }
    );
    return hooks;
}

function installCipherHooks() {
    let hooks = 0;
    const Cipher = useClass('javax.crypto.Cipher');
    if (!Cipher) {
        return hooks;
    }

    [
        ['java.lang.String'],
        ['java.lang.String', 'java.lang.String'],
        ['java.lang.String', 'java.security.Provider']
    ].forEach(function (signature) {
        hooks += installExact(
            'Cipher.getInstance(' + signature.join(',') + ')',
            Cipher,
            'getInstance',
            signature,
            function (original) {
                if (signature.length === 1) {
                    return function (transformation) {
                        const result = original.call(this, transformation);
                        logLine('CRYPTO', 'Cipher.getInstance(' + quoted(transformation, 140) + ')');
                        return result;
                    };
                }
                return function (transformation, provider) {
                    const result = original.call(this, transformation, provider);
                    logLine(
                        'CRYPTO',
                        'Cipher.getInstance(' + quoted(transformation, 140) +
                        ', provider=' + truncate(provider, 100) + ')'
                    );
                    return result;
                };
            }
        );
    });

    function installCipherInit(signature, suffix) {
        hooks += installExact(
            'Cipher.init(' + suffix + ')',
            Cipher,
            'init',
            signature,
            function (original) {
                if (signature.length === 2) {
                    return function (mode, key) {
                        let keyAlgorithm = '?';
                        try { keyAlgorithm = truncate(key.getAlgorithm(), 100); } catch (_) {}
                        logLine(
                            'CRYPTO',
                            'Cipher.init mode=' + cryptoModeName(mode) +
                            ' keyAlgorithm=' + keyAlgorithm
                        );
                        return original.call(this, mode, key);
                    };
                }
                return function (mode, key, parameters) {
                    let keyAlgorithm = '?';
                    try { keyAlgorithm = truncate(key.getAlgorithm(), 100); } catch (_) {}
                    logLine(
                        'CRYPTO',
                        'Cipher.init mode=' + cryptoModeName(mode) +
                        ' keyAlgorithm=' + keyAlgorithm + ' parameters=' +
                        (parameters === null ? 'null' : 'present')
                    );
                    return original.call(this, mode, key, parameters);
                };
            }
        );
    }

    installCipherInit(['int', 'java.security.Key'], 'int,Key');
    installCipherInit(
        ['int', 'java.security.Key', 'java.security.SecureRandom'],
        'int,Key,SecureRandom'
    );
    installCipherInit(
        ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'],
        'int,Key,AlgorithmParameterSpec'
    );
    installCipherInit(
        ['int', 'java.security.Key', 'java.security.AlgorithmParameters'],
        'int,Key,AlgorithmParameters'
    );

    hooks += installExact(
        'Cipher.update(byte[])',
        Cipher,
        'update',
        ['[B'],
        function (original) {
            return function (input) {
                const result = original.call(this, input);
                logLine(
                    'CRYPTO',
                    'Cipher.update inputLength=' + arrayLength(input) +
                    ' output ' + bytePreview(result, 24)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'Cipher.update(byte[],int,int)',
        Cipher,
        'update',
        ['[B', 'int', 'int'],
        function (original) {
            return function (input, offset, length) {
                const result = original.call(this, input, offset, length);
                logLine(
                    'CRYPTO',
                    'Cipher.update inputOffset=' + offset + ' inputLength=' + length +
                    ' output ' + bytePreview(result, 24)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'Cipher.doFinal()',
        Cipher,
        'doFinal',
        [],
        function (original) {
            return function () {
                const result = original.call(this);
                logLine('CRYPTO', 'Cipher.doFinal output ' + bytePreview(result, 24));
                return result;
            };
        }
    );
    hooks += installExact(
        'Cipher.doFinal(byte[])',
        Cipher,
        'doFinal',
        ['[B'],
        function (original) {
            return function (input) {
                const result = original.call(this, input);
                logLine(
                    'CRYPTO',
                    'Cipher.doFinal inputLength=' + arrayLength(input) +
                    ' output ' + bytePreview(result, 24)
                );
                return result;
            };
        }
    );
    hooks += installExact(
        'Cipher.doFinal(byte[],int,int)',
        Cipher,
        'doFinal',
        ['[B', 'int', 'int'],
        function (original) {
            return function (input, offset, length) {
                const result = original.call(this, input, offset, length);
                logLine(
                    'CRYPTO',
                    'Cipher.doFinal inputOffset=' + offset + ' inputLength=' + length +
                    ' output ' + bytePreview(result, 24)
                );
                return result;
            };
        }
    );
    return hooks;
}

function installKeyAndIvHooks() {
    let hooks = 0;
    const SecretKeySpec = useClass('javax.crypto.spec.SecretKeySpec');
    if (SecretKeySpec) {
        hooks += installExact(
            'SecretKeySpec.$init(byte[],String)',
            SecretKeySpec,
            '$init',
            ['[B', 'java.lang.String'],
            function (original) {
                return function (key, algorithm) {
                    const result = original.call(this, key, algorithm);
                    logLine(
                        'CRYPTO',
                        'SecretKeySpec algorithm=' + quoted(algorithm, 100) +
                        ' keyLength=' + arrayLength(key) + ' keyPreview=<redacted>'
                    );
                    return result;
                };
            }
        );
        hooks += installExact(
            'SecretKeySpec.$init(byte[],int,int,String)',
            SecretKeySpec,
            '$init',
            ['[B', 'int', 'int', 'java.lang.String'],
            function (original) {
                return function (key, offset, length, algorithm) {
                    const result = original.call(this, key, offset, length, algorithm);
                    logLine(
                        'CRYPTO',
                        'SecretKeySpec algorithm=' + quoted(algorithm, 100) +
                        ' keyLength=' + length + ' offset=' + offset +
                        ' bufferLength=' + arrayLength(key)
                    );
                    return result;
                };
            }
        );
    }

    const IvParameterSpec = useClass('javax.crypto.spec.IvParameterSpec');
    if (IvParameterSpec) {
        hooks += installExact(
            'IvParameterSpec.$init(byte[])',
            IvParameterSpec,
            '$init',
            ['[B'],
            function (original) {
                return function (iv) {
                    const result = original.call(this, iv);
                    logLine('CRYPTO', 'IvParameterSpec ' + bytePreview(iv, 16));
                    return result;
                };
            }
        );
        hooks += installExact(
            'IvParameterSpec.$init(byte[],int,int)',
            IvParameterSpec,
            '$init',
            ['[B', 'int', 'int'],
            function (original) {
                return function (iv, offset, length) {
                    const result = original.call(this, iv, offset, length);
                    logLine(
                        'CRYPTO',
                        'IvParameterSpec length=' + length + ' offset=' + offset +
                        ' bufferLength=' + arrayLength(iv)
                    );
                    return result;
                };
            }
        );
    }
    return hooks;
}

function installCryptoHooks() {
    let hooks = 0;
    const AndroidBase64 = useClass('android.util.Base64');
    if (AndroidBase64) {
        hooks += installAndroidBase64Hooks(AndroidBase64);
    }
    hooks += installJavaBase64Hooks();
    hooks += installDigestHooks();
    hooks += installMacHooks();
    hooks += installCipherHooks();
    hooks += installKeyAndIvHooks();
    return hooks;
}

// Device identifier hooks
function installIdentifierHooks() {
    let hooks = 0;
    const TelephonyManager = useClass('android.telephony.TelephonyManager');
    if (TelephonyManager) {
        [
            'getDeviceId',
            'getImei',
            'getMeid',
            'getSubscriberId',
            'getSimSerialNumber',
            'getLine1Number'
        ].forEach(function (methodName) {
            hooks += installExact(
                'TelephonyManager.' + methodName + '()',
                TelephonyManager,
                methodName,
                [],
                function (original) {
                    return function () {
                        const result = original.call(this);
                        logLine('IDENTIFIER', methodName + '() -> ' + quoted(result, 160));
                        return result;
                    };
                }
            );
        });

        ['getDeviceId', 'getImei', 'getMeid'].forEach(function (methodName) {
            hooks += installExact(
                'TelephonyManager.' + methodName + '(int)',
                TelephonyManager,
                methodName,
                ['int'],
                function (original) {
                    return function (slotIndex) {
                        const result = original.call(this, slotIndex);
                        logLine(
                            'IDENTIFIER',
                            methodName + '(slot=' + slotIndex + ') -> ' + quoted(result, 160)
                        );
                        return result;
                    };
                }
            );
        });
    }

    const WifiInfo = useClass('android.net.wifi.WifiInfo');
    if (WifiInfo) {
        hooks += installExact(
            'WifiInfo.getMacAddress()',
            WifiInfo,
            'getMacAddress',
            [],
            function (original) {
                return function () {
                    const result = original.call(this);
                    logLine('IDENTIFIER', 'WifiInfo.getMacAddress() -> ' + quoted(result, 160));
                    return result;
                };
            }
        );
    }

    const BluetoothAdapter = useClass('android.bluetooth.BluetoothAdapter');
    if (BluetoothAdapter) {
        hooks += installExact(
            'BluetoothAdapter.getAddress()',
            BluetoothAdapter,
            'getAddress',
            [],
            function (original) {
                return function () {
                    const result = original.call(this);
                    logLine('IDENTIFIER', 'BluetoothAdapter.getAddress() -> ' + quoted(result, 160));
                    return result;
                };
            }
        );
    }
    return hooks;
}

// Intent and component hooks
function intentSummary(intent) {
    if (intent === null || intent === undefined) {
        return 'intent=<null>';
    }
    let action = 'null';
    let data = 'null';
    let component = '<none>';
    try {
        action = quoted(intent.getAction(), 200);
    } catch (_) {
        action = '<unavailable>';
    }
    try {
        const uri = intent.getData();
        data = uri === null ? 'null' : quoted(uri.toString(), 360);
    } catch (_) {
        data = '<unavailable>';
    }
    try {
        const value = intent.getComponent();
        component = value === null ? '<none>' : truncate(value.flattenToShortString(), 240);
    } catch (_) {
        component = '<unavailable>';
    }
    return 'action=' + action + ' data=' + data + ' component=' + component;
}

function logIntentOperation(operation, intent, extra) {
    const summary = intentSummary(intent);
    const suffix = extra ? ' ' + extra : '';
    const key = 'intent-op|' + operation + '|' + summary + suffix;
    if (!shouldSuppress(key, 300)) {
        logLine('INTENT', operation + ' ' + summary + suffix);
    }
}

function installContextIntentHooks() {
    let hooks = 0;
    const ContextWrapper = useClass('android.content.ContextWrapper');
    if (ContextWrapper) {
        hooks += installExact(
            'ContextWrapper.startActivity(Intent)',
            ContextWrapper,
            'startActivity',
            ['android.content.Intent'],
            function (original) {
                return function (intent) {
                    logIntentOperation('startActivity', intent);
                    return original.call(this, intent);
                };
            }
        );
        hooks += installExact(
            'ContextWrapper.startActivity(Intent,Bundle)',
            ContextWrapper,
            'startActivity',
            ['android.content.Intent', 'android.os.Bundle'],
            function (original) {
                return function (intent, options) {
                    logIntentOperation('startActivity', intent, 'options=' + (options === null ? 'null' : 'present'));
                    return original.call(this, intent, options);
                };
            }
        );
        hooks += installExact(
            'ContextWrapper.startService(Intent)',
            ContextWrapper,
            'startService',
            ['android.content.Intent'],
            function (original) {
                return function (intent) {
                    logIntentOperation('startService', intent);
                    return original.call(this, intent);
                };
            }
        );
        hooks += installExact(
            'ContextWrapper.sendBroadcast(Intent)',
            ContextWrapper,
            'sendBroadcast',
            ['android.content.Intent'],
            function (original) {
                return function (intent) {
                    logIntentOperation('sendBroadcast', intent);
                    return original.call(this, intent);
                };
            }
        );
        hooks += installExact(
            'ContextWrapper.sendBroadcast(Intent,String)',
            ContextWrapper,
            'sendBroadcast',
            ['android.content.Intent', 'java.lang.String'],
            function (original) {
                return function (intent, permission) {
                    logIntentOperation(
                        'sendBroadcast',
                        intent,
                        'permission=' + quoted(permission, 180)
                    );
                    return original.call(this, intent, permission);
                };
            }
        );
        hooks += installExact(
            'ContextWrapper.bindService(Intent,ServiceConnection,int)',
            ContextWrapper,
            'bindService',
            ['android.content.Intent', 'android.content.ServiceConnection', 'int'],
            function (original) {
                return function (intent, connection, flags) {
                    logIntentOperation('bindService', intent, 'flags=' + flags);
                    return original.call(this, intent, connection, flags);
                };
            }
        );
    }

    const Activity = useClass('android.app.Activity');
    if (Activity) {
        hooks += installExact(
            'Activity.startActivity(Intent)',
            Activity,
            'startActivity',
            ['android.content.Intent'],
            function (original) {
                return function (intent) {
                    logIntentOperation('startActivity', intent);
                    return original.call(this, intent);
                };
            }
        );
        hooks += installExact(
            'Activity.startActivity(Intent,Bundle)',
            Activity,
            'startActivity',
            ['android.content.Intent', 'android.os.Bundle'],
            function (original) {
                return function (intent, options) {
                    logIntentOperation('startActivity', intent, 'options=' + (options === null ? 'null' : 'present'));
                    return original.call(this, intent, options);
                };
            }
        );
        hooks += installExact(
            'Activity.startActivityForResult(Intent,int)',
            Activity,
            'startActivityForResult',
            ['android.content.Intent', 'int'],
            function (original) {
                return function (intent, requestCode) {
                    logIntentOperation('startActivityForResult', intent, 'requestCode=' + requestCode);
                    return original.call(this, intent, requestCode);
                };
            }
        );
        hooks += installExact(
            'Activity.startActivityForResult(Intent,int,Bundle)',
            Activity,
            'startActivityForResult',
            ['android.content.Intent', 'int', 'android.os.Bundle'],
            function (original) {
                return function (intent, requestCode, options) {
                    logIntentOperation(
                        'startActivityForResult',
                        intent,
                        'requestCode=' + requestCode + ' options=' +
                        (options === null ? 'null' : 'present')
                    );
                    return original.call(this, intent, requestCode, options);
                };
            }
        );
    }
    return hooks;
}

function installIntentMutationHooks() {
    let hooks = 0;
    const Intent = useClass('android.content.Intent');
    if (Intent) {
        hooks += installExact(
            'Intent.setAction(String)',
            Intent,
            'setAction',
            ['java.lang.String'],
            function (original) {
                return function (action) {
                    const result = original.call(this, action);
                    logLine('INTENT', 'setAction(' + quoted(action, 220) + ')');
                    return result;
                };
            }
        );
        hooks += installExact(
            'Intent.setData(Uri)',
            Intent,
            'setData',
            ['android.net.Uri'],
            function (original) {
                return function (uri) {
                    const result = original.call(this, uri);
                    logLine('INTENT', 'setData(' + quoted(uri, 360) + ')');
                    return result;
                };
            }
        );
        hooks += installExact(
            'Intent.setClassName(String,String)',
            Intent,
            'setClassName',
            ['java.lang.String', 'java.lang.String'],
            function (original) {
                return function (packageName, className) {
                    const result = original.call(this, packageName, className);
                    logLine(
                        'INTENT',
                        'setClassName(package=' + quoted(packageName, 180) +
                        ', class=' + quoted(className, 220) + ')'
                    );
                    return result;
                };
            }
        );
        hooks += installExact(
            'Intent.setClassName(Context,String)',
            Intent,
            'setClassName',
            ['android.content.Context', 'java.lang.String'],
            function (original) {
                return function (context, className) {
                    const result = original.call(this, context, className);
                    logLine('INTENT', 'setClassName(context, class=' + quoted(className, 220) + ')');
                    return result;
                };
            }
        );

        const extras = [
            ['java.lang.String', function (value) { return quoted(value); }],
            ['boolean', function (value) { return String(value); }],
            ['int', function (value) { return String(value); }],
            ['long', function (value) { return String(value); }],
            ['[B', function (value) { return bytePreview(value, 24); }]
        ];
        extras.forEach(function (entry) {
            const valueType = entry[0];
            const render = entry[1];
            hooks += installExact(
                'Intent.putExtra(String,' + valueType + ')',
                Intent,
                'putExtra',
                ['java.lang.String', valueType],
                function (original) {
                    return function (key, value) {
                        const self = this;
                        return withGuard(
                            'intent',
                            function () {
                                return original.call(self, key, value);
                            },
                            function () {
                                const result = original.call(self, key, value);
                                logLine(
                                    'INTENT',
                                    'putExtra(' + quoted(key, 180) + ', ' + render(value) + ')'
                                );
                                return result;
                            }
                        );
                    };
                }
            );
        });
    }

    const Bundle = useClass('android.os.Bundle');
    if (Bundle) {
        const bundleValues = [
            ['putString', 'java.lang.String', function (value) { return quoted(value); }],
            ['putBoolean', 'boolean', function (value) { return String(value); }],
            ['putInt', 'int', function (value) { return String(value); }],
            ['putLong', 'long', function (value) { return String(value); }],
            ['putByteArray', '[B', function (value) { return bytePreview(value, 24); }]
        ];
        bundleValues.forEach(function (entry) {
            const methodName = entry[0];
            const valueType = entry[1];
            const render = entry[2];
            hooks += installExact(
                'Bundle.' + methodName + '(String,' + valueType + ')',
                Bundle,
                methodName,
                ['java.lang.String', valueType],
                function (original) {
                    return function (key, value) {
                        const self = this;
                        return withGuard(
                            'intent',
                            function () {
                                return original.call(self, key, value);
                            },
                            function () {
                                logLine(
                                    'INTENT',
                                    'Bundle.' + methodName + '(' + quoted(key, 180) +
                                    ', ' + render(value) + ')'
                                );
                                return original.call(self, key, value);
                            }
                        );
                    };
                }
            );
        });
    }

    const Uri = useClass('android.net.Uri');
    if (Uri) {
        hooks += installExact(
            'Uri.parse(String)',
            Uri,
            'parse',
            ['java.lang.String'],
            function (original) {
                return function (value) {
                    const result = original.call(this, value);
                    if (!MONITOR.guards.intent) {
                        logLine('INTENT', 'Uri.parse(' + quoted(value, 420) + ')');
                    }
                    return result;
                };
            }
        );
    }
    return hooks;
}

function installIntentHooks() {
    return installContextIntentHooks() + installIntentMutationHooks();
}

// Main entry point
setImmediate(function () {
    Java.perform(function () {
        logLine('HOOK', 'Starting Java API monitor');

        if (CONFIG.deoptimizeBootImage) {
            try {
                Java.deoptimizeBootImage();
                logLine('HOOK', 'Boot image deoptimized');
            } catch (error) {
                logLine('HOOK', 'Boot-image deoptimization unavailable: ' + conciseError(error));
                if (CONFIG.deoptimizeEverythingFallback) {
                    try {
                        Java.deoptimizeEverything();
                        logLine('HOOK', 'Full deoptimization enabled by explicit fallback option');
                    } catch (fallbackError) {
                        logLine('HOOK', 'Full deoptimization unavailable: ' + conciseError(fallbackError));
                    }
                }
            }
        }

        let installedGroups = 0;
        const totalGroups = 13;

        // Every group is isolated by runGroup's try/catch. A missing class or
        // overload therefore cannot stop later groups from being installed.
        if (runGroup('Settings', installSettingsHooks)) installedGroups++;
        if (runGroup('Debugger', installDebuggerHooks)) installedGroups++;
        if (runGroup('System properties', installSystemPropertyHooks)) installedGroups++;
        if (runGroup('Filesystem', installFilesystemHooks)) installedGroups++;
        if (runGroup('Command execution', installCommandExecutionHooks)) installedGroups++;
        if (runGroup('Package manager', installPackageManagerHooks)) installedGroups++;
        if (runGroup('SharedPreferences', installSharedPreferencesHooks)) installedGroups++;
        if (runGroup('Basic network', installNetworkHooks)) installedGroups++;
        if (runGroup('OkHttp', installOkHttpHooks)) installedGroups++;
        if (runGroup('WebView', installWebViewHooks)) installedGroups++;
        if (runGroup('Crypto and encoding', installCryptoHooks)) installedGroups++;
        if (runGroup('Device identifiers', installIdentifierHooks)) installedGroups++;
        if (runGroup('Intents and components', installIntentHooks)) installedGroups++;

        logLine(
            'HOOK',
            'Java API monitor ready: ' + installedGroups + '/' + totalGroups +
            ' groups installed (' + MONITOR.installedHooks + ' hooks)'
        );
    });
});
