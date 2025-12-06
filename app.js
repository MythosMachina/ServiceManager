const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const pam = require('authenticate-pam');
const crypto = require('crypto');
const path = require('path');
const util = require('util');
const { exec, execFileSync } = require('child_process');

const execAsync = util.promisify(exec);
const PORT = process.env.PORT || 3001;
const ACCESS_GROUP = process.env.ACCESS_GROUP || 'svcweb';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const CACHE_TTL = 10000;

const nativePriorities = new Set(['required', 'important', 'standard', 'essential']);
const nativePackages = new Set([
  'apparmor',
  'open-iscsi',
  'iscsi-common',
  'multipath-tools',
  'fwupd',
  'fwupd-signed',
  'pollinate',
  'cloud-init',
  'cloud-initramfs-copymods',
  'cloud-initramfs-dyn-netconf',
  'lvm2',
  'mdadm',
  'ubuntu-advantage-tools',
]);
const nativeServices = new Set([
  'apparmor.service',
  'open-iscsi.service',
  'iscsid.service',
  'multipathd.service',
  'pollinate.service',
  'fwupd.service',
  'fwupd-refresh.service',
]);
const nativePrefixes = [
  'systemd-',
  'user@',
  'getty@',
  'serial-getty@',
  'dbus-',
  'plymouth',
  'networkd',
  'cloud-',
  'snap',
  'apt-',
  'update-',
  'rescue',
  'emergency',
  'console-setup',
  'lvm2',
  'mdadm',
  'keyboard-setup',
  'kmod',
  'rsyslog',
  'cron',
  'unattended-upgrades',
  'ufw',
  'polkit',
  'multipath',
  'ModemManager',
  'udisks2',
  'thermald',
  'irqbalance',
  'secureboot',
  'ua-',
  'ubuntu-advantage',
  'man-db',
  'logrotate',
  'setvtrgb',
  'hwclock',
  'e2scrub',
  'gpu-manager',
  'console-getty',
];

let serviceCache = { at: 0, data: [] };

const app = express();
app.set('trust proxy', true);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');
  } else {
    res.header('Access-Control-Allow-Origin', '*');
  }
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  return next();
});
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  next();
});
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'", "https:"],
        "img-src": ["'self'", "data:"],
        "upgrade-insecure-requests": null,
      },
    },
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' },
  })
);

function ensureAccessGroup() {
  try {
    execFileSync('getent', ['group', ACCESS_GROUP], { stdio: 'ignore' });
  } catch {
    execFileSync('groupadd', [ACCESS_GROUP]);
  }
}

ensureAccessGroup();

function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

function safeUsername(u) {
  return /^[a-z_][a-z0-9._-]*\$?$/i.test(u);
}

async function userInGroup(username) {
  if (!safeUsername(username)) return false;
  try {
    const { stdout } = await execAsync(`id -nG ${username}`);
    return stdout.trim().split(/\s+/).includes(ACCESS_GROUP);
  } catch {
    return false;
  }
}

function pamAuthenticate(username, password) {
  return new Promise((resolve, reject) => {
    pam.authenticate(username, password, (err) => {
      if (err) return reject(err);
      resolve(true);
    });
  });
}

async function getPackageForUnit(fragmentPath) {
  if (!fragmentPath) return { packageName: null, priority: null };
  try {
    const { stdout } = await execAsync(`dpkg-query -S ${fragmentPath}`);
    const pkg = stdout.split(':')[0].trim();
    const { stdout: priorityStdout } = await execAsync(`dpkg-query -W -f='${'${Priority}'}' ${pkg}`);
    return { packageName: pkg, priority: priorityStdout.trim() || null };
  } catch {
    return { packageName: null, priority: null };
  }
}

function looksNative(name, priority, packageName) {
  if (nativePriorities.has(priority)) return true;
  if (nativeServices.has(name)) return true;
  if (packageName && nativePackages.has(packageName)) return true;
  return nativePrefixes.some((prefix) => name.startsWith(prefix));
}

async function getServiceDetails(name) {
  const { stdout } = await execAsync(
    `systemctl show ${name} -p Description -p ActiveState -p SubState -p FragmentPath -p UnitFileState --no-pager`
  );
  const lines = stdout
    .trim()
    .split('\n')
    .reduce((acc, line) => {
      const [k, ...rest] = line.split('=');
      acc[k] = rest.join('=');
      return acc;
    }, {});
  const { packageName, priority } = await getPackageForUnit(lines.FragmentPath);
  return {
    name,
    description: lines.Description || name,
    activeState: lines.ActiveState || 'unknown',
    subState: lines.SubState || 'unknown',
    unitFileState: lines.UnitFileState || 'unknown',
    fragmentPath: lines.FragmentPath || null,
    packageName,
    priority,
    native: looksNative(name, priority, packageName),
  };
}

async function listServices() {
  const now = Date.now();
  if (now - serviceCache.at < CACHE_TTL) return serviceCache.data;

  const { stdout } = await execAsync(
    'systemctl list-unit-files --type=service --all --no-legend --no-pager'
  );
  const names = stdout
    .trim()
    .split('\n')
    .map((line) => line.trim().split(/\s+/)[0])
    .filter((n) => n && !n.includes('@') && !n.startsWith('-.slice'));

  const details = [];
  for (const name of names) {
    try {
      const info = await getServiceDetails(name);
      details.push(info);
    } catch (err) {
      // skip problematic entries
      console.error(`Failed to inspect ${name}:`, err.message);
    }
  }

  const nonNative = details.filter((svc) => !svc.native);
  serviceCache = { at: now, data: nonNative };
  return nonNative;
}

async function serviceAction(name, action) {
  if (!/^[\w.\-]+\.service$/.test(name)) throw new Error('invalid service name');
  if (!['start', 'stop', 'restart'].includes(action)) throw new Error('invalid action');
  await execAsync(`systemctl ${action} ${name}`);
  serviceCache.at = 0;
}

app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing credentials' });
  if (!safeUsername(username)) return res.status(400).json({ error: 'invalid username' });
  try {
    await pamAuthenticate(username, password);
    const allowed = await userInGroup(username);
    if (!allowed) return res.status(403).json({ error: `user not in ${ACCESS_GROUP}` });
    req.session.user = username;
    return res.json({ ok: true, user: username });
  } catch (err) {
    return res.status(401).json({ error: 'authentication failed' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (req.session?.user) return res.json({ authenticated: true, user: req.session.user });
  return res.json({ authenticated: false });
});

app.get('/api/services', requireAuth, async (req, res) => {
  try {
    const services = await listServices();
    res.json({ services });
  } catch (err) {
    res.status(500).json({ error: 'failed to list services', detail: err.message });
  }
});

app.post('/api/services/:name/:action', requireAuth, async (req, res) => {
  const { name, action } = req.params;
  try {
    const services = await listServices();
    const target = services.find((s) => s.name === name);
    if (!target) return res.status(404).json({ error: 'service not managed' });
    await serviceAction(name, action);
    const refreshed = await getServiceDetails(name);
    res.json({ ok: true, service: refreshed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Service manager listening on http://localhost:${PORT}`);
  console.log(`Authorize users by adding them to the ${ACCESS_GROUP} group.`);
});
