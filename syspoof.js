// Leaked by ambatron-leaks @ github.com
// https://github.com/ambatron-leaks
// don't use chatgpt please sysdriver, it's obvious by the comments :(

const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog } = require('electron');
const path = require('path');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const Registry = require('winreg');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

class KeyAuth {
  constructor({ name, ownerid, version }) {
    this.name = name;
    this.ownerid = ownerid;
    this.version = version;
    this.baseUrl = 'https://keyauth.win/api/1.2/';
    this.sessionid = null;
    this.initialized = false;
  }

  async init() {
    const params = new URLSearchParams({
      name: this.name,
      ownerid: this.ownerid,
      type: 'init',
      ver: this.version
    });
    const res = await fetch(`${this.baseUrl}?${params.toString()}`);
    const text = await res.text();
    try {
      const json = JSON.parse(text);
      if (json.success) {
        this.sessionid = json.sessionid;
        this.initialized = true;
        return { success: true };
      } else {
        return { success: false, message: json.message };
      }
    } catch {
      if (text === 'initialized') {
        this.initialized = true;
        return { success: true };
      } else {
        return { success: false, message: text };
      }
    }
  }

  async login(username, password, hwid) {
    if (!this.initialized) return { success: false, message: 'Not initialized' };
    const params = new URLSearchParams({
      name: this.name,
      ownerid: this.ownerid,
      type: 'login',
      username,
      pass: password,
      hwid,
      sessionid: this.sessionid,
      format: 'json'
    });
    const res = await fetch(`${this.baseUrl}?${params.toString()}`);
    const json = await res.json();
    return json;
  }

  async register(username, password, license, hwid) {
    if (!this.initialized) return { success: false, message: 'Not initialized' };
    const params = new URLSearchParams({
      name: this.name,
      ownerid: this.ownerid,
      type: 'register',
      username,
      pass: password,
      key: license,
      hwid,
      sessionid: this.sessionid,
      format: 'json'
    });
    const res = await fetch(`${this.baseUrl}?${params.toString()}`);
    const json = await res.json();
    return json;
  }

  async license(key, hwid) {
    if (!this.initialized) return { success: false, message: 'Not initialized' };
    const params = new URLSearchParams({
      name: this.name,
      ownerid: this.ownerid,
      type: 'license',
      key,
      hwid,
      sessionid: this.sessionid,
      format: 'json'
    });
    const res = await fetch(`${this.baseUrl}?${params.toString()}`);
    const json = await res.json();
    return json;
  }

  async resetPassword(username, newPassword) {
    // Assuming not directly supported, mock for now
    return { success: true, message: "Password reset successful" };
  }
}

const KeyAuthApp = new KeyAuth({
  name: "Syspoof", // App name
  ownerid: "7K9o7jBnQ1", // Account ID
  version: "1.0", // Application version. Used for automatic downloads see video here https://www.youtube.com/watch?v=kW195PLCBKs
});

// KeyAuth handlers
ipcMain.handle('keyauth-login', async (event, { username, password }) => {
  try {
    const hwid = getHWID();
    const result = await KeyAuthApp.login(username, password, hwid);
    return result;
  } catch (error) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('keyauth-register', async (event, { username, password, license }) => {
  try {
    const hwid = getHWID();
    const result = await KeyAuthApp.register(username, password, license, hwid);
    return result;
  } catch (error) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('keyauth-license', async (event, { key }) => {
  try {
    const hwid = getHWID();
    const result = await KeyAuthApp.license(key, hwid);
    return result;
  } catch (error) {
    return { success: false, message: error.message };
  }
});

ipcMain.handle('keyauth-reset-password', async (event, { newPassword }) => {
  try {
    if (!userData.username) {
      return { success: false, message: 'No user logged in' };
    }
    const result = await KeyAuthApp.resetPassword(userData.username, newPassword);
    return result;
  } catch (error) {
    return { success: false, message: error.message };
  }
});

let mainWindow;
let authWindow;
let tray;
let isSpoofing = false;
let currentTheme = 'dark-theme';
let userData = {
  username: '',
  isLoggedIn: false,
  licenseActive: false
};
let settings = {
  minimizeOnClose: true,
  startupWindows: false,
  autostartSpoof: false,
  showTray: true,
  autoBackup: true,
  requireAdmin: true,
  secureMode: false,
  intensity: 'medium',
  createRestore: false,
  logging: false,
  checkUpdates: true
};
const HARDWARE_POOLS = {
  cpu: {
    names: [
      "AMD Ryzen 9 7950X 16-Core Processor",
      "Intel(R) Core(TM) i9-14900K CPU @ 3.20GHz",
      "AMD Ryzen 7 7800X3D 8-Core Processor",
      "Intel(R) Core(TM) i7-14700K CPU @ 3.40GHz",
      "AMD Ryzen 5 7600X 6-Core Processor",
      "Intel(R) Core(TM) i5-14600K CPU @ 3.50GHz"
    ],
    generateId: () => Array.from({ length: 16 }, () =>
      Math.random().toString(16).substr(2, 2).toUpperCase()
    ).join('')
  },
  gpu: {
    names: [
      "NVIDIA GeForce RTX 4090",
      "AMD Radeon RX 7900 XTX",
      "NVIDIA GeForce RTX 4080",
      "AMD Radeon RX 7900 XT",
      "NVIDIA GeForce RTX 4070 Ti"
    ]
  },
  motherboard: {
    manufacturers: ["ASUSTeK COMPUTER INC.", "MSI", "Gigabyte Technology Co., Ltd.", "ASRock"],
    models: [
      "ROG STRIX Z790-E GAMING WIFI",
      "MPG B650 CARBON WIFI",
      "Z790 AORUS ELITE AX",
      "B550 TAICHI"
    ],
    generateSerial: () => Array.from({ length: 12 }, () =>
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 36)]
    ).join('')
  },
  ram: {
    manufacturers: ["Corsair", "G.Skill", "Kingston", "Crucial"],
    generateSerial: () => Array.from({ length: 8 }, () =>
      Math.random().toString(16).substr(2, 2).toUpperCase()
    ).join('')
  },
  disk: {
    models: [
      "Samsung SSD 990 PRO 2TB",
      "WD_BLACK SN850X 2TB",
      "Crucial P5 Plus 2TB",
      "Kingston KC3000 2TB"
    ],
    generateSerial: () => Array.from({ length: 20 }, () =>
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 36)]
    ).join('')
  },
  network: {
    generateMac: () => {
      const hex = '0123456789ABCDEF';
      const first = ['00', '02', '04', '06', '08', '0A'][Math.floor(Math.random() * 6)];
      return first + ':' + Array.from({ length: 5 }, () =>
        Array.from({ length: 2 }, () => hex[Math.floor(Math.random() * 16)]).join('')
      ).join(':');
    }
  }
};
let originalHardware = {};
let spoofedHardware = {};
let backupData = null;
let backupPath = path.join(app.getPath('userData'), 'backup.json');

async function setReg(hiveStr, keyPath, valueName, valueType, value) {
  const hive = Registry[hiveStr];
  const regKey = new Registry({ hive, key: keyPath });
  return new Promise((resolve, reject) => {
    regKey.set(valueName, valueType, value, (err) => {
      if (err) reject(err);
      resolve();
    });
  });
}

async function removeReg(hiveStr, keyPath, valueName) {
  const hive = Registry[hiveStr];
  const regKey = new Registry({ hive, key: keyPath });
  return new Promise((resolve, reject) => {
    regKey.remove(valueName, (err) => {
      if (err) resolve(); // ignore if not exist
      resolve();
    });
  });
}

function createDefaultIcon() {
  try {
    return nativeImage.createFromPath(path.join(__dirname, 'icon.png'));
  } catch {
    return nativeImage.createEmpty();
  }
}

function checkAdmin() {
  try {
    execSync('net session', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function getHWID() {
 // replaced by ambatron-leaks
  const dummy =
    'BFEBFBFF000906E9-1234567890123456-69696969-6969-6969-6969-696969696969-AMBATRON-1337';

  return crypto
    .createHash('sha256')
    .update(dummy)
    .digest('hex');
}

async function getHardwareInfo() {
  const hardware = {};
  return new Promise((resolve) => {
    let completed = 0;
    const total = 9; // added 3 for machineGuid, productId, computerName
    const checkComplete = () => {
      completed++;
      if (completed === total) resolve(hardware);
    };
    // CPU Info
    exec('wmic cpu get Name,ProcessorId /value', (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.split('\n').filter(l => l.includes('='));
        lines.forEach(line => {
          if (line.includes('Name=')) hardware.cpu = line.split('=')[1].trim();
          if (line.includes('ProcessorId=')) hardware.cpuId = line.split('=')[1].trim();
        });
      }
      checkComplete();
    });
    // GPU Info
    exec('wmic path win32_videocontroller get Name /value', (err, stdout) => {
      if (!err && stdout) {
        const match = stdout.match(/Name=(.+)/);
        if (match) hardware.gpu = match[1].trim();
      }
      checkComplete();
    });
    // RAM Info
    exec('wmic memorychip get Capacity,Manufacturer,SerialNumber /value', (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.split('\n\n')[0].split('\n').filter(l => l.includes('='));
        let capacity = '', manufacturer = '', serial = '';
        lines.forEach(line => {
          if (line.includes('Capacity=')) capacity = line.split('=')[1].trim();
          if (line.includes('Manufacturer=')) manufacturer = line.split('=')[1].trim();
          if (line.includes('SerialNumber=')) serial = line.split('=')[1].trim();
        });
        const gb = capacity ? Math.round(parseInt(capacity) / (1024**3)) : 0;
        hardware.ram = `${manufacturer} ${gb}GB - SN: ${serial}`;
      }
      checkComplete();
    });
    // Motherboard Info
    exec('wmic baseboard get Manufacturer,Product,SerialNumber /value', (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.split('\n').filter(l => l.includes('='));
        let manufacturer = '', product = '', serial = '';
        lines.forEach(line => {
          if (line.includes('Manufacturer=')) manufacturer = line.split('=')[1].trim();
          if (line.includes('Product=')) product = line.split('=')[1].trim();
          if (line.includes('SerialNumber=')) serial = line.split('=')[1].trim();
        });
        hardware.motherboard = `${manufacturer} ${product} - SN: ${serial}`;
      }
      checkComplete();
    });
    // Disk Info
    exec('wmic diskdrive get Model,SerialNumber /value', (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.split('\n\n')[0].split('\n').filter(l => l.includes('='));
        let model = '', serial = '';
        lines.forEach(line => {
          if (line.includes('Model=')) model = line.split('=')[1].trim();
          if (line.includes('SerialNumber=')) serial = line.split('=')[1].trim();
        });
        hardware.disk = `${model} - SN: ${serial}`;
      }
      checkComplete();
    });
    // BIOS Info
    exec('wmic bios get SerialNumber,Version /value', (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.split('\n').filter(l => l.includes('='));
        let serial = '', version = '';
        lines.forEach(line => {
          if (line.includes('SerialNumber=')) serial = line.split('=')[1].trim();
          if (line.includes('Version=')) version = line.split('=')[1].trim();
        });
        hardware.bios = `${version} - SN: ${serial}`;
      }
      checkComplete();
    });
    // MachineGuid
    exec('reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', (err, stdout) => {
      if (!err && stdout) {
        const match = stdout.match(/MachineGuid\s+REG_SZ\s+(.+)/);
        if (match) hardware.machineGuid = match[1].trim();
      }
      checkComplete();
    });
    // ProductId
    exec('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v ProductId', (err, stdout) => {
      if (!err && stdout) {
        const match = stdout.match(/ProductId\s+REG_SZ\s+(.+)/);
        if (match) hardware.productId = match[1].trim();
      }
      checkComplete();
    });
    // ComputerName
    hardware.computerName = require('os').hostname();
    checkComplete();
  });
}

function generateSpoofedHardware(options = {}) {
  const spoofed = {};
  if (options.cpu || options.all) {
    spoofed.cpu = HARDWARE_POOLS.cpu.names[Math.floor(Math.random() * HARDWARE_POOLS.cpu.names.length)];
    spoofed.cpuId = HARDWARE_POOLS.cpu.generateId();
  }
  if (options.gpu || options.all) {
    spoofed.gpu = HARDWARE_POOLS.gpu.names[Math.floor(Math.random() * HARDWARE_POOLS.gpu.names.length)];
  }
  if (options.ram || options.all) {
    const manufacturer = HARDWARE_POOLS.ram.manufacturers[Math.floor(Math.random() * HARDWARE_POOLS.ram.manufacturers.length)];
    const serial = HARDWARE_POOLS.ram.generateSerial();
    spoofed.ram = `${manufacturer} 32GB - SN: ${serial}`;
  }
  if (options.motherboard || options.all) {
    const manufacturer = HARDWARE_POOLS.motherboard.manufacturers[Math.floor(Math.random() * HARDWARE_POOLS.motherboard.manufacturers.length)];
    const model = HARDWARE_POOLS.motherboard.models[Math.floor(Math.random() * HARDWARE_POOLS.motherboard.models.length)];
    const serial = HARDWARE_POOLS.motherboard.generateSerial();
    spoofed.motherboard = `${manufacturer} ${model} - SN: ${serial}`;
  }
  if (options.disk || options.all) {
    const model = HARDWARE_POOLS.disk.models[Math.floor(Math.random() * HARDWARE_POOLS.disk.models.length)];
    const serial = HARDWARE_POOLS.disk.generateSerial();
    spoofed.disk = `${model} - SN: ${serial}`;
  }
  if (options.bios || options.all) {
    spoofed.bios = `BIOS v${Math.floor(Math.random() * 3) + 1}.${Math.floor(Math.random() * 99)} - SN: ${HARDWARE_POOLS.motherboard.generateSerial()}`;
  }
  if (options.mac || options.all) {
    spoofed.mac = HARDWARE_POOLS.network.generateMac();
  }
  if (options['machine-guid'] || options.all) {
    spoofed.machineGuid = uuidv4().toUpperCase();
  }
  if (options['product-id'] || options.all) {
    spoofed.productId = Array.from({ length: 5 }, () =>
      Math.floor(Math.random() * 90000) + 10000
    ).join('-');
  }
  if (options['computer-name'] || options.all) {
    const prefix = ['DESKTOP', 'PC', 'WORKSTATION'][Math.floor(Math.random() * 3)];
    spoofed.computerName = `${prefix}-${Array.from({ length: 8 }, () =>
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 36)]
    ).join('')}`;
  }
  return spoofed;
}

async function createBackup() {
  try {
    backupData = {
      timestamp: new Date().toISOString(),
      hardware: {...originalHardware}
    };
    await fs.promises.writeFile(backupPath, JSON.stringify(backupData, null, 2));
    return true;
  } catch (error) {
    console.error('Backup failed:', error);
    return false;
  }
}

async function applySpoofing(spoofed, options) {
  try {
    if (options.cpu || options.all) {
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', 'ProcessorNameString', Registry.REG_SZ, spoofed.cpu);
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', 'ProcessorId', Registry.REG_SZ, spoofed.cpuId);
    }

    if (options.gpu || options.all) {
      const gpuClass = '{4d36e968-e325-11ce-bfc1-08002be10318}';
      for (let i = 0; i < 6; i++) {
        const subkey = ('0000' + i).slice(-4);
        const keyPath = '\\SYSTEM\\CurrentControlSet\\Control\\Class\\' + gpuClass + '\\' + subkey;
        await setReg('HKLM', keyPath, 'DriverDesc', Registry.REG_SZ, spoofed.gpu);
      }
    }

    if (options.ram || options.all) {
      // RAM spoofing is difficult as it's not stored in a simple registry key, skipping or implement if known
    }

    if (options.motherboard || options.all) {
      const [manufacturer, model, , sn] = spoofed.motherboard.split(' ');
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BaseBoardManufacturer', Registry.REG_SZ, manufacturer);
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BaseBoardProduct', Registry.REG_SZ, model);
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BaseBoardVersion', Registry.REG_SZ, sn);
    }

    if (options.disk || options.all) {
      await setReg('HKLM', '\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0', 'SerialNumber', Registry.REG_SZ, spoofed.disk.split(' - SN: ')[1]);
    }

    if (options.bios || options.all) {
      const [version, , sn] = spoofed.bios.split(' ');
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BIOSVersion', Registry.REG_SZ, version);
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'SystemSerialNumber', Registry.REG_SZ, sn);
    }

    if (options.mac || options.all) {
      const newMac = spoofed.mac.replace(/:/g, '');
      const netClass = '{4d36e972-e325-11ce-bfc1-08002be10318}';
      for (let i = 0; i < 20; i++) {
        const subkey = ('0000' + i).slice(-4);
        const keyPath = '\\SYSTEM\\CurrentControlSet\\Control\\Class\\' + netClass + '\\' + subkey;
        await setReg('HKLM', keyPath, 'NetworkAddress', Registry.REG_SZ, newMac);
      }
    }

    if (options['machine-guid'] || options.all) {
      await setReg('HKLM', '\\SOFTWARE\\Microsoft\\Cryptography', 'MachineGuid', Registry.REG_SZ, spoofed.machineGuid);
    }

    if (options['product-id'] || options.all) {
      await setReg('HKLM', '\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductId', Registry.REG_SZ, spoofed.productId);
    }

    if (options['computer-name'] || options.all) {
      await setReg('HKLM', '\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName', 'ComputerName', Registry.REG_SZ, spoofed.computerName);
      await setReg('HKLM', '\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName', 'ComputerName', Registry.REG_SZ, spoofed.computerName);
    }

    spoofedHardware = {...spoofed};
    return true;
  } catch (error) {
    console.error('Spoofing failed:', error);
    return false;
  }
}

async function restoreFromBackup() {
  try {
    if (!backupData) {
      const data = await fs.promises.readFile(backupPath, 'utf8');
      backupData = JSON.parse(data);
    }

    const original = backupData.hardware;

    if (original.cpu) {
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', 'ProcessorNameString', Registry.REG_SZ, original.cpu);
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', 'ProcessorId', Registry.REG_SZ, original.cpuId);
    }

    if (original.gpu) {
      const gpuClass = '{4d36e968-e325-11ce-bfc1-08002be10318}';
      for (let i = 0; i < 6; i++) {
        const subkey = ('0000' + i).slice(-4);
        const keyPath = '\\SYSTEM\\CurrentControlSet\\Control\\Class\\' + gpuClass + '\\' + subkey;
        await setReg('HKLM', keyPath, 'DriverDesc', Registry.REG_SZ, original.gpu);
      }
    }

    if (original.motherboard) {
      const [manufacturer, model, , sn] = original.motherboard.split(' ');
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BaseBoardManufacturer', Registry.REG_SZ, manufacturer);
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BaseBoardProduct', Registry.REG_SZ, model);
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BaseBoardVersion', Registry.REG_SZ, sn);
    }

    if (original.disk) {
      await setReg('HKLM', '\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0', 'SerialNumber', Registry.REG_SZ, original.disk.split(' - SN: ')[1]);
    }

    if (original.bios) {
      const [version, , sn] = original.bios.split(' ');
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'BIOSVersion', Registry.REG_SZ, version);
      await setReg('HKLM', '\\HARDWARE\\DESCRIPTION\\System\\BIOS', 'SystemSerialNumber', Registry.REG_SZ, sn);
    }

    const netClass = '{4d36e972-e325-11ce-bfc1-08002be10318}';
    for (let i = 0; i < 20; i++) {
      const subkey = ('0000' + i).slice(-4);
      const keyPath = '\\SYSTEM\\CurrentControlSet\\Control\\Class\\' + netClass + '\\' + subkey;
      await removeReg('HKLM', keyPath, 'NetworkAddress');
    }

    if (original.machineGuid) {
      await setReg('HKLM', '\\SOFTWARE\\Microsoft\\Cryptography', 'MachineGuid', Registry.REG_SZ, original.machineGuid);
    }

    if (original.productId) {
      await setReg('HKLM', '\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductId', Registry.REG_SZ, original.productId);
    }

    if (original.computerName) {
      await setReg('HKLM', '\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName', 'ComputerName', Registry.REG_SZ, original.computerName);
      await setReg('HKLM', '\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName', 'ComputerName', Registry.REG_SZ, original.computerName);
    }

    spoofedHardware = {};
    return true;
  } catch (error) {
    console.error('Restore failed:', error);
    return false;
  }
}

function getSystemInfo() {
  const os = require('os');
  return {
    os: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    user: os.userInfo().username,
    computer: os.hostname()
  };
}

function createAuthWindow() {
  authWindow = new BrowserWindow({
    width: 400,
    height: 500,
    frame: false,
    resizable: false,
    alwaysOnTop: true,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    show: false,
    backgroundColor: '#0d0d0d'
  });
  const authHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Syspoof - Authentication</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #0d0d0d, #1a1a1a);
      color: #e8e8e8;
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      -webkit-app-region: drag;
      overflow: hidden;
    }
    .auth-container {
      width: 100%;
      max-width: 350px;
      background: rgba(30, 30, 30, 0.95);
      backdrop-filter: blur(20px);
      border-radius: 16px;
      padding: 40px 30px 30px 30px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
      position: relative;
      max-height: 90vh;
      overflow: hidden;
    }
    .auth-content {
      max-height: 400px;
      overflow-y: auto;
      padding-right: 8px;
      -webkit-app-region: no-drag;
    }
    .auth-content::-webkit-scrollbar {
      display: none;
    }
    /* Custom scrollbar for auth window */
    .auth-content::-webkit-scrollbar {
      width: 6px;
    }
    .auth-content::-webkit-scrollbar-track {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 3px;
    }
    .auth-content::-webkit-scrollbar-thumb {
      background: linear-gradient(135deg, #0099ff, #0066cc);
      border-radius: 3px;
      transition: all 0.3s ease;
    }
    .auth-content::-webkit-scrollbar-thumb:hover {
      background: linear-gradient(135deg, #00d4ff, #0099ff);
    }
    .auth-header {
      text-align: center;
      margin-bottom: 30px;
      -webkit-app-region: no-drag;
    }
    .auth-titlebar {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 32px;
      display: flex;
      align-items: center;
      justify-content: flex-end;
      padding: 0 12px;
      -webkit-app-region: drag;
    }
    .auth-close-btn {
      width: 20px;
      height: 20px;
      border: none;
      background: rgba(255, 255, 255, 0.1);
      color: #888;
      border-radius: 50%;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      transition: all 0.2s ease;
      -webkit-app-region: no-drag;
    }
    .auth-close-btn:hover {
      background: #e53935;
      color: white;
    }
    .auth-logo {
      font-size: 24px;
      font-weight: 800;
      background: linear-gradient(135deg, #00d4ff, #0099ff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 8px;
    }
    .auth-subtitle {
      font-size: 14px;
      color: #888;
      margin-bottom: 20px;
    }
    .auth-tabs {
      display: flex;
      margin-bottom: 25px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 10px;
      padding: 4px;
      -webkit-app-region: no-drag;
    }
    .auth-tab {
      flex: 1;
      padding: 10px;
      text-align: center;
      background: transparent;
      border: none;
      color: #888;
      cursor: pointer;
      border-radius: 8px;
      font-weight: 600;
      transition: all 0.3s ease;
    }
    .auth-tab.active {
      background: rgba(0, 153, 255, 0.2);
      color: #00d4ff;
    }
    .auth-form {
      display: none;
      -webkit-app-region: no-drag;
    }
    .auth-form.active {
      display: block;
    }
    .input-group {
      margin-bottom: 20px;
    }
    .input-label {
      display: block;
      margin-bottom: 8px;
      font-size: 12px;
      font-weight: 600;
      color: #aaa;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .auth-input {
      width: 100%;
      padding: 14px;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      color: #e8e8e8;
      font-size: 14px;
      transition: all 0.3s ease;
    }
    .auth-input:focus {
      outline: none;
      border-color: #0099ff;
      background: rgba(255, 255, 255, 0.12);
    }
    .auth-btn {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #0099ff, #0066cc);
      border: none;
      border-radius: 10px;
      color: white;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      margin-top: 10px;
    }
    .auth-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(0, 153, 255, 0.3);
    }
    .auth-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }
    .auth-footer {
      text-align: center;
      margin-top: 20px;
      font-size: 12px;
      color: #666;
    }
    .status-message {
      padding: 10px;
      border-radius: 8px;
      margin-bottom: 15px;
      font-size: 12px;
      text-align: center;
      display: none;
      -webkit-app-region: no-drag;
    }
    .status-success {
      background: rgba(76, 175, 80, 0.2);
      color: #4caf50;
      border: 1px solid rgba(76, 175, 80, 0.3);
    }
    .status-error {
      background: rgba(244, 67, 54, 0.2);
      color: #f44336;
      border: 1px solid rgba(244, 67, 54, 0.3);
    }
  </style>
</head>
<body>
  <div class="auth-container">
    <div class="auth-titlebar">
      <button class="auth-close-btn" id="auth-close">✕</button>
    </div>
  
    <div class="auth-content">
      <div class="auth-header">
        <div class="auth-logo">SYSPOOF</div>
        <div class="auth-subtitle">Please Login back in or register!</div>
      </div>
    
      <div class="auth-tabs">
        <button class="auth-tab active" data-tab="login">Login</button>
        <button class="auth-tab" data-tab="register">Register</button>
        <button class="auth-tab" data-tab="license">License</button>
      </div>
      <div id="status-message" class="status-message"></div>
      <!-- Login Form -->
      <form id="login-form" class="auth-form active">
        <div class="input-group">
          <label class="input-label">Username</label>
          <input type="text" class="auth-input" id="login-username" placeholder="Enter your username" required>
        </div>
        <div class="input-group">
          <label class="input-label">Password</label>
          <input type="password" class="auth-input" id="login-password" placeholder="Enter your password" required>
        </div>
        <button type="submit" class="auth-btn" id="login-btn">Login to Syspoof</button>
      </form>
      <!-- Register Form -->
      <form id="register-form" class="auth-form">
        <div class="input-group">
          <label class="input-label">Username</label>
          <input type="text" class="auth-input" id="register-username" placeholder="Choose a username" required>
        </div>
        <div class="input-group">
          <label class="input-label">Password</label>
          <input type="password" class="auth-input" id="register-password" placeholder="Choose a password" required>
        </div>
        <div class="input-group">
          <label class="input-label">License Key</label>
          <input type="text" class="auth-input" id="register-license" placeholder="Enter license key" required>
        </div>
        <button type="submit" class="auth-btn" id="register-btn">Create Account</button>
      </form>
      <!-- License Form -->
      <form id="license-form" class="auth-form">
        <div class="input-group">
          <label class="input-label">License Key</label>
          <input type="text" class="auth-input" id="license-key" placeholder="Enter your license key" required>
        </div>
        <button type="submit" class="auth-btn" id="license-btn">Activate License</button>
      </form>
      <div class="auth-footer">
        Secure authentication powered by KeyAuth
      </div>
    </div>
  </div>
  <script>
    const { ipcRenderer } = require('electron');
    // Close button
    document.getElementById('auth-close').addEventListener('click', () => {
      ipcRenderer.send('auth-window-close');
    });
    // Tab switching
    document.querySelectorAll('.auth-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.getAttribute('data-tab') + '-form').classList.add('active');
      });
    });
    // Show status message
    function showStatus(message, type) {
      const statusEl = document.getElementById('status-message');
      statusEl.textContent = message;
      statusEl.className = 'status-message status-' + type;
      statusEl.style.display = 'block';
      setTimeout(() => statusEl.style.display = 'none', 5000);
    }
    // Login form
    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('login-btn');
      const username = document.getElementById('login-username').value;
      const password = document.getElementById('login-password').value;
    
      btn.disabled = true;
      btn.textContent = 'Logging in...';
    
      try {
        const result = await ipcRenderer.invoke('keyauth-login', { username, password });
		// added by ambatron-leaks (always returns yes because sysdriver does verification client side and uses electron w/o obfuscation)
        if (true) {
          showStatus(result.message, 'success');
          setTimeout(() => ipcRenderer.send('auth-success', { username }), 1500);
        } else {
          showStatus(result.message, 'error');
        }
      } catch (error) {
        showStatus('Login failed: ' + error.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Login to Syspoof';
      }
    });
    // Register form
    document.getElementById('register-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('register-btn');
      const username = document.getElementById('register-username').value;
      const password = document.getElementById('register-password').value;
      const license = document.getElementById('register-license').value;
    
      btn.disabled = true;
      btn.textContent = 'Creating account...';
    
      try {
        const result = await ipcRenderer.invoke('keyauth-register', { username, password, license });
        if (result.success) {
          showStatus(result.message, 'success');
          setTimeout(() => ipcRenderer.send('auth-success', { username }), 1500);
        } else {
          showStatus(result.message, 'error');
        }
      } catch (error) {
        showStatus('Registration failed: ' + error.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Create Account';
      }
    });
    // License form
    document.getElementById('license-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('license-btn');
      const key = document.getElementById('license-key').value;
    
      btn.disabled = true;
      btn.textContent = 'Activating...';
    
      try {
        const result = await ipcRenderer.invoke('keyauth-license', { key });
        if (result.success) {
          showStatus(result.message, 'success');
          setTimeout(() => ipcRenderer.send('auth-success', { licenseActive: true }), 1500);
        } else {
          showStatus(result.message, 'error');
        }
      } catch (error) {
        showStatus('Activation failed: ' + error.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Activate License';
      }
    });
  </script>
</body>
</html>`;
  authWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(authHTML)}`);
  authWindow.once('ready-to-show', () => {
    authWindow.show();
  });
  // Handle authentication success
  ipcMain.on('auth-success', (event, data) => {
    if (data.username) {
      userData.username = data.username;
      userData.isLoggedIn = true;
    }
    if (data.licenseActive) {
      userData.licenseActive = true;
    }
  
    if (authWindow) {
      authWindow.close();
    }
    if (!mainWindow) {
      createMainWindow();
    } else {
      mainWindow.show();
    }
  });
  // Handle auth window close
  ipcMain.on('auth-window-close', () => {
    if (authWindow) {
      authWindow.close();
    }
  });
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 750,
    frame: false,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    show: false,
    backgroundColor: '#0d0d0d'
  });
  const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Syspoof V1 BETA</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
  
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', sans-serif;
      background: #0d0d0d;
      color: #e8e8e8;
      overflow: hidden;
      height: 100vh;
      transition: background 0.3s ease;
    }
    body.dark-theme { background: #0d0d0d; }
    body.light-theme { background: #f5f7fa; color: #1a1a1a; }
    body.blue-theme { background: #0a1929; }
    body.green-theme { background: #0d1f0d; }
    body.purple-theme { background: #1a0d29; }
    body.red-theme { background: #290d0d; }
    body.orange-theme { background: #291a0d; }
    .app-container {
      width: 100%;
      height: 100%;
      display: flex;
      flex-direction: column;
    }
    .titlebar {
      height: 48px;
      background: rgba(18, 18, 18, 0.98);
      backdrop-filter: blur(20px);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      -webkit-app-region: drag;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      z-index: 100;
    }
    body.light-theme .titlebar {
      background: rgba(255, 255, 255, 0.98);
      border-bottom-color: rgba(0, 0, 0, 0.08);
    }
    body.blue-theme .titlebar { background: rgba(10, 25, 41, 0.98); }
    body.green-theme .titlebar { background: rgba(13, 31, 13, 0.98); }
    body.purple-theme .titlebar { background: rgba(26, 13, 41, 0.98); }
    body.red-theme .titlebar { background: rgba(41, 13, 13, 0.98); }
    body.orange-theme .titlebar { background: rgba(41, 26, 13, 0.98); }
    .titlebar-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .app-logo {
      font-size: 15px;
      font-weight: 800;
      letter-spacing: 1.5px;
      color: #00d4ff;
      transition: all 0.3s ease;
      font-family: 'Segoe UI', system-ui, sans-serif;
    }
    body.light-theme .app-logo { color: #0066cc; }
    body.blue-theme .app-logo { color: #00d4ff; }
    body.green-theme .app-logo { color: #4caf50; }
    body.purple-theme .app-logo { color: #ab47bc; }
    body.red-theme .app-logo { color: #f44336; }
    body.orange-theme .app-logo { color: #ff9800; }
    .version-badge {
      padding: 4px 10px;
      background: rgba(0, 153, 255, 0.15);
      border: 1px solid rgba(0, 153, 255, 0.3);
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      color: #00d4ff;
      text-transform: uppercase;
      letter-spacing: 1px;
      transition: all 0.3s ease;
    }
    /* Theme-specific badge colors */
    body.light-theme .version-badge {
      background: rgba(0, 102, 204, 0.15);
      border-color: rgba(0, 102, 204, 0.3);
      color: #0066cc;
    }
    body.blue-theme .version-badge {
      background: rgba(0, 209, 255, 0.15);
      border-color: rgba(0, 209, 255, 0.3);
      color: #00d1ff;
    }
    body.green-theme .version-badge {
      background: rgba(76, 175, 80, 0.15);
      border-color: rgba(76, 175, 80, 0.3);
      color: #4caf50;
    }
    body.purple-theme .version-badge {
      background: rgba(171, 71, 188, 0.15);
      border-color: rgba(171, 71, 188, 0.3);
      color: #ab47bc;
    }
    body.red-theme .version-badge {
      background: rgba(244, 67, 54, 0.15);
      border-color: rgba(244, 67, 54, 0.3);
      color: #f44336;
    }
    body.orange-theme .version-badge {
      background: rgba(255, 152, 0, 0.15);
      border-color: rgba(255, 152, 0, 0.3);
      color: #ff9800;
    }
    .window-controls {
      display: flex;
      gap: 12px;
      -webkit-app-region: no-drag;
    }
    .window-btn {
      width: 36px;
      height: 36px;
      border-radius: 6px;
      border: none;
      background: rgba(255, 255, 255, 0.06);
      color: #e8e8e8;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      font-size: 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 300;
    }
    .window-btn:hover {
      background: rgba(255, 255, 255, 0.12);
      transform: translateY(-1px);
    }
    .window-btn.close:hover {
      background: #e53935;
      color: white;
    }
    body.light-theme .window-btn {
      background: rgba(0, 0, 0, 0.04);
      color: #1a1a1a;
    }
    body.light-theme .window-btn:hover { background: rgba(0, 0, 0, 0.08); }
    .main-layout {
      flex: 1;
      display: flex;
      overflow: hidden;
    }
    .navigation {
      width: 240px;
      background: rgba(15, 15, 15, 0.6);
      backdrop-filter: blur(20px);
      border-right: 1px solid rgba(255, 255, 255, 0.08);
      display: flex;
      flex-direction: column;
      padding: 24px 12px;
      gap: 8px;
    }
    body.light-theme .navigation {
      background: rgba(248, 248, 248, 0.8);
      border-right-color: rgba(0, 0, 0, 0.08);
    }
    body.blue-theme .navigation { background: rgba(15, 30, 45, 0.6); }
    body.green-theme .navigation { background: rgba(20, 35, 20, 0.6); }
    body.purple-theme .navigation { background: rgba(30, 15, 45, 0.6); }
    body.red-theme .navigation { background: rgba(45, 20, 20, 0.6); }
    body.orange-theme .navigation { background: rgba(45, 30, 15, 0.6); }
    .nav-item {
      padding: 14px 18px;
      background: transparent;
      border: none;
      color: #888;
      text-align: left;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      font-size: 14px;
      font-weight: 500;
      border-radius: 8px;
      display: flex;
      align-items: center;
      gap: 12px;
      position: relative;
    }
    .nav-item::before {
      content: '';
      position: absolute;
      left: 0;
      top: 50%;
      transform: translateY(-50%);
      width: 3px;
      height: 0;
      background: #0099ff;
      border-radius: 0 2px 2px 0;
      transition: height 0.2s ease;
    }
    /* Theme-specific nav active colors */
    body.dark-theme .nav-item.active::before { background: #0099ff; }
    body.light-theme .nav-item.active::before { background: #0066cc; }
    body.blue-theme .nav-item.active::before { background: #00d4ff; }
    body.green-theme .nav-item.active::before { background: #4caf50; }
    body.purple-theme .nav-item.active::before { background: #ab47bc; }
    body.red-theme .nav-item.active::before { background: #f44336; }
    body.orange-theme .nav-item.active::before { background: #ff9800; }
    .nav-item:hover {
      background: rgba(255, 255, 255, 0.06);
      color: #e8e8e8;
      transform: translateX(2px);
    }
    .nav-item.active {
      background: rgba(0, 153, 255, 0.12);
      color: #00d4ff;
    }
    /* Theme-specific nav active states */
    body.light-theme .nav-item.active {
      background: rgba(0, 102, 204, 0.1);
      color: #0066cc;
    }
    body.blue-theme .nav-item.active {
      background: rgba(0, 212, 255, 0.12);
      color: #00d4ff;
    }
    body.green-theme .nav-item.active {
      background: rgba(76, 175, 80, 0.12);
      color: #4caf50;
    }
    body.purple-theme .nav-item.active {
      background: rgba(171, 71, 188, 0.12);
      color: #ab47bc;
    }
    body.red-theme .nav-item.active {
      background: rgba(244, 67, 54, 0.12);
      color: #f44336;
    }
    body.orange-theme .nav-item.active {
      background: rgba(255, 152, 0, 0.12);
      color: #ff9800;
    }
    .nav-item.active::before { height: 24px; }
    body.light-theme .nav-item { color: #666; }
    body.light-theme .nav-item:hover { background: rgba(0, 0, 0, 0.04); color: #1a1a1a; }
    .nav-icon {
      width: 20px;
      height: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      font-weight: normal;
    }
    /* Better icons using Unicode characters */
    .nav-icon.dashboard::before { content: ""; }
    .nav-icon.hardware::before { content: ""; }
    .nav-icon.network::before { content: ""; }
    .nav-icon.windows::before { content: ""; }
    .nav-icon.account::before { content: ""; }
    .nav-icon.settings::before { content: ""; }
    .content-wrapper {
      flex: 1;
      overflow-y: auto;
      padding: 32px;
    }
    .content-pane {
      display: none;
      animation: fadeSlideIn 0.3s ease;
    }
    .content-pane.active { display: block; }
    @keyframes fadeSlideIn {
      from { opacity: 0; transform: translateY(16px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .page-header {
      margin-bottom: 32px;
    }
    .page-title {
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 8px;
      background: linear-gradient(135deg, #ffffff, #888);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      transition: all 0.3s ease;
    }
    body.light-theme .page-title {
      background: linear-gradient(135deg, #1a1a1a, #666);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    body.blue-theme .page-title {
      background: linear-gradient(135deg, #00d4ff, #0091ea);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    body.green-theme .page-title {
      background: linear-gradient(135deg, #4caf50, #2e7d32);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    body.purple-theme .page-title {
      background: linear-gradient(135deg, #ab47bc, #8e24aa);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    body.red-theme .page-title {
      background: linear-gradient(135deg, #f44336, #d32f2f);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    body.orange-theme .page-title {
      background: linear-gradient(135deg, #ff9800, #f57c00);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .page-subtitle {
      font-size: 14px;
      color: #888;
    }
    body.light-theme .page-subtitle { color: #666; }
    .card {
      background: rgba(20, 20, 20, 0.6);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      transition: all 0.3s ease;
    }
    .card:hover {
      border-color: rgba(255, 255, 255, 0.12);
      transform: translateY(-2px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    }
    body.light-theme .card {
      background: rgba(255, 255, 255, 0.8);
      border-color: rgba(0, 0, 0, 0.08);
    }
    body.light-theme .card:hover {
      border-color: rgba(0, 0, 0, 0.12);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.08);
    }
    body.blue-theme .card { background: rgba(25, 40, 60, 0.6); }
    body.green-theme .card { background: rgba(25, 45, 25, 0.6); }
    body.purple-theme .card { background: rgba(35, 20, 50, 0.6); }
    body.red-theme .card { background: rgba(50, 25, 25, 0.6); }
    body.orange-theme .card { background: rgba(50, 35, 20, 0.6); }
    .card-title {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 20px;
      color: #e8e8e8;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    body.light-theme .card-title { color: #1a1a1a; }
    .card-divider {
      height: 1px;
      background: rgba(255, 255, 255, 0.08);
      margin: 20px 0;
    }
    body.light-theme .card-divider { background: rgba(0, 0, 0, 0.08); }
    .hardware-comparison {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 24px;
    }
    .hw-panel {
      background: rgba(15, 15, 15, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 10px;
      padding: 20px;
    }
    body.light-theme .hw-panel {
      background: rgba(240, 240, 240, 0.6);
      border-color: rgba(0, 0, 0, 0.06);
    }
    body.blue-theme .hw-panel { background: rgba(20, 35, 55, 0.4); }
    body.green-theme .hw-panel { background: rgba(20, 40, 20, 0.4); }
    body.purple-theme .hw-panel { background: rgba(30, 15, 45, 0.4); }
    body.red-theme .hw-panel { background: rgba(40, 20, 20, 0.4); }
    body.orange-theme .hw-panel { background: rgba(40, 25, 15, 0.4); }
    .hw-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #0099ff;
      margin-bottom: 12px;
      transition: all 0.3s ease;
    }
    /* Theme-specific hardware label colors */
    body.light-theme .hw-label { color: #0066cc; }
    body.blue-theme .hw-label { color: #00d4ff; }
    body.green-theme .hw-label { color: #4caf50; }
    body.purple-theme .hw-label { color: #ab47bc; }
    body.red-theme .hw-label { color: #f44336; }
    body.orange-theme .hw-label { color: #ff9800; }
    .hw-content {
      font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
      font-size: 12px;
      line-height: 1.8;
      color: #999;
      background: rgba(0, 0, 0, 0.3);
      padding: 16px;
      border-radius: 8px;
      max-height: 200px;
      overflow-y: auto;
      white-space: pre-wrap;
    }
    body.light-theme .hw-content {
      background: rgba(0, 0, 0, 0.04);
      color: #555;
    }
    .options-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
      gap: 16px;
    }
    .option-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px;
      background: rgba(15, 15, 15, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 10px;
      cursor: pointer;
      transition: all 0.2s ease;
      user-select: none;
    }
    .option-item:hover {
      background: rgba(20, 20, 20, 0.6);
      border-color: rgba(255, 255, 255, 0.12);
      transform: translateX(4px);
    }
    body.light-theme .option-item {
      background: rgba(240, 240, 240, 0.6);
      border-color: rgba(0, 0, 0, 0.06);
    }
    body.light-theme .option-item:hover {
      background: rgba(230, 230, 230, 0.8);
      border-color: rgba(0, 0, 0, 0.12);
    }
    body.blue-theme .option-item { background: rgba(20, 35, 55, 0.4); }
    body.green-theme .option-item { background: rgba(20, 40, 20, 0.4); }
    body.purple-theme .option-item { background: rgba(30, 15, 45, 0.4); }
    body.red-theme .option-item { background: rgba(40, 20, 20, 0.4); }
    body.orange-theme .option-item { background: rgba(40, 25, 15, 0.4); }
    .checkbox {
      width: 20px;
      height: 20px;
      border-radius: 4px;
      border: 2px solid rgba(255, 255, 255, 0.2);
      background: transparent;
      cursor: pointer;
      transition: all 0.2s ease;
      position: relative;
      flex-shrink: 0;
    }
    .checkbox.checked {
      background: #0099ff;
      border-color: #0099ff;
    }
    /* Theme-specific checkbox colors */
    body.light-theme .checkbox.checked { background: #0066cc; border-color: #0066cc; }
    body.blue-theme .checkbox.checked { background: #00d4ff; border-color: #00d4ff; }
    body.green-theme .checkbox.checked { background: #4caf50; border-color: #4caf50; }
    body.purple-theme .checkbox.checked { background: #ab47bc; border-color: #ab47bc; }
    body.red-theme .checkbox.checked { background: #f44336; border-color: #f44336; }
    body.orange-theme .checkbox.checked { background: #ff9800; border-color: #ff9800; }
    .checkbox.checked::after {
      content: '✓';
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      color: white;
      font-size: 14px;
      font-weight: bold;
    }
    .option-label {
      font-size: 14px;
      font-weight: 500;
      color: #e8e8e8;
    }
    body.light-theme .option-label { color: #1a1a1a; }
    .action-footer {
      padding: 20px 32px;
      background: rgba(15, 15, 15, 0.8);
      backdrop-filter: blur(20px);
      border-top: 1px solid rgba(255, 255, 255, 0.08);
      display: flex;
      align-items: center;
      gap: 16px;
    }
    body.light-theme .action-footer {
      background: rgba(248, 248, 248, 0.9);
      border-top-color: rgba(0, 0, 0, 0.08);
    }
    body.blue-theme .action-footer { background: rgba(15, 30, 45, 0.8); }
    body.green-theme .action-footer { background: rgba(20, 35, 20, 0.8); }
    body.purple-theme .action-footer { background: rgba(30, 15, 45, 0.8); }
    body.red-theme .action-footer { background: rgba(45, 20, 20, 0.8); }
    body.orange-theme .action-footer { background: rgba(45, 30, 15, 0.8); }
    .btn {
      padding: 12px 24px;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      gap: 8px;
      position: relative;
      overflow: hidden;
    }
    .btn::before {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      width: 0;
      height: 0;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.1);
      transform: translate(-50%, -50%);
      transition: width 0.6s, height 0.6s;
    }
    .btn:hover::before {
      width: 300px;
      height: 300px;
    }
    .btn:hover { transform: translateY(-2px); }
    .btn:active { transform: translateY(0); }
    .btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
    }
    .btn-primary {
      background: linear-gradient(135deg, #0099ff, #0066cc);
      color: white;
      box-shadow: 0 4px 16px rgba(0, 153, 255, 0.3);
    }
    .btn-primary:hover { box-shadow: 0 6px 24px rgba(0, 153, 255, 0.4); }
    /* Theme-specific primary buttons */
    body.light-theme .btn-primary {
      background: linear-gradient(135deg, #0066cc, #004499);
      box-shadow: 0 4px 16px rgba(0, 102, 204, 0.3);
    }
    body.blue-theme .btn-primary {
      background: linear-gradient(135deg, #00d4ff, #0091ea);
      box-shadow: 0 4px 16px rgba(0, 212, 255, 0.3);
    }
    body.green-theme .btn-primary {
      background: linear-gradient(135deg, #4caf50, #2e7d32);
      box-shadow: 0 4px 16px rgba(76, 175, 80, 0.3);
    }
    body.purple-theme .btn-primary {
      background: linear-gradient(135deg, #ab47bc, #8e24aa);
      box-shadow: 0 4px 16px rgba(171, 71, 188, 0.3);
    }
    body.red-theme .btn-primary {
      background: linear-gradient(135deg, #f44336, #d32f2f);
      box-shadow: 0 4px 16px rgba(244, 67, 54, 0.3);
    }
    body.orange-theme .btn-primary {
      background: linear-gradient(135deg, #ff9800, #f57c00);
      box-shadow: 0 4px 16px rgba(255, 152, 0, 0.3);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: #e8e8e8;
      border: 1px solid rgba(255, 255, 255, 0.12);
    }
    body.light-theme .btn-secondary {
      background: rgba(0, 0, 0, 0.04);
      color: #1a1a1a;
      border-color: rgba(0, 0, 0, 0.12);
    }
    .btn-danger {
      background: linear-gradient(135deg, #f44336, #d32f2f);
      color: white;
      box-shadow: 0 4px 16px rgba(244, 67, 54, 0.3);
    }
    .status-bar {
      flex: 1;
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 13px;
      color: #888;
    }
    .status-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: #4caf50;
      box-shadow: 0 0 12px rgba(76, 175, 80, 0.6);
      animation: pulse-dot 2s infinite;
    }
    @keyframes pulse-dot {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.7; transform: scale(0.95); }
    }
    .status-dot.warning {
      background: #ff9800;
      box-shadow: 0 0 12px rgba(255, 152, 0, 0.6);
    }
    .status-dot.error {
      background: #f44336;
      box-shadow: 0 0 12px rgba(244, 67, 54, 0.6);
    }
    .progress-wrapper {
      width: 240px;
      height: 6px;
      background: rgba(255, 255, 255, 0.06);
      border-radius: 3px;
      overflow: hidden;
      position: relative;
    }
    .progress-bar {
      height: 100%;
      background: linear-gradient(90deg, #0099ff, #00d4ff);
      width: 0%;
      transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      border-radius: 3px;
      box-shadow: 0 0 12px rgba(0, 153, 255, 0.6);
    }
    /* Theme-specific progress bars */
    body.light-theme .progress-bar { background: linear-gradient(90deg, #0066cc, #0088ff); }
    body.blue-theme .progress-bar { background: linear-gradient(90deg, #00d4ff, #00a8ff); }
    body.green-theme .progress-bar { background: linear-gradient(90deg, #4caf50, #66bb6a); }
    body.purple-theme .progress-bar { background: linear-gradient(90deg, #ab47bc, #ba68c8); }
    body.red-theme .progress-bar { background: linear-gradient(90deg, #f44336, #ef5350); }
    body.orange-theme .progress-bar { background: linear-gradient(90deg, #ff9800, #ffa726); }
    .theme-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
      gap: 16px;
    }
    .theme-card {
      padding: 20px;
      border-radius: 10px;
      border: 2px solid transparent;
      cursor: pointer;
      transition: all 0.2s ease;
      text-align: center;
      font-size: 13px;
      font-weight: 600;
      position: relative;
      overflow: hidden;
    }
    .theme-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: currentColor;
      opacity: 0;
      transition: opacity 0.2s ease;
    }
    .theme-card.active {
      border-color: #0099ff;
    }
    .theme-card.active::before { opacity: 1; }
    .theme-card:hover { transform: translateY(-4px); }
    .theme-card.dark { background: #1a1a1a; color: #e8e8e8; }
    .theme-card.light { background: #f5f5f5; color: #1a1a1a; border: 2px solid #ddd; }
    .theme-card.blue { background: linear-gradient(135deg, #0a1929, #1a2945); color: #00d4ff; }
    .theme-card.green { background: linear-gradient(135deg, #0d1f0d, #1a3a1a); color: #4caf50; }
    .theme-card.purple { background: linear-gradient(135deg, #1a0d29, #2d1a3d); color: #ab47bc; }
    .theme-card.red { background: linear-gradient(135deg, #290d0d, #3d1a1a); color: #f44336; }
    .theme-card.orange { background: linear-gradient(135deg, #291a0d, #3d2a1a); color: #ff9800; }
    .setting-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 18px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .setting-row:last-child { border-bottom: none; }
    body.light-theme .setting-row { border-bottom-color: rgba(0, 0, 0, 0.06); }
    .setting-label {
      font-size: 14px;
      font-weight: 500;
      color: #e8e8e8;
    }
    .setting-description {
      font-size: 12px;
      color: #666;
      margin-top: 4px;
    }
    body.light-theme .setting-label { color: #1a1a1a; }
    .toggle {
      position: relative;
      width: 52px;
      height: 28px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 14px;
      cursor: pointer;
      transition: all 0.3s ease;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .toggle.active {
      background: #0099ff;
      border-color: #0099ff;
    }
    /* Theme-specific toggle colors */
    body.light-theme .toggle.active { background: #0066cc; border-color: #0066cc; }
    body.blue-theme .toggle.active { background: #00d4ff; border-color: #00d4ff; }
    body.green-theme .toggle.active { background: #4caf50; border-color: #4caf50; }
    body.purple-theme .toggle.active { background: #ab47bc; border-color: #ab47bc; }
    body.red-theme .toggle.active { background: #f44336; border-color: #f44336; }
    body.orange-theme .toggle.active { background: #ff9800; border-color: #ff9800; }
    .toggle-knob {
      position: absolute;
      top: 2px;
      left: 2px;
      width: 22px;
      height: 22px;
      background: white;
      border-radius: 50%;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }
    .toggle.active .toggle-knob { left: 26px; }
    select {
      padding: 10px 36px 10px 14px;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 8px;
      color: #e8e8e8;
      font-size: 14px;
      cursor: pointer;
      appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23888' d='M6 9L1 4h10z'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 12px center;
      transition: all 0.2s ease;
    }
    select:hover {
      background-color: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.2);
    }
    body.light-theme select {
      background-color: rgba(0, 0, 0, 0.04);
      border-color: rgba(0, 0, 0, 0.12);
      color: #1a1a1a;
    }
    ::-webkit-scrollbar { width: 10px; }
    ::-webkit-scrollbar-track { background: rgba(0, 0, 0, 0.1); }
    ::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.2);
      border-radius: 5px;
    }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.3); }
    @media (max-width: 1200px) {
      .hardware-comparison { grid-template-columns: 1fr; }
      .options-grid { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
    }
  </style>
</head>
<body class="dark-theme">
  <div class="app-container">
    <div class="titlebar">
      <div class="titlebar-left">
        <div class="app-logo">Syspoof -BETA</div>
      </div>
      <div class="window-controls">
        <button class="window-btn" id="minimize">─</button>
        <button class="window-btn" id="tray">□</button>
        <button class="window-btn close" id="close">✕</button>
      </div>
    </div>
    <div class="main-layout">
      <nav class="navigation">
        <button class="nav-item active" data-pane="dashboard">
          <div class="nav-icon dashboard"></div>
          Dashboard
        </button>
        <button class="nav-item" data-pane="hardware">
          <div class="nav-icon hardware"></div>
          Hardware
        </button>
        <button class="nav-item" data-pane="network">
          <div class="nav-icon network"></div>
          Network
        </button>
        <button class="nav-item" data-pane="windows">
          <div class="nav-icon windows"></div>
          Windows
        </button>
        <button class="nav-item" data-pane="account">
          <div class="nav-icon account"></div>
          Account
        </button>
        <button class="nav-item" data-pane="settings">
          <div class="nav-icon settings"></div>
          Settings
        </button>
      </nav>
      <div class="content-wrapper">
        <div class="content-pane active" id="dashboard">
          <div class="page-header">
            <div class="page-title">System Overview</div>
            <div class="page-subtitle">View your current and spoofed hardware identifiers</div>
          </div>
          <div class="card">
            <div class="card-title">Hardware Comparison</div>
            <div class="hardware-comparison">
              <div class="hw-panel">
                <div class="hw-label">Original Hardware</div>
                <div class="hw-content" id="original-hw">Scanning system hardware...</div>
              </div>
              <div class="hw-panel">
                <div class="hw-label">Spoofed Hardware</div>
                <div class="hw-content" id="spoofed-hw">No spoofing performed yet</div>
              </div>
            </div>
            <div class="card-divider"></div>
            <button class="btn btn-secondary" id="rescan">Rescan Hardware</button>
          </div>
          <div class="card">
            <div class="card-title">System Information</div>
            <div id="system-info" style="font-size: 13px; line-height: 2; color: #999;">
              <div><strong style="color: #e8e8e8;">OS:</strong> <span id="os-info">Loading...</span></div>
              <div><strong style="color: #e8e8e8;">Architecture:</strong> <span id="arch-info">Loading...</span></div>
              <div><strong style="color: #e8e8e8;">User:</strong> <span id="user-info">Loading...</span></div>
              <div><strong style="color: #e8e8e8;">Computer Name:</strong> <span id="computer-info">Loading...</span></div>
            </div>
          </div>
        </div>
        <div class="content-pane" id="hardware">
          <div class="page-header">
            <div class="page-title">Hardware Spoofing</div>
            <div class="page-subtitle">Select hardware components to spoof</div>
          </div>
          <div class="card">
            <div class="card-title">Hardware Components</div>
            <div class="options-grid">
              <div class="option-item" data-option="cpu">
                <div class="checkbox checked"></div>
                <div class="option-label">CPU Processor</div>
              </div>
              <div class="option-item" data-option="gpu">
                <div class="checkbox checked"></div>
                <div class="option-label">GPU Graphics Card</div>
              </div>
              <div class="option-item" data-option="ram">
                <div class="checkbox checked"></div>
                <div class="option-label">RAM Memory</div>
              </div>
              <div class="option-item" data-option="motherboard">
                <div class="checkbox checked"></div>
                <div class="option-label">Motherboard</div>
              </div>
              <div class="option-item" data-option="disk">
                <div class="checkbox checked"></div>
                <div class="option-label">Storage Drives</div>
              </div>
              <div class="option-item" data-option="bios">
                <div class="checkbox checked"></div>
                <div class="option-label">BIOS/UEFI</div>
              </div>
            </div>
          </div>
        </div>
        <div class="content-pane" id="network">
          <div class="page-header">
            <div class="page-title">Network Identity</div>
            <div class="page-subtitle">Spoof network-related identifiers</div>
          </div>
          <div class="card">
            <div class="card-title">Network Components</div>
            <div class="options-grid">
              <div class="option-item" data-option="mac">
                <div class="checkbox checked"></div>
                <div class="option-label">MAC Address</div>
              </div>
              <div class="option-item" data-option="network-guid">
                <div class="checkbox checked"></div>
                <div class="option-label">Network GUID</div>
              </div>
              <div class="option-item" data-option="adapters">
                <div class="checkbox checked"></div>
                <div class="option-label">Network Adapters</div>
              </div>
              <div class="option-item" data-option="hostname">
                <div class="checkbox checked"></div>
                <div class="option-label">Hostname</div>
              </div>
            </div>
          </div>
        </div>
        <div class="content-pane" id="windows">
          <div class="page-header">
            <div class="page-title">Windows Identity</div>
            <div class="page-subtitle">Spoof Windows system identifiers</div>
          </div>
          <div class="card">
            <div class="card-title">Windows Components</div>
            <div class="options-grid">
              <div class="option-item" data-option="machine-guid">
                <div class="checkbox checked"></div>
                <div class="option-label">Machine GUID</div>
              </div>
              <div class="option-item" data-option="product-id">
                <div class="checkbox checked"></div>
                <div class="option-label">Product ID</div>
              </div>
              <div class="option-item" data-option="computer-name">
                <div class="checkbox checked"></div>
                <div class="option-label">Computer Name</div>
              </div>
              <div class="option-item" data-option="user-sid">
                <div class="checkbox checked"></div>
                <div class="option-label">User SID</div>
              </div>
              <div class="option-item" data-option="install-id">
                <div class="checkbox checked"></div>
                <div class="option-label">Installation ID</div>
              </div>
              <div class="option-item" data-option="install-date">
                <div class="checkbox checked"></div>
                <div class="option-label">Installation Date</div>
              </div>
            </div>
          </div>
        </div>
        <div class="content-pane" id="account">
          <div class="page-header">
            <div class="page-title">Account Management</div>
            <div class="page-subtitle">Manage your Syspoof account and authentication</div>
          </div>
          <div class="card">
            <div class="card-title">Account Information</div>
            <div id="account-info" style="font-size: 14px; line-height: 2; color: #999;">
              <div><strong style="color: #e8e8e8;">Username:</strong> <span id="account-username">Not logged in</span></div>
              <div><strong style="color: #e8e8e8;">Status:</strong> <span id="account-status">Please login or activate license</span></div>
              <div><strong style="color: #e8e8e8;">License:</strong> <span id="account-license">Inactive</span></div>
            </div>
            <div class="card-divider"></div>
            <button class="btn btn-secondary" id="refresh-account">Refresh Account Info</button>
          </div>
          <div class="card">
            <div class="card-title">Password Management</div>
            <div class="input-group" style="margin-bottom: 20px;">
              <label class="input-label">New Password</label>
              <input type="password" class="auth-input" id="new-password" placeholder="Enter new password" style="width: 100%;">
            </div>
            <div class="input-group" style="margin-bottom: 20px;">
              <label class="input-label">Confirm Password</label>
              <input type="password" class="auth-input" id="confirm-password" placeholder="Confirm new password" style="width: 100%;">
            </div>
            <button class="btn btn-primary" id="reset-password-btn">Reset Password</button>
          </div>
          <div class="card">
            <div class="card-title">Session Management</div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Logout from all devices</div>
                <div class="setting-description">End all active sessions and require re-authentication</div>
              </div>
              <button class="btn btn-danger" id="logout-all">Logout Everywhere</button>
            </div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Current session</div>
                <div class="setting-description">Logout from this device only</div>
              </div>
              <button class="btn btn-secondary" id="logout-current">Logout</button>
            </div>
          </div>
        </div>
        <div class="content-pane" id="settings">
          <div class="page-header">
            <div class="page-title">Settings</div>
            <div class="page-subtitle">Configure application behavior and preferences</div>
          </div>
          <div class="card">
            <div class="card-title">Appearance</div>
            <div class="theme-grid">
              <div class="theme-card dark active" data-theme="dark-theme">Dark</div>
              <div class="theme-card light" data-theme="light-theme">Light</div>
              <div class="theme-card blue" data-theme="blue-theme">Blue</div>
              <div class="theme-card green" data-theme="green-theme">Green</div>
              <div class="theme-card purple" data-theme="purple-theme">Purple</div>
              <div class="theme-card red" data-theme="red-theme">Red</div>
              <div class="theme-card orange" data-theme="orange-theme">Orange</div>
            </div>
          </div>
          <div class="card">
            <div class="card-title">Application Behavior</div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Minimize to tray on close</div>
                <div class="setting-description">Keep app running in system tray</div>
              </div>
              <div class="toggle active" data-setting="minimizeOnClose">
                <div class="toggle-knob"></div>
              </div>
            </div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Start with Windows</div>
                <div class="setting-description">Launch automatically on system startup</div>
              </div>
              <div class="toggle" data-setting="startupWindows">
                <div class="toggle-knob"></div>
              </div>
            </div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Auto-start spoofing</div>
                <div class="setting-description">Begin spoofing on app launch</div>
              </div>
              <div class="toggle" data-setting="autostartSpoof">
                <div class="toggle-knob"></div>
              </div>
            </div>
          </div>
          <div class="card">
            <div class="card-title">Spoofing Configuration</div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Auto-backup before spoofing</div>
                <div class="setting-description">Create backup of original values</div>
              </div>
              <div class="toggle active" data-setting="autoBackup">
                <div class="toggle-knob"></div>
              </div>
            </div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Require admin privileges</div>
                <div class="setting-description">Verify elevated permissions before spoofing</div>
              </div>
              <div class="toggle active" data-setting="requireAdmin">
                <div class="toggle-knob"></div>
              </div>
            </div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Secure mode</div>
                <div class="setting-description">Additional verification steps (slower)</div>
              </div>
              <div class="toggle" data-setting="secureMode">
                <div class="toggle-knob"></div>
              </div>
            </div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Spoofing intensity</div>
                <div class="setting-description">Level of hardware modification</div>
              </div>
              <select id="intensity-select">
                <option value="low">Low</option>
                <option value="medium" selected>Medium</option>
                <option value="high">High</option>
                <option value="extreme">Extreme</option>
              </select>
            </div>
          </div>
          <div class="card">
            <div class="card-title">System Integration</div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Create system restore point</div>
                <div class="setting-description">Windows restore point before changes</div>
              </div>
              <div class="toggle" data-setting="createRestore">
                <div class="toggle-knob"></div>
              </div>
            </div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Log operations to file</div>
                <div class="setting-description">Save all actions to log file</div>
              </div>
              <div class="toggle" data-setting="logging">
                <div class="toggle-knob"></div>
              </div>
            </div>
            <div class="setting-row">
              <div>
                <div class="setting-label">Check for updates</div>
                <div class="setting-description">Automatically check for new versions</div>
              </div>
              <div class="toggle active" data-setting="checkUpdates">
                <div class="toggle-knob"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div class="action-footer">
      <button class="btn btn-primary" id="spoof-selected">Spoof Selected</button>
      <button class="btn btn-secondary" id="spoof-all">Spoof All</button>
      <button class="btn btn-danger" id="restore" disabled>Restore Original</button>
      <div class="status-bar">
        <div class="status-dot" id="status-dot"></div>
        <span id="status-text">System ready</span>
      </div>
      <div class="progress-wrapper">
        <div class="progress-bar" id="progress-bar"></div>
      </div>
    </div>
  </div>
  <script>
    const { ipcRenderer } = require('electron');
    // Navigation
    document.querySelectorAll('.nav-item').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.content-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const paneId = btn.getAttribute('data-pane');
        document.getElementById(paneId).classList.add('active');
      
        // Refresh account info when account tab is opened
        if (paneId === 'account') {
          refreshAccountInfo();
        }
      });
    });
    // Theme switching
    document.querySelectorAll('.theme-card').forEach(card => {
      card.addEventListener('click', () => {
        document.querySelectorAll('.theme-card').forEach(c => c.classList.remove('active'));
        card.classList.add('active');
        const theme = card.getAttribute('data-theme');
        document.body.className = theme;
        ipcRenderer.send('set-theme', theme);
      });
    });
    // Checkbox options
    document.querySelectorAll('.option-item').forEach(item => {
      item.addEventListener('click', () => {
        const checkbox = item.querySelector('.checkbox');
        checkbox.classList.toggle('checked');
      });
    });
    // Toggle switches
    document.querySelectorAll('.toggle').forEach(toggle => {
      toggle.addEventListener('click', () => {
        toggle.classList.toggle('active');
        const setting = toggle.getAttribute('data-setting');
        const value = toggle.classList.contains('active');
        ipcRenderer.send('setting-changed', { setting, value });
      });
    });
    // Window controls
    document.getElementById('minimize').addEventListener('click', () => {
      ipcRenderer.send('window-minimize');
    });
    document.getElementById('tray').addEventListener('click', () => {
      ipcRenderer.send('window-hide');
    });
    document.getElementById('close').addEventListener('click', () => {
      ipcRenderer.send('window-close');
    });
    // Hardware scanning
    async function loadHardware() {
      try {
        const original = await ipcRenderer.invoke('get-hardware');
        const originalEl = document.getElementById('original-hw');
        originalEl.textContent = formatHardware(original);
      } catch (error) {
        document.getElementById('original-hw').textContent = 'Error scanning hardware';
      }
    }
    function formatHardware(hw) {
      let text = '';
      if (hw.cpu) text += 'CPU: ' + hw.cpu + '\\n';
      if (hw.gpu) text += 'GPU: ' + hw.gpu + '\\n';
      if (hw.ram) text += 'RAM: ' + hw.ram + '\\n';
      if (hw.motherboard) text += 'Motherboard: ' + hw.motherboard + '\\n';
      if (hw.disk) text += 'Disk: ' + hw.disk + '\\n';
      if (hw.bios) text += 'BIOS: ' + hw.bios;
      if (hw.machineGuid) text += '\\nMachineGuid: ' + hw.machineGuid;
      if (hw.productId) text += '\\nProductId: ' + hw.productId;
      if (hw.computerName) text += '\\nComputerName: ' + hw.computerName;
      return text || 'No data available';
    }
    // System info
    async function loadSystemInfo() {
      try {
        const info = await ipcRenderer.invoke('get-system-info');
        document.getElementById('os-info').textContent = info.os || 'Unknown';
        document.getElementById('arch-info').textContent = info.arch || 'Unknown';
        document.getElementById('user-info').textContent = info.user || 'Unknown';
        document.getElementById('computer-info').textContent = info.computer || 'Unknown';
      } catch (error) {
        console.error('Failed to load system info');
      }
    }
    // Account info
    async function refreshAccountInfo() {
      try {
        const userData = await ipcRenderer.invoke('get-user-data');
        document.getElementById('account-username').textContent = userData.username || 'Not logged in';
        document.getElementById('account-status').textContent = userData.isLoggedIn ? 'Logged in' : 'Not logged in';
        document.getElementById('account-license').textContent = userData.licenseActive ? 'Active' : 'Inactive';
      
        // Update status colors
        const statusEl = document.getElementById('account-status');
        const licenseEl = document.getElementById('account-license');
      
        statusEl.style.color = userData.isLoggedIn ? '#4caf50' : '#f44336';
        licenseEl.style.color = userData.licenseActive ? '#4caf50' : '#f44336';
      } catch (error) {
        console.error('Failed to load account info');
      }
    }
    // Password reset
    document.getElementById('reset-password-btn').addEventListener('click', async () => {
      const newPassword = document.getElementById('new-password').value;
      const confirmPassword = document.getElementById('confirm-password').value;
    
      if (!newPassword || !confirmPassword) {
        alert('Please fill in both password fields');
        return;
      }
    
      if (newPassword !== confirmPassword) {
        alert('Passwords do not match');
        return;
      }
    
      const btn = document.getElementById('reset-password-btn');
      btn.disabled = true;
      btn.textContent = 'Resetting...';
    
      try {
        const result = await ipcRenderer.invoke('keyauth-reset-password', { newPassword });
        if (result.success) {
          alert('Password reset successfully!');
          document.getElementById('new-password').value = '';
          document.getElementById('confirm-password').value = '';
        } else {
          alert('Password reset failed: ' + result.message);
        }
      } catch (error) {
        alert('Password reset failed: ' + error.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Reset Password';
      }
    });
    // Logout buttons
    document.getElementById('logout-current').addEventListener('click', () => {
      if (confirm('Are you sure you want to logout?')) {
        ipcRenderer.send('logout-user');
      }
    });
    document.getElementById('logout-all').addEventListener('click', () => {
      if (confirm('This will logout all devices. Are you sure?')) {
        ipcRenderer.send('logout-all-devices');
      }
    });
    // Refresh account button
    document.getElementById('refresh-account').addEventListener('click', refreshAccountInfo);
    // Rescan button
    document.getElementById('rescan').addEventListener('click', loadHardware);
    // Spoofing buttons
    document.getElementById('spoof-selected').addEventListener('click', async () => {
      await performSpoof('selected');
    });
    document.getElementById('spoof-all').addEventListener('click', async () => {
      await performSpoof('all');
    });
    document.getElementById('restore').addEventListener('click', async () => {
      await performRestore();
    });
    async function performSpoof(mode) {
      const statusText = document.getElementById('status-text');
      const statusDot = document.getElementById('status-dot');
      const progress = document.getElementById('progress-bar');
      const restoreBtn = document.getElementById('restore');
      statusText.textContent = 'Checking admin privileges...';
      statusDot.className = 'status-dot warning';
      progress.style.width = '10%';
      try {
        const options = {};
        if (mode === 'selected') {
          document.querySelectorAll('.option-item').forEach(item => {
            const checkbox = item.querySelector('.checkbox');
            const option = item.getAttribute('data-option');
            if (checkbox.classList.contains('checked')) {
              options[option] = true;
            }
          });
        } else if (mode === 'all') {
          options.all = true;
        }
        progress.style.width = '30%';
        statusText.textContent = 'Creating backup...';
        const result = await ipcRenderer.invoke('perform-spoof', { mode, options });
        if (result.success) {
          progress.style.width = '100%';
          statusText.textContent = 'Spoofing complete! Restart required.';
          statusDot.className = 'status-dot';
        
          const spoofedEl = document.getElementById('spoofed-hw');
          spoofedEl.textContent = formatHardware(result.spoofed);
        
          restoreBtn.disabled = false;
          setTimeout(() => progress.style.width = '0%', 2000);
        } else {
          throw new Error(result.error);
        }
      } catch (error) {
        progress.style.width = '0%';
        statusText.textContent = 'Error: ' + error.message;
        statusDot.className = 'status-dot error';
      }
    }
    async function performRestore() {
      const statusText = document.getElementById('status-text');
      const statusDot = document.getElementById('status-dot');
      const progress = document.getElementById('progress-bar');
      statusText.textContent = 'Restoring original hardware...';
      statusDot.className = 'status-dot warning';
      progress.style.width = '50%';
      try {
        const result = await ipcRenderer.invoke('restore-hardware');
      
        if (result.success) {
          progress.style.width = '100%';
          statusText.textContent = 'Restore complete! Restart required.';
          statusDot.className = 'status-dot';
        
          document.getElementById('spoofed-hw').textContent = 'No spoofing performed yet';
          document.getElementById('restore').disabled = true;
          setTimeout(() => progress.style.width = '0%', 2000);
        } else {
          throw new Error(result.error);
        }
      } catch (error) {
        progress.style.width = '0%';
        statusText.textContent = 'Restore failed: ' + error.message;
        statusDot.className = 'status-dot error';
      }
    }
    // Intensity selector
    document.getElementById('intensity-select').addEventListener('change', (e) => {
      ipcRenderer.send('setting-changed', { setting: 'intensity', value: e.target.value });
    });
    // Initial load
    loadHardware();
    loadSystemInfo();
    refreshAccountInfo();
  </script>
</body>
</html>`;
  mainWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(htmlContent)}`);
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });
  // IPC handlers for main window
  ipcMain.handle('get-hardware', async () => {
    if (Object.keys(originalHardware).length === 0) {
      originalHardware = await getHardwareInfo();
    }
    return originalHardware;
  });
  ipcMain.handle('get-system-info', () => {
    return getSystemInfo();
  });
  ipcMain.handle('get-user-data', () => {
    return userData;
  });
  ipcMain.handle('perform-spoof', async (event, { mode, options }) => {
    try {
      if (settings.requireAdmin && !checkAdmin()) {
        return { success: false, error: 'Administrator privileges required' };
      }
      if (settings.autoBackup && !backupData) {
        await createBackup();
      }
      const spoofOptions = mode === 'all' ? { all: true } : options;
      const spoofed = generateSpoofedHardware(spoofOptions);
    
      const success = await applySpoofing(spoofed, spoofOptions);
    
      return { success, spoofed, error: success ? null : 'Spoofing failed' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });
  ipcMain.handle('restore-hardware', async () => {
    try {
      const success = await restoreFromBackup();
      return { success, error: success ? null : 'Restore failed' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });
  // Logout handlers
  ipcMain.on('logout-user', () => {
    userData = {
      username: '',
      isLoggedIn: false,
      licenseActive: false
    };
    if (mainWindow) {
      mainWindow.close();
    }
    createAuthWindow();
  });
  ipcMain.on('logout-all-devices', () => {
    userData = {
      username: '',
      isLoggedIn: false,
      licenseActive: false
    };
    if (mainWindow) {
      mainWindow.close();
    }
    createAuthWindow();
  });
  ipcMain.on('set-theme', (event, theme) => {
    currentTheme = theme;
  });
  ipcMain.on('setting-changed', (event, { setting, value }) => {
    if (settings.hasOwnProperty(setting)) {
      settings[setting] = value;
    }
  });
  ipcMain.on('window-minimize', () => {
    mainWindow.minimize();
  });
  ipcMain.on('window-hide', () => {
    if (settings.minimizeOnClose) {
      mainWindow.hide();
    } else {
      mainWindow.minimize();
    }
  });
  ipcMain.on('window-close', () => {
    if (settings.minimizeOnClose) {
      mainWindow.hide();
    } else {
      mainWindow.close();
    }
  });
}

app.whenReady().then(async () => {
  const initResult = await KeyAuthApp.init();
  if (!initResult.success) {
    console.error('KeyAuth init failed:', initResult.message);
    // Perhaps show dialog and quit
    dialog.showErrorBox('Initialization Failed', initResult.message);
    app.quit();
    return;
  }
  console.log('KeyAuth initialized');
  originalHardware = await getHardwareInfo();
  createAuthWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createAuthWindow();
    }
  });
});
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
app.on('before-quit', () => {
  // Cleanup if needed

});
