// Secure storage of username/password for auto re-login when access_token
// expires. Backed by flutter_secure_storage -> platform credential vault
// (Windows wincred / macOS Keychain / Linux libsecret).
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureCredentials {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  static const _kUser = 'auto_relogin_user';
  static const _kPass = 'auto_relogin_pass';
  static const _kApi = 'auto_relogin_api';

  static Future<void> save(
      String user, String pass, String apiServer) async {
    await _storage.write(key: _kUser, value: user);
    await _storage.write(key: _kPass, value: pass);
    await _storage.write(key: _kApi, value: apiServer);
  }

  static Future<({String user, String pass, String api})?> load() async {
    final u = await _storage.read(key: _kUser);
    final p = await _storage.read(key: _kPass);
    final a = await _storage.read(key: _kApi);
    if (u == null || p == null || a == null) return null;
    return (user: u, pass: p, api: a);
  }

  static Future<bool> has() async {
    final u = await _storage.read(key: _kUser);
    return u != null;
  }

  static Future<void> clear() async {
    await _storage.delete(key: _kUser);
    await _storage.delete(key: _kPass);
    await _storage.delete(key: _kApi);
  }
}
