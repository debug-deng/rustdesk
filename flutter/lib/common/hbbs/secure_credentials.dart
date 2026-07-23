// Encrypted credential cache used to silently re-authenticate when the
// access_token expires.
//
// Storage path: instead of pulling in `flutter_secure_storage` (which had
// Windows build issues on Flutter 3.24.5 / windows-2022), we round-trip through
// the existing Rust-side `LocalConfig` via four dedicated FFI helpers in
// `src/flutter_ffi.rs` (`main_save_relogin_credentials`, etc.). On the Rust side
// the password is encrypted at rest with `sodiumoxide::crypto::secretbox`
// keyed off the machine UUID — the same scheme used by `permanent_password`.
//
// Trade-off vs. OS credential vaults: ciphertext lives in the user's
// LocalConfig file rather than wincred/Keychain. The key is still per-machine
// so it's not portable, but a determined local attacker with file access could
// in principle decrypt it. This is acceptable for the auto re-login use case
// (the access_token alone would let an attacker with file access do the same
// thing on the next launch anyway), and it avoids the plugin build issues.
import 'package:flutter_hbb/models/model.dart';

class SecureCredentials {
  static const _kUser = 'auto_relogin_user';
  static const _kPass = 'auto_relogin_pass';
  static const _kApi = 'auto_relogin_api';

  static Future<void> save(
      String user, String pass, String apiServer) async {
    await bind.mainSaveReloginCredentials(
        user: user, pass: pass, api: apiServer);
  }

  static Future<({String user, String pass, String api})?> load() async {
    final has = await bind.mainHasReloginCredentials();
    if (!has) return null;
    final creds = await bind.mainLoadReloginCredentials();
    if (creds.length < 3 ||
        creds[0].isEmpty ||
        creds[1].isEmpty ||
        creds[2].isEmpty) {
      return null;
    }
    return (user: creds[0], pass: creds[1], api: creds[2]);
  }

  static Future<bool> has() async {
    return await bind.mainHasReloginCredentials();
  }

  static Future<void> clear() async {
    await bind.mainClearReloginCredentials();
  }
}
