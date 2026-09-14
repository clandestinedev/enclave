# Enclave Mobile

Flutter app targeting Android + iOS. This is a Phase 0 skeleton only.

The Flutter/Dart toolchain is not installed on the dev machine yet. Once it is (via FVM),
run `flutter create .` inside this directory to scaffold the `android/`, `ios/`, and
platform-integration directories, then resume with the crypto core (`lib/core`) and
feature modules.

Planned layout (see ADR 0001):

```
lib/
  core/           crypto, keys, recovery (libsodium)
  data/           client repositories + API client
  features/       home / memories / drops / streak / us
  design_system/  tokens + reusable components
```
