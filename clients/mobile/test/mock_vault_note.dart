import 'dart:typed_data';
import 'package:mobile/bridge_generated.dart/mobile_api.dart';

/// A Mock wrapper that mimics MobileVault behavior for UI testing
/// This allows us to test failure scenarios without needing the actual Rust FFI
class MockMobileVault implements MobileVault {
  final List<MobileFileInfo> _files;
  final bool shouldFailDecrypt;
  final bool shouldFailWrite;

  MockMobileVault({
    List<MobileFileInfo>? files,
    this.shouldFailDecrypt = false,
    this.shouldFailWrite = false,
  }) : _files = files ?? [];

  // Implement Required Interface (Stubbing the FFI bridge methods)
  // Note: Since MobileVault uses Rust bridge opaque pointers, we can't easily inherit from it
  // directly in a real app without the bridge.
  // However, for widget testing, we usually abstract the Vault behind a Repo/Service interface.
  // For this tasks's scope, we will structure the test to swap the implementation or
  // just verify the UI logic around these calls.

  // Since we cannot easily implement the FFI class `MobileVault` directly due to its internal structure,
  // we will interpret "Mocking" as creating a separate test helper or modifying the code to be testable.
  // BUT: The user asked for "Risk Based Testing". The best way to do this in Flutter integration tests
  // (which run on device) is to actually use the real vault or a test-specific vault path.
  //
  // IF we are running `flutter test` (unit tests on host), we CANNOT call FFI.
  // So we need an interface.
  @override
  Future<void> addFile({
    required String fileName,
    required List<int> data,
  }) async {
    if (shouldFailWrite) throw Exception("Write Failure");
    _files.add(
      MobileFileInfo(
        name: fileName,
        size: BigInt.from(data.length),
        isDir: false,
      ),
    );
  }

  @override
  Future<void> deleteFile({required String fileName}) async {
    if (shouldFailWrite) throw Exception("Delete Failure");
    _files.removeWhere((element) => element.name == fileName);
  }

  @override
  Future<List<MobileFileInfo>> listFiles() async {
    return _files;
  }

  @override
  Future<Uint8List> readFile({required String fileName}) async {
    if (shouldFailDecrypt) throw Exception("Decryption Failure");
    return Uint8List(0);
  }

  @override
  void dispose() {}

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
