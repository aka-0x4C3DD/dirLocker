import 'package:flutter/material.dart';
import 'screens/vault_access_screen.dart';

import 'package:mobile/bridge_generated.dart/frb_generated.dart';

void main() async {
  await RustLib.init();
  runApp(const DirLockerApp());
}

class DirLockerApp extends StatelessWidget {
  const DirLockerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DirLocker',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const VaultAccessScreen(),
    );
  }
}
