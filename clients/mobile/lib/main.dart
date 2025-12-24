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
        useMaterial3: true,
        brightness: Brightness.dark,
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00FF41), // Matrix Green
          secondary: Color(0xFF008F11), // Darker Green
          surface: Color(0xFF0D0208), // Almost Black
          error: Color(0xFFFF0033), // Cyber Punk Red
          onPrimary: Colors.black,
          onSurface: Color(0xFFE0E0E0),
        ),
        scaffoldBackgroundColor: const Color(0xFF050505), // Deep Black
        fontFamily: 'Courier New', // Monospace fallback
        textTheme: const TextTheme(
          displayLarge: TextStyle(
            fontFamily: 'monospace',
            fontWeight: FontWeight.bold,
          ),
          displayMedium: TextStyle(
            fontFamily: 'monospace',
            fontWeight: FontWeight.bold,
          ),
          bodyLarge: TextStyle(fontFamily: 'monospace', fontSize: 16),
          bodyMedium: TextStyle(fontFamily: 'monospace', fontSize: 14),
          titleMedium: TextStyle(
            fontFamily: 'monospace',
            fontWeight: FontWeight.bold,
            color: Color(0xFF00FF41),
          ),
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: Colors.black,
          foregroundColor: Color(0xFF00FF41),
          elevation: 0,
          centerTitle: true,
          titleTextStyle: TextStyle(
            fontFamily: 'monospace',
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: Color(0xFF00FF41),
          ),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF003B00),
            foregroundColor: const Color(0xFF00FF41),
            side: const BorderSide(color: Color(0xFF00FF41), width: 1),
            shape: const RoundedRectangleBorder(
              borderRadius: BorderRadius.zero,
            ), // Brutalist sharp corners
            textStyle: const TextStyle(
              fontFamily: 'monospace',
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        inputDecorationTheme: const InputDecorationTheme(
          filled: true,
          fillColor: Color(0xFF111111),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.zero,
            borderSide: BorderSide(color: Color(0xFF333333)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.zero,
            borderSide: BorderSide(color: Color(0xFF00FF41), width: 2),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.zero,
            borderSide: BorderSide(color: Color(0xFF008F11)),
          ),
          labelStyle: TextStyle(
            color: Color(0xFF008F11),
            fontFamily: 'monospace',
          ),
          hintStyle: TextStyle(
            color: Color(0xFF444444),
            fontFamily: 'monospace',
          ),
        ),
      ),
      home: const VaultAccessScreen(),
    );
  }
}
