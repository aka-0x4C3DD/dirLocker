import 'package:flutter/material.dart';
import '../bridge_generated.dart/mobile_api.dart';
import 'vault_dashboard_screen.dart';
import 'create_vault_screen.dart';

class VaultAccessScreen extends StatefulWidget {
  const VaultAccessScreen({super.key});

  @override
  State<VaultAccessScreen> createState() => _VaultAccessScreenState();
}

class _VaultAccessScreenState extends State<VaultAccessScreen> {
  final _pathController = TextEditingController();
  final _passwordController = TextEditingController();
  String _status = '';
  bool _isLoading = false;

  Future<void> _openVault() async {
    setState(() {
      _isLoading = true;
      _status = 'Opening vault...';
    });

    try {
      final vault = await MobileVault.newInstance(
        path: _pathController.text,
        password: _passwordController.text,
      );

      if (!mounted) return;

      setState(() {
        _status = '';
        _isLoading = false;
      });

      // Navigate to dashboard with the open vault
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (context) => VaultDashboardScreen(vault: vault),
        ),
      );
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _status = 'Error: $e';
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('DirLocker Mobile'), centerTitle: true),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Icon(
              Icons.lock_outline,
              size: 80,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(height: 32),
            TextField(
              controller: _pathController,
              decoration: const InputDecoration(
                labelText: 'Vault Path',
                prefixIcon: Icon(Icons.folder),
                hintText: '/path/to/your/vault.dat',
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _passwordController,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Password',
                prefixIcon: Icon(Icons.key),
              ),
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _isLoading ? null : _openVault,
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
                textStyle: const TextStyle(
                  fontSize: 18,
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.bold,
                ),
              ),
              child: _isLoading
                  ? SizedBox(
                      height: 24,
                      width: 24,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                    )
                  : const Text('Open Vault'),
            ),
            const SizedBox(height: 16),
            TextButton(
              onPressed: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (context) => const CreateVaultScreen(),
                  ),
                );
              },
              child: Text(
                'Create New Vault',
                style: TextStyle(
                  color: Theme.of(context).colorScheme.secondary,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            const SizedBox(height: 24),
            if (_status.isNotEmpty)
              Text(
                _status,
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: _status.startsWith('Error')
                      ? Colors.red
                      : Colors.green,
                  fontWeight: FontWeight.bold,
                ),
              ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _pathController.dispose();
    _passwordController.dispose();
    super.dispose();
  }
}
