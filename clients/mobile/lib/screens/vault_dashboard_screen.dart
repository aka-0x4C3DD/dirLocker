import 'package:flutter/material.dart';
import '../bridge_generated.dart/mobile_api.dart';

class VaultDashboardScreen extends StatefulWidget {
  final MobileVault vault;

  const VaultDashboardScreen({super.key, required this.vault});

  @override
  State<VaultDashboardScreen> createState() => _VaultDashboardScreenState();
}

class _VaultDashboardScreenState extends State<VaultDashboardScreen> {
  List<MobileFileInfo>? _files;
  bool _isLoading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadFiles();
  }

  Future<void> _loadFiles() async {
    try {
      final files = await widget.vault.listFiles();
      setState(() {
        _files = files;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Vault Content'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () {
              setState(() {
                _isLoading = true;
                _error = null;
              });
              _loadFiles();
            },
          ),
        ],
      ),
      body: _buildBody(),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          // TODO: Implement file add
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('File addition not implemented yet')),
          );
        },
        child: const Icon(Icons.add),
      ),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, color: Colors.red, size: 48),
            const SizedBox(height: 16),
            Text(
              'Error loading files:',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            Padding(
              padding: const EdgeInsets.all(16.0),
              child: Text(_error!, textAlign: TextAlign.center),
            ),
            ElevatedButton(onPressed: _loadFiles, child: const Text('Retry')),
          ],
        ),
      );
    }

    if (_files == null || _files!.isEmpty) {
      return const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.folder_open, size: 64, color: Colors.grey),
            SizedBox(height: 16),
            Text('Vault is empty'),
          ],
        ),
      );
    }

    return ListView.builder(
      itemCount: _files!.length,
      itemBuilder: (context, index) {
        final file = _files![index];
        return ListTile(
          leading: Icon(
            file.isDir ? Icons.folder : Icons.insert_drive_file,
            color: file.isDir ? Colors.amber : Colors.blue,
          ),
          title: Text(file.name),
          subtitle: Text(file.isDir ? 'Directory' : '${file.size} bytes'),
          onTap: () {
            showDialog(
              context: context,
              builder: (context) => AlertDialog(
                title: Text(file.name),
                content: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Type: ${file.isDir ? "Directory" : "File"}'),
                    const SizedBox(height: 8),
                    Text('Size: ${file.size} bytes'),
                  ],
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('Close'),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }
}
