import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import '../bridge_generated.dart/mobile_api.dart';
import 'file_content_screen.dart';

class VaultDashboardScreen extends StatefulWidget {
  final MobileVault vault;

  const VaultDashboardScreen({super.key, required this.vault});

  @override
  State<VaultDashboardScreen> createState() => _VaultDashboardScreenState();
}

class _VaultDashboardScreenState extends State<VaultDashboardScreen> {
  List<MobileFileInfo> _allFiles = [];
  List<MobileFileInfo> _displayedFiles = [];
  bool _isLoading = true;
  String? _error;
  String _currentPath = "";

  @override
  void initState() {
    super.initState();
    _loadFiles();
  }

  Future<void> _loadFiles() async {
    try {
      final files = await widget.vault.listFiles();
      if (mounted) {
        setState(() {
          _allFiles = files;
          _isLoading = false;
          _filterFiles();
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _isLoading = false;
        });
      }
    }
  }

  void _filterFiles() {
    setState(() {
      _displayedFiles = _allFiles.where((file) {
        if (_currentPath.isEmpty) {
          // In root: show items that don't have '/' (files in root)
          // OR items that have '/' but no more after the first part if we wanted to show folders synthesized.
          // BUT: Vault returns explicit full paths. e.g. "folder", "folder/file.txt".
          // If "folder" exists, we show it. "folder/file.txt" has '/' so we hide it.
          return !file.name.contains('/');
        }
        // In directory: e.g. "folder"
        // We want "folder/file.txt".
        // startsWith("folder/") is true.
        // It is not "folder/" itself (if trailing slash) or "folder" itself.
        // And the suffix "file.txt" does not contain '/'.
        // e.g. "folder/sub/file.txt". suffix "sub/file.txt". contains '/'. Hidden.

        final prefix = "$_currentPath/";
        if (!file.name.startsWith(prefix)) return false;
        if (file.name == _currentPath || file.name == prefix) return false;

        final relativePath = file.name.substring(prefix.length);
        return !relativePath.contains('/');
      }).toList();
    });
  }

  void _enterDirectory(String path) {
    setState(() {
      _currentPath = path;
      _filterFiles();
    });
  }

  void _navigateUp() {
    if (_currentPath.isEmpty) return;

    final lastSlash = _currentPath.lastIndexOf('/');
    setState(() {
      if (lastSlash == -1) {
        _currentPath = "";
      } else {
        _currentPath = _currentPath.substring(0, lastSlash);
      }
      _filterFiles();
    });
  }

  Future<void> _addFile() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles();

      if (result != null) {
        File file = File(result.files.single.path!);
        String fileName = result.files.single.name;

        List<int> bytes = await file.readAsBytes();

        await widget.vault.addFile(fileName: fileName, data: bytes);

        if (!mounted) return;

        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('File added successfully')),
        );

        _loadFiles();
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Error adding file: $e')));
    }
  }

  Future<void> _deleteFile(MobileFileInfo file) async {
    try {
      await widget.vault.deleteFile(fileName: file.name);

      if (!mounted) return;

      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('File deleted')));
      _loadFiles();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Error deleting file: $e')));
    }
  }

  void _confirmDelete(MobileFileInfo file) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete File'),
        content: Text('Are you sure you want to delete "${file.name}"?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              _deleteFile(file);
            },
            child: const Text('Delete', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: _currentPath.isEmpty,
      onPopInvokedWithResult: (didPop, result) {
        if (didPop) return;
        _navigateUp();
      },
      child: Scaffold(
        appBar: AppBar(
          leading: _currentPath.isNotEmpty
              ? IconButton(
                  icon: const Icon(Icons.arrow_back),
                  onPressed: _navigateUp,
                )
              : null,
          title: Text(
            _currentPath.isEmpty
                ? 'Vault Content'
                : _currentPath.split('/').last,
          ),
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
          onPressed: _addFile,
          child: const Icon(Icons.add),
        ),
      ),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_error != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.error_outline, color: Colors.red, size: 48),
              const SizedBox(height: 16),
              Text(
                'Error loading files:',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Text(_error!, textAlign: TextAlign.center),
              const SizedBox(height: 16),
              ElevatedButton(onPressed: _loadFiles, child: const Text('Retry')),
            ],
          ),
        ),
      );
    }

    if (_displayedFiles.isEmpty) {
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
      itemCount: _displayedFiles.length,
      itemBuilder: (context, index) {
        final file = _displayedFiles[index];
        return ListTile(
          leading: Icon(
            file.isDir ? Icons.folder : Icons.insert_drive_file,
            color: file.isDir ? Colors.amber : Colors.blue,
          ),
          title: Text(file.name),
          subtitle: Text(file.isDir ? 'Directory' : '${file.size} bytes'),
          onTap: () {
            if (file.isDir) {
              _enterDirectory(file.name);
            } else {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) =>
                      FileContentScreen(vault: widget.vault, file: file),
                ),
              );
            }
          },
          trailing: IconButton(
            icon: const Icon(Icons.delete),
            onPressed: () => _confirmDelete(file),
          ),
        );
      },
    );
  }
}
