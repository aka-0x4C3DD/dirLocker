import 'dart:convert';
import 'package:flutter/material.dart';
import '../bridge_generated.dart/mobile_api.dart';

class FileContentScreen extends StatefulWidget {
  final MobileVault vault;
  final MobileFileInfo file;

  const FileContentScreen({super.key, required this.vault, required this.file});

  @override
  State<FileContentScreen> createState() => _FileContentScreenState();
}

class _FileContentScreenState extends State<FileContentScreen> {
  bool _isLoading = true;
  String? _content;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadFileContent();
  }

  Future<void> _loadFileContent() async {
    try {
      // Call Rust to read (and decrypt) the file
      final bytes = await widget.vault.readFile(fileName: widget.file.name);

      // For now, try to decode as UTF-8 string
      // In a real app, we'd handle binary types differently
      try {
        final text = utf8.decode(bytes);
        if (mounted) {
          setState(() {
            _content = text;
            _isLoading = false;
          });
        }
      } catch (_) {
        if (mounted) {
          setState(() {
            _content = "Binary content (size: ${bytes.length} bytes)";
            _isLoading = false;
          });
        }
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.file.name)),
      body: _buildBody(),
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
                'Error reading file:',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Text(_error!, textAlign: TextAlign.center),
            ],
          ),
        ),
      );
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: SelectableText(
        _content ?? '',
        style: const TextStyle(fontFamily: 'monospace'),
      ),
    );
  }
}
