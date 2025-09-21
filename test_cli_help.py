#!/usr/bin/env python3
"""
Test script to verify all CLI commands and subcommands have proper help documentation.
This tests requirement 11.1 - comprehensive CLI tools.
"""

import subprocess
import sys
import os

def run_command(cmd):
    """Run a command and return stdout, stderr, and return code."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1

def test_command_help(cmd_path, command_args, expected_content=None):
    """Test that a command shows help and contains expected content."""
    full_cmd = f"{cmd_path} {command_args} --help"
    stdout, stderr, returncode = run_command(full_cmd)
    
    # Help commands should return 0
    if returncode != 0:
        print(f"❌ FAIL: {full_cmd} returned {returncode}")
        if stderr:
            print(f"   Error: {stderr.strip()}")
        return False
    
    # Should contain basic help structure
    output = stdout + stderr
    if "Usage:" not in output:
        print(f"❌ FAIL: {full_cmd} missing 'Usage:' section")
        return False
    
    if "Flags:" not in output and "Available Commands:" not in output:
        print(f"❌ FAIL: {full_cmd} missing 'Flags:' or 'Available Commands:' section")
        return False
    
    # Check for expected content if provided
    if expected_content:
        for content in expected_content:
            if content not in output:
                print(f"❌ FAIL: {full_cmd} missing expected content: '{content}'")
                return False
    
    print(f"✅ PASS: {full_cmd}")
    return True

def main():
    """Main test function."""
    cli_path = "dirlocker-cli.exe"
    
    # Check if CLI binary exists
    if not os.path.exists(cli_path):
        print(f"❌ CLI binary not found: {cli_path}")
        print("Run: go build -o dirlocker-cli.exe ./cmd/cli")
        return 1
    
    print("Testing CLI Help Documentation")
    print("=" * 50)
    
    all_passed = True
    
    # Test main help
    if not test_command_help(cli_path, "", ["dirLocker is a cross-platform", "Available Commands:"]):
        all_passed = False
    
    # Test version
    stdout, stderr, returncode = run_command(f"{cli_path} --version")
    if returncode == 0 and ("version" in stdout.lower() or "version" in stderr.lower()):
        print(f"✅ PASS: {cli_path} --version")
    else:
        print(f"❌ FAIL: {cli_path} --version")
        all_passed = False
    
    # Test main commands
    main_commands = [
        ("create", ["Create a new encrypted vault", "--cipher", "--memory", "--operations"]),
        ("open", ["Open an", "encrypted vault"]),
        ("close", ["Close an open vault"]),
        ("list", ["List", "open vaults"]),
        ("info", ["information about a vault"]),
        ("password", ["password"]),
        ("recovery", ["recovery keys"]),
        ("extract", ["Extract", "files", "vault", "--output", "--all"]),
        ("push", ["Add files", "vault", "--recursive"]),
        ("config", ["configuration"]),
    ]
    
    for cmd, expected in main_commands:
        if not test_command_help(cli_path, cmd, expected):
            all_passed = False
    
    # Test share subcommands
    share_commands = [
        ("share", ["Manage secure sharing", "Available Commands:"]),
        ("share keygen", ["Generate", "X25519 key pair"]),
        ("share add", ["Add a recipient", "vault", "--key"]),
        ("share remove", ["Remove a recipient", "vault"]),
        ("share export", ["Export sharing envelopes", "--output"]),
    ]
    
    for cmd, expected in share_commands:
        if not test_command_help(cli_path, cmd, expected):
            all_passed = False
    
    # Test mount subcommands
    mount_commands = [
        ("mount", ["Mount and unmount vaults", "Available Commands:"]),
        ("mount vault", ["Mount", "vault", "filesystem", "--mount-point"]),
        ("mount unmount", ["Unmount", "vault filesystem"]),
        ("mount list", ["List all currently mounted", "vault filesystems"]),
        ("mount status", ["Check", "mount status"]),
    ]
    
    for cmd, expected in mount_commands:
        if not test_command_help(cli_path, cmd, expected):
            all_passed = False
    
    # Test repair subcommands
    repair_commands = [
        ("repair", ["Repair corrupted vaults", "Available Commands:"]),
        ("repair vault", ["Attempt to repair", "corrupted vault", "--backup", "--force", "--dry-run"]),
        ("repair check", ["Perform comprehensive integrity checks", "--verbose", "--quick"]),
        ("repair verify", ["Verify", "vault", "opened"]),
    ]
    
    for cmd, expected in repair_commands:
        if not test_command_help(cli_path, cmd, expected):
            all_passed = False
    
    # Test recovery subcommands
    recovery_commands = [
        ("recovery", ["recovery keys", "Available Commands:"]),
        ("recovery generate", ["Generate", "recovery key"]),
        ("recovery recover", ["Recover access to a vault", "recovery key"]),
    ]
    
    for cmd, expected in recovery_commands:
        if not test_command_help(cli_path, cmd, expected):
            all_passed = False
    
    # Test config subcommands
    config_commands = [
        ("config", ["configuration", "Available Commands:"]),
        ("config show", ["Display the current", "configuration"]),
        ("config set", ["Set", "configuration"]),
    ]
    
    for cmd, expected in config_commands:
        if not test_command_help(cli_path, cmd, expected):
            all_passed = False
    
    print("=" * 50)
    if all_passed:
        print("🎉 All CLI help tests passed!")
        return 0
    else:
        print("❌ Some CLI help tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())