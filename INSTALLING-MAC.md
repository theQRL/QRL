# Installing QRL from source on macOS

This guide provides step-by-step instructions for building and running QRL from source on macOS. These steps have been tested and resolve common compatibility issues with modern macOS systems.

## Prerequisites

### System Requirements
- macOS 10.7 or later
- Homebrew package manager
- Command Line Tools for Xcode

### Install Homebrew
If you don't have Homebrew installed:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

## Step 1: Install System Dependencies

### Install LevelDB
LevelDB is required for the database backend. Install it via Homebrew:
```bash
brew install leveldb
```

Verify the installation:
```bash
brew info leveldb
```

Note the installation path (typically `/opt/homebrew/opt/leveldb` on Apple Silicon or `/usr/local/opt/leveldb` on Intel Macs).

## Step 2: Set Up Python Environment

### Install Python 3.12
Install Python 3.12 using pyenv for better version management:
```bash
brew install pyenv
pyenv install 3.12.0
```

### Configure Python Version
In the QRL repository directory, set the local Python version:
```bash
cd /path/to/QRL
pyenv local 3.12.0
```

This creates a `.python-version` file that automatically activates Python 3.12 when you're in this directory.

### Verify Python Version
```bash
python3 --version
# Should output: Python 3.12.0 (or similar)
```

## Step 3: Clone the Repository

```bash
git clone https://github.com/theQRL/QRL.git
cd QRL
```

### Initialize Git Submodules
The project uses integration tests as a submodule:
```bash
git submodule update --init --recursive
```

## Step 4: Install Python Dependencies

The key challenge on macOS is properly linking the plyvel package (Python bindings for LevelDB) with the system LevelDB installation.

### Set Environment Variables
Set the required compiler flags and paths for LevelDB:

**For Apple Silicon (M1/M2/M3):**
```bash
export CPLUS_INCLUDE_PATH=/opt/homebrew/opt/leveldb/include
export LIBRARY_PATH=/opt/homebrew/opt/leveldb/lib
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'
```

**For Intel Macs:**
```bash
export CPLUS_INCLUDE_PATH=/usr/local/opt/leveldb/include
export LIBRARY_PATH=/usr/local/opt/leveldb/lib
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'
```

### Install Dependencies
With the environment variables set, install the Python dependencies:
```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

### Install the QRL Package
Install QRL in development mode:
```bash
pip3 install -e .
```

## Step 5: Verify Installation

### Check plyvel Installation
Verify that plyvel is properly installed and can link to LevelDB:
```bash
python3 -c "import plyvel; print('plyvel version:', plyvel.__version__)"
```

If this succeeds without errors, the critical LevelDB bindings are working correctly.

### Check QRL Installation
Verify that QRL commands are available:
```bash
qrl --help
```

## Troubleshooting

### Issue: plyvel fails to install with "library not found for -lleveldb"

**Solution:** Ensure you've set the environment variables correctly before running pip install:
```bash
export CPLUS_INCLUDE_PATH=/opt/homebrew/opt/leveldb/include  # Adjust path for Intel Macs
export LIBRARY_PATH=/opt/homebrew/opt/leveldb/lib            # Adjust path for Intel Macs
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'
pip3 install plyvel>=1.5.0
```

### Issue: Wrong Python version is being used

**Solution:** Make sure pyenv is properly configured in your shell:
```bash
# Add to ~/.zshrc or ~/.bash_profile
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```

Then restart your shell or run:
```bash
source ~/.zshrc  # or source ~/.bash_profile
```

### Issue: Git submodule errors

**Solution:** Ensure submodules are properly initialized:
```bash
git submodule update --init --recursive
```

### Issue: ImportError for pkg_resources

**Solution:** Install or upgrade setuptools:
```bash
pip3 install --upgrade setuptools
```

### Issue: Protobuf version conflicts

**Solution:** The project requires protobuf >= 4.21.0 but < 7.0.0. If you encounter version conflicts:
```bash
pip3 install 'protobuf>=6.31.1,<7.0.0'
```

## Running QRL

### Start the QRL Node
```bash
start_qrl
```

Or use the alternative command:
```bash
qrl_start
```

### Additional Commands
The installation provides several utility commands:
- `qrl` - Main CLI interface
- `qrl_grpc_proxy` - gRPC proxy server
- `qrl_walletd` - Wallet daemon
- `qrl_generate_genesis` - Genesis block generation tool

## Development Setup

### Running Tests
```bash
pip3 install -e ".[test]"
pytest
```

### Code Quality Checks
The project uses flake8 for code quality:
```bash
flake8 src/qrl
```

## Notes

### Python 3.12 Compatibility
This project has been updated to support Python 3.12 with the following key updates:
- Updated plyvel to >= 1.5.0 for Python 3.12 support
- Updated Twisted to >= 25.0.0
- Updated Flask to >= 3.0.0
- Updated all cryptography libraries for compatibility

### Environment Variables Persistence
To avoid setting environment variables every time, add them to your shell configuration file:

**For zsh (default on modern macOS):**
```bash
# Add to ~/.zshrc
export CPLUS_INCLUDE_PATH=/opt/homebrew/opt/leveldb/include  # Adjust for Intel Macs
export LIBRARY_PATH=/opt/homebrew/opt/leveldb/lib            # Adjust for Intel Macs
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'
```

**For bash:**
```bash
# Add to ~/.bash_profile
export CPLUS_INCLUDE_PATH=/opt/homebrew/opt/leveldb/include  # Adjust for Intel Macs
export LIBRARY_PATH=/opt/homebrew/opt/leveldb/lib            # Adjust for Intel Macs
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'
```

After adding, restart your terminal or source the file:
```bash
source ~/.zshrc  # or source ~/.bash_profile
```

## Support

For issues and questions:
- GitHub Issues: https://github.com/theQRL/QRL/issues
- QRL Discord: https://discord.gg/theqrl
- Website: https://theqrl.org

## License

MIT License - See LICENSE file for details.
