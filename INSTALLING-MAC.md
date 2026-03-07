# Installing QRL from source on macOS

This guide provides step-by-step instructions for building
and running QRL from source on macOS.

## Prerequisites

Before you begin, ensure you have:

- **Homebrew package manager** - Install from <https://brew.sh> if needed
- **Command Line Tools for Xcode** - Run `xcode-select --install`
- **Git** - Typically included with Command Line Tools

### Step 1: Clone the Repository & fetch submodules

```bash
git clone https://github.com/theQRL/QRL.git
cd QRL
git submodule update --init --recursive
```

### Step 2: Install LevelDB with RTTI Support

Run the automated LevelDB installation script:

```bash
./scripts/install_leveldb.sh
```

This script:

- Installs LevelDB from Homebrew
- Automatically detects and fixes RTTI symbol issues
- Rebuilds LevelDB from source with RTTI enabled if needed
- Installs the plyvel Python bindings correctly

If you encounter issues, force a complete rebuild:

```bash
./scripts/install_leveldb.sh --rebuild
```

> The Homebrew-installed LevelDB is built without RTTI (Run-Time Type Information)
> symbols that the plyvel Python bindings require.
> This causes import errors like:
>
> ```text
> ImportError: symbol not found in flat namespace '__ZTIN7leveldb10ComparatorE'
> ```
>
> The solution is to rebuild LevelDB from source with RTTI enabled. The `
> install_leveldb.sh` script automates this, but you can do it manually if needed.

### Step 3: Install build dependencies from Homebrew

```bash
brew install swig boost hwloc openssl gcc cmake xcodegen
```

### Step 4: Set Up Python Environment

Install Python 3.12 using pyenv:

```bash
brew install pyenv
pyenv install 3.12.0
pyenv local 3.12.0
```

Verify the Python version:

```bash
python3 --version
# Should output: Python 3.12.0
```

### Step 5: Install QRL Python Dependencies

Source the LevelDB environment variables and install dependencies:

```bash
source scripts/leveldb_env.sh
pip3 install --upgrade pip
pip3 install -r requirements.txt
pip3 install -e .
```

**Note:** The `leveldb_env.sh` script sets the necessary compiler
flags for building packages that depend on LevelDB.

### Step 6: Build Native Dependencies

Run the native dependencies installer to rebuild QRL's
native extensions for your Python version:

```bash
./scripts/install_mac_deps.sh
```

This script:

- Detects your Python version and architecture
- Rebuilds pyqrllib, pyqryptonight, and pyqrandomx from source
- Ensures all native modules are correctly linked
- Verifies the installation with tests

### Step 7: Start QRL

```bash
start_qrl
```

If everything is set up correctly, your QRL node will start running!

---

## Troubleshooting

### Issue: plyvel fails to install with "library not found for -lleveldb"

**Solution:** Ensure you've set the environment variables
correctly before running pip install:

```bash
export CPLUS_INCLUDE_PATH=/opt/homebrew/opt/leveldb/include
export LIBRARY_PATH=/opt/homebrew/opt/leveldb/lib
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'
pip3 install plyvel>=1.5.0
```

Or use the helper script:

```bash
source scripts/leveldb_env.sh
pip3 install plyvel>=1.5.0
```

### Issue: RTTI symbol errors when importing plyvel

**Error message:**

```text
ImportError: symbol not found in flat namespace '__ZTIN7leveldb10ComparatorE'
```

**Solution:** LevelDB was built without RTTI support.
Run the installation script to fix:

```bash
./scripts/install_leveldb.sh --rebuild
```

This will rebuild LevelDB from source with RTTI enabled and reinstall plyvel.

### Issue: Segmentation fault when running QRL

**Common cause:** Native Python extensions (pyqrllib, pyqryptonight,
pyqrandomx) were built for a different Python version.

**Solution:** Rebuild the native dependencies:

```bash
./scripts/install_mac_deps.sh
```

This script detects your current Python version and rebuilds
all native modules correctly.

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

Verify the correct version is active:

```bash
python3 --version
which python3
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

**Solution:** The project requires protobuf >= 4.21.0 but < 7.0.0.
If you encounter version conflicts:

```bash
pip3 install 'protobuf>=6.31.1,<7.0.0'
```

### Issue: CMake not found when building native dependencies

**Solution:** Install CMake via Homebrew:

```bash
brew install cmake
```

### Issue: Scripts fail with permission denied

**Solution:** Make the scripts executable:

```bash
chmod +x scripts/*.sh
```

### Manual Building of Native Dependencies

If the `install_mac_deps.sh` script fails, you can manually rebuild each package:

**pyqrllib:**

```bash
git clone https://github.com/theQRL/qrllib.git /tmp/qrllib
cd /tmp/qrllib
git submodule update --init --recursive
mkdir -p build && cd build
cmake .. -DPYTHON_EXECUTABLE=$(which python3) -DBUILD_PYTHON=ON
cmake --build . --config Release
# Copy the built files to your Python site-packages
```

**pyqryptonight:**

```bash
git clone https://github.com/theQRL/qryptonight.git /tmp/qryptonight
cd /tmp/qryptonight
git submodule update --init --recursive
mkdir -p build && cd build
cmake .. -DPYTHON_EXECUTABLE=$(which python3) -DBUILD_PYTHON=ON
cmake --build . --config Release
```

**pyqrandomx:**

```bash
git clone https://github.com/theQRL/qrandomx.git /tmp/qrandomx
cd /tmp/qrandomx
git submodule update --init --recursive
mkdir -p build && cd build
cmake .. -DPYTHON_EXECUTABLE=$(which python3) -DBUILD_PYTHON=ON
cmake --build . --config Release
```

For detailed manual build instructions, refer to each repository's documentation.

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

## Additional Notes

### Script Reference

The QRL repository includes three helper scripts in the `scripts/` directory:

1. **`install_leveldb.sh`** - Installs LevelDB with RTTI support
   - Automatically detects and fixes RTTI symbol issues
   - Use `--rebuild` flag to force a complete rebuild

2. **`install_mac_deps.sh`** - Rebuilds native Python extensions
   - Builds pyqrllib, pyqryptonight, and pyqrandomx
   - Ensures correct Python version linkage
   - Runs comprehensive verification tests

3. **`leveldb_env.sh`** - Sets LevelDB environment variables
   - Source this before building packages that need LevelDB
   - Use: `source scripts/leveldb_env.sh`

### Environment Variables Persistence

If you frequently build Python packages that depend on LevelDB,
you can make the environment variables permanent:

#### Option 1: Source the helper script (recommended)

```bash
# Add to ~/.zshrc or ~/.bash_profile
source /path/to/QRL/scripts/leveldb_env.sh
```

#### Option 2: Manually add environment variables

**For zsh:**

```bash
# Add to ~/.zshrc
export CPLUS_INCLUDE_PATH=/opt/homebrew/opt/leveldb/include
export LIBRARY_PATH=/opt/homebrew/opt/leveldb/lib
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'
```

**For bash:**

```bash
# Add to ~/.bash_profile
export CPLUS_INCLUDE_PATH=/opt/homebrew/opt/leveldb/include
export LIBRARY_PATH=/opt/homebrew/opt/leveldb/lib
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'
```

After adding, restart your terminal or source the file:

```bash
source ~/.zshrc  # or source ~/.bash_profile
```

### Intel vs Apple Silicon

The scripts automatically detect your architecture, but if you
need to manually specify paths:

- **Apple Silicon (M1/M2/M3/M4):** `/opt/homebrew/opt/leveldb`
- **Intel Macs:** `/usr/local/opt/leveldb`

## Support

For issues and questions:

- GitHub Issues: <https://github.com/theQRL/QRL/issues>
- QRL Discord: <https://discord.gg/theqrl>
- Website: <https://theqrl.org>

Development issues are preferred to be reported on GitHub.

## License

MIT License - See LICENSE file for details.
