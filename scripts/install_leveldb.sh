#!/bin/bash
# QRL LevelDB and Plyvel Installation Script
# This script installs leveldb and the plyvel Python bindings with proper linking

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect architecture
detect_arch() {
    local arch=$(uname -m)
    if [[ "$arch" == "arm64" ]]; then
        echo "apple_silicon"
    elif [[ "$arch" == "x86_64" ]]; then
        echo "intel"
    else
        echo "unknown"
    fi
}

# Function to get LevelDB paths based on architecture
get_leveldb_paths() {
    local arch=$1
    if [[ "$arch" == "apple_silicon" ]]; then
        echo "/opt/homebrew/opt/leveldb"
    elif [[ "$arch" == "intel" ]]; then
        echo "/usr/local/opt/leveldb"
    else
        echo ""
    fi
}

# Function to check if Homebrew is installed
check_homebrew() {
    if ! command -v brew &> /dev/null; then
        print_error "Homebrew is not installed"
        print_info "Install Homebrew from: https://brew.sh"
        print_info "Run: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        return 1
    fi
    print_success "Homebrew is installed"
    return 0
}

# Function to check if leveldb is installed
check_leveldb_installed() {
    if brew list leveldb &> /dev/null; then
        local version=$(brew list --versions leveldb | awk '{print $2}')
        print_info "LevelDB is installed: version $version"
        return 0
    else
        print_warning "LevelDB is not installed"
        return 1
    fi
}

# Function to build LevelDB from source with RTTI support
build_leveldb_with_rtti() {
    local arch=$1
    local leveldb_cellar="/opt/homebrew/Cellar/leveldb"
    if [[ "$arch" == "intel" ]]; then
        leveldb_cellar="/usr/local/Cellar/leveldb"
    fi

    print_info "Building LevelDB from source with RTTI support..."

    # Create temporary build directory
    local build_dir=$(mktemp -d)
    print_info "Using build directory: $build_dir"

    # Clone LevelDB source
    print_info "Cloning LevelDB 1.23 source code..."
    git clone --depth 1 --branch 1.23 https://github.com/google/leveldb.git "$build_dir/leveldb" || {
        print_error "Failed to clone LevelDB repository"
        rm -rf "$build_dir"
        return 1
    }

    # Patch CMakeLists.txt to enable RTTI
    print_info "Patching CMakeLists.txt to enable RTTI..."
    local cmake_file="$build_dir/leveldb/CMakeLists.txt"

    # Replace the RTTI-disabling code with RTTI-enabling code
    if grep -q "set(CMAKE_CXX_FLAGS \"\${CMAKE_CXX_FLAGS} -fno-rtti\")" "$cmake_file"; then
        # shellcheck disable=SC2016
        sed -i.bak \
            -e 's/# Disable RTTI\./# Enable RTTI (required for plyvel Python bindings)./' \
            -e 's/string(REGEX REPLACE "-frtti" "" CMAKE_CXX_FLAGS "\${CMAKE_CXX_FLAGS}")/string(REGEX REPLACE "-fno-rtti" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")/' \
            -e 's/set(CMAKE_CXX_FLAGS "\${CMAKE_CXX_FLAGS} -fno-rtti")/set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -frtti")/' \
            "$cmake_file" || {
            print_error "Failed to patch CMakeLists.txt"
            rm -rf "$build_dir"
            return 1
        }
        print_success "Successfully patched CMakeLists.txt"
    else
        print_warning "Could not find expected RTTI configuration in CMakeLists.txt"
        print_info "Attempting to build anyway..."
    fi

    # Get the LevelDB version from Homebrew
    local leveldb_version=$(brew list --versions leveldb 2>/dev/null | awk '{print $2}' || echo "1.23_2")
    local install_prefix="${leveldb_cellar}/${leveldb_version}"

    # Build LevelDB
    print_info "Building LevelDB (this may take a few minutes)..."
    mkdir -p "$build_dir/leveldb/build"
    cd "$build_dir/leveldb/build"

    cmake -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_INSTALL_PREFIX="$install_prefix" \
          -DLEVELDB_BUILD_TESTS=OFF \
          -DLEVELDB_BUILD_BENCHMARKS=OFF \
          .. || {
        print_error "CMake configuration failed"
        cd - > /dev/null
        rm -rf "$build_dir"
        return 1
    }

    make -j$(sysctl -n hw.ncpu) || {
        print_error "Build failed"
        cd - > /dev/null
        rm -rf "$build_dir"
        return 1
    }

    # Verify RTTI symbols are present
    print_info "Verifying RTTI symbols in built library..."
    if ! nm libleveldb.*.dylib | grep -q "__ZTIN7leveldb10ComparatorE"; then
        print_error "Built library is missing RTTI symbols"
        print_error "The patch may not have worked correctly"
        cd - > /dev/null
        rm -rf "$build_dir"
        return 1
    fi
    print_success "RTTI symbols verified in built library"

    # Backup and replace the existing library
    print_info "Installing patched LevelDB library..."
    local lib_dir="${install_prefix}/lib"
    local lib_file="${lib_dir}/libleveldb.1.23.0.dylib"

    if [[ -f "$lib_file" ]]; then
        print_info "Backing up existing library..."
        cp "$lib_file" "${lib_file}.no-rtti-backup" || {
            print_warning "Failed to create backup (continuing anyway)"
        }
        chmod u+w "$lib_file" || {
            print_error "Failed to make library writable"
            cd - > /dev/null
            rm -rf "$build_dir"
            return 1
        }
    fi

    cp libleveldb.1.23.0.dylib "$lib_file" || {
        print_error "Failed to copy library file"
        cd - > /dev/null
        rm -rf "$build_dir"
        return 1
    }

    cd - > /dev/null
    rm -rf "$build_dir"

    print_success "LevelDB with RTTI support installed successfully"
    return 0
}

# Function to install or reinstall leveldb
install_leveldb() {
    local force_rebuild=$1
    local enable_rtti=$2
    local arch=$3

    print_info "Installing LevelDB..."

    # Check if already installed
    if check_leveldb_installed; then
        if [[ "$force_rebuild" == "true" ]]; then
            print_info "Force rebuild requested, uninstalling existing LevelDB..."
            brew uninstall leveldb || {
                print_error "Failed to uninstall existing LevelDB"
                return 1
            }
        else
            print_info "LevelDB is already installed"
            if [[ "$enable_rtti" == "true" ]]; then
                print_info "RTTI support needed, will build from source and patch..."
                # Don't uninstall - we'll patch in place
                build_leveldb_with_rtti "$arch"
                return $?
            else
                print_info "Use --rebuild flag to force rebuild from source"
                return 0
            fi
        fi
    fi

    # Install from source for better compatibility
    if [[ "$enable_rtti" == "true" ]]; then
        print_info "Installing LevelDB with RTTI support..."
        # First install via Homebrew to get the basic structure
        brew install leveldb --build-from-source || brew install leveldb || {
            print_error "Failed to install LevelDB via Homebrew"
            return 1
        }
        # Then build and patch with RTTI
        build_leveldb_with_rtti "$arch"
        return $?
    else
        print_info "Installing LevelDB from source (this may take a few minutes)..."
        brew install leveldb --build-from-source || {
            print_error "Failed to install LevelDB"
            print_info "Trying with pre-built bottle..."
            brew install leveldb || {
                print_error "Failed to install LevelDB with bottle"
                return 1
            }
        }
    fi

    print_success "LevelDB installed successfully"
    return 0
}

# Function to verify leveldb library exists
verify_leveldb_library() {
    local leveldb_path=$1
    local lib_path="${leveldb_path}/lib/libleveldb.1.dylib"

    print_info "Verifying LevelDB library..."

    if [[ ! -f "$lib_path" ]]; then
        print_error "LevelDB library not found at: $lib_path"
        return 1
    fi

    print_success "Found LevelDB library: $lib_path"

    # Check library architecture
    local arch_info=$(file "$lib_path" | grep -o "arm64\|x86_64")
    print_info "Library architecture: $arch_info"

    return 0
}

# Function to check if leveldb has RTTI symbols
check_leveldb_rtti() {
    local leveldb_path=$1
    local lib_path="${leveldb_path}/lib/libleveldb.1.dylib"

    print_info "Checking for RTTI symbols in LevelDB library..."

    if [[ ! -f "$lib_path" ]]; then
        print_warning "LevelDB library not found, cannot check RTTI symbols"
        return 1
    fi

    # Check for RTTI typeinfo symbols (these should be present for plyvel to work)
    if nm "$lib_path" | grep -q "__ZTIN7leveldb10ComparatorE"; then
        print_success "LevelDB has RTTI symbols (Comparator typeinfo found)"
        return 0
    else
        print_warning "LevelDB is missing RTTI symbols"
        print_info "The library was likely built without -frtti flag"
        return 1
    fi
}

# Function to get Python version
get_python_version() {
    python3 --version 2>&1 | awk '{print $2}'
}

# Function to get Python executable path
get_python_executable() {
    python3 -c "import sys; print(sys.executable)"
}

# Function to install plyvel with proper linking
install_plyvel() {
    local leveldb_path=$1
    local python_exec=$2
    local force_build=$3

    print_info "Installing plyvel Python bindings..."

    # Check if plyvel is already installed and working
    if "$python_exec" -c "import plyvel; plyvel.__version__" >/dev/null 2>&1; then
        if [[ "$force_build" != "true" ]]; then
            print_success "Plyvel is already installed and working"
            return 0
        else
            print_info "Force rebuild requested, uninstalling existing plyvel..."
            "$python_exec" -m pip uninstall -y plyvel || {
                print_error "Failed to uninstall existing plyvel"
                return 1
            }
        fi
    fi

    if [[ "$force_build" == "true" ]]; then
        # Set environment variables for compilation
        export CPLUS_INCLUDE_PATH="${leveldb_path}/include"
        export LIBRARY_PATH="${leveldb_path}/lib"
        export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'

        print_info "Using environment variables for source build:"
        print_info "  CPLUS_INCLUDE_PATH=${CPLUS_INCLUDE_PATH}"
        print_info "  LIBRARY_PATH=${LIBRARY_PATH}"
        print_info "  CXXFLAGS=${CXXFLAGS}"

        # Install plyvel from source
        print_info "Building plyvel from source..."
        "$python_exec" -m pip install --no-cache-dir --no-binary plyvel 'plyvel>=1.5.0' || {
            print_error "Failed to install plyvel from source"
            print_info "Falling back to pre-built wheel..."
            "$python_exec" -m pip install 'plyvel>=1.5.0' || {
                print_error "Failed to install plyvel"
                return 1
            }
        }
    else
        # Try to use pre-built wheel first (usually more reliable)
        print_info "Installing plyvel (using pre-built wheel if available)..."
        "$python_exec" -m pip install 'plyvel>=1.5.0' || {
            print_error "Failed to install plyvel"
            print_info "Make sure you have Xcode Command Line Tools installed:"
            print_info "  xcode-select --install"
            return 1
        }
    fi

    print_success "Plyvel installed successfully"
    return 0
}

# Function to verify plyvel installation
verify_plyvel() {
    local python_exec=$1
    local leveldb_path=$2

    print_info "Verifying plyvel installation..."

    # Try to import plyvel and capture any errors
    # Note: set -e is disabled by the caller, so we don't need to manage it here

    "$python_exec" -c "
import plyvel
# Force the C extension to load by accessing the DB class
_ = plyvel.DB
print('  ✓ plyvel version:', plyvel.__version__)
" > /tmp/plyvel_test_out.txt 2>&1
    local import_exit_code=$?
    local import_result=$(cat /tmp/plyvel_test_out.txt)

    if [[ $import_exit_code -ne 0 ]]; then
        # Check if it's an RTTI symbol error
        if echo "$import_result" | grep -q "symbol not found.*Comparator"; then
            print_error "Plyvel import failed due to RTTI symbol incompatibility"
            echo "$import_result"
            return 2  # Return 2 to indicate RTTI issue specifically
        else
            print_error "Failed to import plyvel:"
            echo "$import_result"
            return 1
        fi
    fi

    echo "$import_result"
    print_success "Plyvel import successful"

    # Find the plyvel .so file
    local plyvel_so=$("$python_exec" -c "import os, plyvel; print(os.path.join(os.path.dirname(plyvel.__file__), '_plyvel.cpython-*-darwin.so'))" 2>/dev/null || echo "")

    # Expand glob pattern
    plyvel_so=$(echo "$plyvel_so")

    if [[ -f "$plyvel_so" ]]; then
        print_info "Checking plyvel library linkage..."
        local linked_libs=$(otool -L "$plyvel_so" | grep leveldb)
        if [[ -n "$linked_libs" ]]; then
            print_info "  Linked libraries:"
            echo "$linked_libs" | while read -r line; do
                print_info "    $line"
            done
            print_success "Plyvel is properly linked to LevelDB"
        else
            print_warning "Plyvel may not be properly linked to LevelDB"
        fi
    else
        print_warning "Could not locate plyvel .so file for inspection"
    fi

    # Test actual database operations
    print_info "Testing plyvel database operations..."

    # Note: set -e is disabled by the caller
    local test_result=$("$python_exec" -c "
import plyvel
import tempfile
import os
import shutil

# Create a temporary directory for the test database
test_db_path = tempfile.mkdtemp()
try:
    # Open a database
    db = plyvel.DB(test_db_path, create_if_missing=True)

    # Write a key-value pair
    db.put(b'test_key', b'test_value')

    # Read it back
    value = db.get(b'test_key')

    # Verify
    assert value == b'test_value', 'Read/write test failed'

    # Close database
    db.close()

    print('  ✓ Database operations test passed')
finally:
    # Cleanup
    if os.path.exists(test_db_path):
        shutil.rmtree(test_db_path)
" 2>&1)
    local test_exit_code=$?

    if [[ $test_exit_code -eq 0 ]]; then
        echo "$test_result"
        print_success "Plyvel database operations work correctly"
        return 0
    else
        print_error "Plyvel database operations test failed:"
        echo "$test_result"
        return 1
    fi
}

# Function to create environment variable helper
create_env_helper() {
    local leveldb_path=$1
    local script_dir=$(dirname "$0")
    local env_file="${script_dir}/leveldb_env.sh"

    print_info "Creating environment variable helper script..."

    cat > "$env_file" << EOF
#!/bin/bash
# LevelDB Environment Variables
# Source this file before building Python packages that depend on LevelDB
# Usage: source scripts/leveldb_env.sh

export CPLUS_INCLUDE_PATH="${leveldb_path}/include"
export LIBRARY_PATH="${leveldb_path}/lib"
export CXXFLAGS='-mmacosx-version-min=10.7 -stdlib=libc++'

echo "LevelDB environment variables set:"
echo "  CPLUS_INCLUDE_PATH=\${CPLUS_INCLUDE_PATH}"
echo "  LIBRARY_PATH=\${LIBRARY_PATH}"
echo "  CXXFLAGS=\${CXXFLAGS}"
EOF

    chmod +x "$env_file"
    print_success "Created environment helper: $env_file"
    print_info "You can source this file in the future: source scripts/leveldb_env.sh"
}

# Main script
main() {
    local force_rebuild=false
    local force_rebuild_plyvel=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --rebuild)
                force_rebuild=true
                shift
                ;;
            --rebuild-plyvel)
                force_rebuild_plyvel=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Install LevelDB and plyvel for QRL"
                echo ""
                echo "OPTIONS:"
                echo "  --rebuild         Force rebuild of LevelDB from source"
                echo "  --rebuild-plyvel  Force rebuild of plyvel from source"
                echo "  -h, --help        Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                print_info "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    print_info "QRL LevelDB and Plyvel Installer"
    print_info "================================="
    echo ""

    # Detect architecture
    local arch=$(detect_arch)
    if [[ "$arch" == "unknown" ]]; then
        print_error "Unsupported architecture: $(uname -m)"
        exit 1
    fi
    print_info "Architecture: $arch"

    # Get LevelDB paths
    local leveldb_path=$(get_leveldb_paths "$arch")
    if [[ -z "$leveldb_path" ]]; then
        print_error "Could not determine LevelDB path for architecture: $arch"
        exit 1
    fi
    print_info "LevelDB path: $leveldb_path"

    # Get Python info
    local python_version=$(get_python_version)
    local python_exec=$(get_python_executable)
    print_info "Python version: $python_version"
    print_info "Python executable: $python_exec"
    echo ""

    # Check for Homebrew
    if ! check_homebrew; then
        exit 1
    fi
    echo ""

    # Install LevelDB
    if ! install_leveldb "$force_rebuild" "false" "$arch"; then
        print_error "LevelDB installation failed"
        exit 1
    fi
    echo ""

    # Verify LevelDB
    if ! verify_leveldb_library "$leveldb_path"; then
        print_error "LevelDB verification failed"
        exit 1
    fi
    echo ""

    # Check for RTTI symbols in LevelDB
    if ! check_leveldb_rtti "$leveldb_path"; then
        print_warning "LevelDB needs to be rebuilt with RTTI support"
    fi
    echo ""

    # Install plyvel
    if ! install_plyvel "$leveldb_path" "$python_exec" "$force_rebuild_plyvel"; then
        print_error "Plyvel installation failed"
        exit 1
    fi
    echo ""

    # Verify plyvel
    # Temporarily disable set -e to capture return codes properly
    set +e
    verify_plyvel "$python_exec" "$leveldb_path"
    local verify_result=$?
    set -e

    if [[ $verify_result -eq 2 ]]; then
        # RTTI symbol issue detected
        print_warning "Detected RTTI symbol issue - will rebuild LevelDB with RTTI support"
        echo ""

        print_info "Step 1: Rebuilding LevelDB with RTTI enabled..."
        if ! install_leveldb "true" "true" "$arch"; then
            print_error "Failed to rebuild LevelDB with RTTI support"
            exit 1
        fi
        echo ""

        print_info "Step 2: Verifying rebuilt LevelDB has RTTI symbols..."
        if ! check_leveldb_rtti "$leveldb_path"; then
            print_error "LevelDB rebuild failed to add RTTI symbols"
            print_info "This may require manual intervention"
            exit 1
        fi
        echo ""

        print_info "Step 3: Rebuilding plyvel with RTTI-enabled LevelDB..."
        if ! install_plyvel "$leveldb_path" "$python_exec" "true"; then
            print_error "Failed to rebuild plyvel after LevelDB RTTI rebuild"
            exit 1
        fi
        echo ""

        print_info "Step 4: Re-verifying plyvel installation..."
        set +e
        verify_plyvel "$python_exec" "$leveldb_path"
        verify_result=$?
        set -e

        if [[ $verify_result -ne 0 ]]; then
            print_error "Plyvel still has issues after RTTI rebuild"
            print_info "You may need to manually resolve this issue"
            print_info "See INSTALLING-MAC.md for additional troubleshooting"
        else
            print_success "Successfully fixed RTTI issue!"
        fi
    elif [[ $verify_result -ne 0 ]]; then
        print_warning "Plyvel verification failed, but continuing..."
        echo ""
        print_info "You may need to resolve plyvel issues before running QRL"
        print_info "See the messages above for possible solutions"
    fi
    echo ""

    # Create environment helper
    create_env_helper "$leveldb_path"
    echo ""

    # Final summary
    print_info "================================="
    print_info "Installation Summary"
    print_info "================================="
    echo ""

    # Check if we have a working plyvel
    if "$python_exec" -c "import plyvel" >/dev/null 2>&1; then
        print_success "LevelDB and plyvel are working correctly!"
        echo ""
        print_info "Next steps:"
        print_info "1. Run: bash scripts/install_mac_deps.sh"
        print_info "   This will build the native QRL modules (pyqrllib, pyqryptonight, pyqrandomx)"
        echo ""
        print_info "2. Install QRL Python dependencies:"
        print_info "   pip3 install -r requirements.txt"
        echo ""
        print_info "3. Install QRL package:"
        print_info "   pip3 install -e ."
        echo ""
        print_info "4. Run QRL:"
        print_info "   start_qrl"
    else
        print_warning "LevelDB is installed but plyvel has issues"
        echo ""
        print_info "Recommended approach:"
        print_info "1. Make sure you're using Python 3.12: pyenv local 3.12.0"
        print_info "2. Follow the manual installation steps in INSTALLING-MAC.md"
        print_info "3. If plyvel continues to fail, you may need to:"
        print_info "   - Use a clean Python virtual environment"
        print_info "   - Or install from a working system backup"
        echo ""
        print_info "See INSTALLING-MAC.md for detailed troubleshooting steps"
    fi
    echo ""
}

# Run main function
main "$@"
