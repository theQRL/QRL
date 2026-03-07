#!/bin/bash
# QRL macOS Native Dependencies Installation Script
# This script rebuilds native Python extensions (pyqrllib, pyqryptonight, pyqrandomx)
# with the correct Python version to avoid segmentation faults.

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

# Function to get Python version
get_python_version() {
    python3 --version 2>&1 | awk '{print $2}'
}

# Function to get Python executable path
get_python_executable() {
    # Get the actual Python executable, not just the shim
    # This is important for pyenv users, as shims can change based on directory
    python3 -c "import sys; print(sys.executable)"
}

# Function to fix GCC include-fixed headers on macOS
fix_gcc_include_fixed() {
    print_info "Checking GCC include-fixed headers..."

    # Get current macOS version (e.g., darwin24)
    local current_darwin_version=$(uname -r | cut -d'.' -f1)
    print_info "  Current Darwin version: darwin${current_darwin_version}"

    # Find all GCC installations in Homebrew
    local gcc_cellar_base="/usr/local/Cellar"
    if [[ ! -d "$gcc_cellar_base" ]]; then
        print_info "  Homebrew Cellar not found at $gcc_cellar_base, skipping GCC check"
        return 0
    fi

    # Look for gcc and gcc@* installations
    local fixed_any=false
    for gcc_dir in "$gcc_cellar_base"/gcc@* "$gcc_cellar_base"/gcc; do
        if [[ ! -d "$gcc_dir" ]]; then
            continue
        fi

        local gcc_name=$(basename "$gcc_dir")
        print_info "  Checking $gcc_name..."

        # Find include-fixed directories in this GCC installation
        while IFS= read -r -d '' include_fixed_dir; do
            # Extract darwin version from path (e.g., x86_64-apple-darwin23)
            if [[ "$include_fixed_dir" =~ darwin([0-9]+) ]]; then
                local fixed_darwin_version="${BASH_REMATCH[1]}"

                # Check if there's a version mismatch
                if [[ "$fixed_darwin_version" != "$current_darwin_version" ]]; then
                    print_warning "  Found include-fixed built for darwin${fixed_darwin_version} (current: darwin${current_darwin_version})"
                    print_info "    Path: $include_fixed_dir"

                    # Check if already backed up
                    if [[ -d "${include_fixed_dir}.bak" ]]; then
                        print_info "    Already backed up, skipping"
                    else
                        print_info "    Renaming to ${include_fixed_dir}.bak"
                        if mv "$include_fixed_dir" "${include_fixed_dir}.bak" 2>/dev/null; then
                            print_success "    Successfully renamed incompatible include-fixed directory"
                            fixed_any=true
                        else
                            print_warning "    Could not rename (may need sudo), attempting build anyway"
                        fi
                    fi
                else
                    print_success "  include-fixed version matches current system (darwin${fixed_darwin_version})"
                fi
            fi
        done < <(find "$gcc_dir" -type d -name "include-fixed" -print0 2>/dev/null)
    done

    if [[ "$fixed_any" == true ]]; then
        print_success "Fixed GCC include-fixed header issues"
    else
        print_info "  No GCC include-fixed issues found"
    fi

    echo ""
    return 0
}

# Function to check if a package needs rebuilding
check_package_python_version() {
    local package_name=$1
    local so_name=$2
    local python_exec=$3  # Use the specific Python executable

    print_info "Checking $package_name..."

    # Try to get the .so file path
    local so_path=$("$python_exec" -c "import os, $package_name; print(os.path.join(os.path.dirname($package_name.__file__), '$so_name'))" 2>/dev/null || echo "")

    if [[ -z "$so_path" ]] || [[ ! -f "$so_path" ]]; then
        print_warning "$package_name not found or not properly installed"
        return 1
    fi

    # Check which Python version it's linked against
    local linked_python=$(otool -L "$so_path" | grep -i python | head -1 || echo "")

    if [[ -z "$linked_python" ]]; then
        print_warning "Could not determine Python version for $package_name"
        return 1
    fi

    print_info "  Linked against: $linked_python"

    # Extract version from path (e.g., python@3.13 or python3.12)
    local linked_version=$(echo "$linked_python" | grep -oE 'python(@)?3\.[0-9]+' | grep -oE '3\.[0-9]+')
    local current_version=$("$python_exec" --version 2>&1 | awk '{print $2}' | grep -oE '^3\.[0-9]+')

    if [[ "$linked_version" != "$current_version" ]]; then
        print_warning "  Version mismatch: linked=$linked_version, current=$current_version"
        return 1
    else
        print_success "  Version match: $current_version"
        return 0
    fi
}

# Function to build a QRL package
build_qrl_package() {
    local repo_name=$1
    local package_name=$2
    local python_exec=$3  # Pass Python executable as parameter to ensure consistency
    local repo_url="https://github.com/theQRL/${repo_name}.git"
    local build_dir="/tmp/${repo_name}_build_$$"

    print_info "Building $package_name from $repo_url..."

    # Clone repository
    print_info "  Cloning repository..."
    git clone --quiet "$repo_url" "$build_dir" || {
        print_error "Failed to clone $repo_url"
        return 1
    }

    cd "$build_dir"

    # Initialize submodules
    print_info "  Initializing submodules..."
    git submodule update --init --recursive --quiet || {
        print_error "Failed to initialize submodules"
        return 1
    }

    # Create build directory
    mkdir -p build
    cd build

    # Use the Python executable passed as parameter (to avoid pyenv switching in /tmp)
    print_info "  Using Python: $python_exec"

    # Get macOS SDK path for GCC compatibility
    local macos_sdk=""
    if command -v xcrun &> /dev/null; then
        macos_sdk=$(xcrun --show-sdk-path 2>/dev/null || echo "")
        if [[ -n "$macos_sdk" ]]; then
            print_info "  macOS SDK: $macos_sdk"
        fi
    fi

    # Configure with CMake
    print_info "  Configuring with CMake..."
    local cmake_output
    if ! cmake_output=$(cmake .. \
        -DPYTHON_EXECUTABLE="$python_exec" \
        -DPython_EXECUTABLE="$python_exec" \
        -DPython3_EXECUTABLE="$python_exec" \
        -DBUILD_PYTHON=ON \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_FLAGS="" \
        ${macos_sdk:+-DCMAKE_OSX_SYSROOT="$macos_sdk"} \
        2>&1); then
        print_error "CMake configuration failed for $package_name"
        print_error "CMake output:"
        echo "$cmake_output" | while IFS= read -r line; do
            print_error "  $line"
        done
        return 1
    fi

    # Build
    print_info "  Building (this may take a few minutes)..."
    cmake --build . --config Release -- -j2 > /dev/null 2>&1 || {
        print_warning "Build completed with errors (this may be OK if the module was built)"
    }

    # Check if .so file was created in pyqrllib (we're already in the build directory)
    local build_output_dir="${package_name}"
    local so_file="${build_output_dir}/_${package_name}.so"

    if [[ ! -f "$so_file" ]]; then
        print_error "Failed to build $package_name - .so file not found at: $so_file"
        cd /
        rm -rf "$build_dir"
        return 1
    fi

    print_success "  Build completed - found .so file"

    # Install
    print_info "  Installing to site-packages..."
    # Use the specific Python executable to get the correct site-packages
    local site_packages=$("$python_exec" -c "import site; print(site.getsitepackages()[0])")
    local install_dir="$site_packages/$package_name"
    print_info "  Site-packages for $(basename "$python_exec"): $site_packages"

    # Remove old installation directory to ensure clean install
    if [[ -d "$install_dir" ]]; then
        print_info "  Removing old installation at $install_dir..."
        rm -rf "$install_dir"
    fi

    # Create fresh package directory
    mkdir -p "$install_dir"
    print_info "  Installing to: $install_dir"

    # Copy all .so files from build output directory
    print_info "  Copying .so files..."
    print_info "    Looking in: $(pwd)/${build_output_dir}/"
    local so_files_found=false
    for so_file_path in "${build_output_dir}"/*.so; do
        # Check if glob matched any files (bash leaves the pattern if no match)
        if [[ -f "$so_file_path" ]]; then
            local src_path="$(pwd)/$so_file_path"
            local dest_path="$install_dir/$(basename "$so_file_path")"
            print_info "    Copying: $src_path -> $dest_path"

            cp "$so_file_path" "$install_dir/" || {
                print_error "Failed to copy $(basename "$so_file_path")"
                cd /
                rm -rf "$build_dir"
                return 1
            }

            # Verify the copy succeeded
            if [[ ! -f "$dest_path" ]]; then
                print_error "Copy verification failed: $dest_path does not exist"
                cd /
                rm -rf "$build_dir"
                return 1
            fi

            local src_size=$(stat -f%z "$so_file_path")
            local dest_size=$(stat -f%z "$dest_path")
            if [[ "$src_size" != "$dest_size" ]]; then
                print_error "Copy verification failed: size mismatch ($src_size vs $dest_size)"
                cd /
                rm -rf "$build_dir"
                return 1
            fi

            so_files_found=true
            print_info "    ✓ Verified: $(basename "$so_file_path") ($src_size bytes)"
        fi
    done

    if [[ "$so_files_found" == false ]]; then
        print_error "No .so files found in build output directory: $(pwd)/${build_output_dir}/"
        print_error "Contents of build directory:"
        ls -la "${build_output_dir}/" 2>&1 || print_error "Cannot list directory"
        cd /
        rm -rf "$build_dir"
        return 1
    fi

    # Copy SWIG-generated Python files from build output directory
    print_info "  Copying SWIG-generated Python files..."
    for py_file in "${build_output_dir}"/*.py; do
        if [[ -f "$py_file" ]]; then
            cp "$py_file" "$install_dir/"
            print_info "    ✓ Copied: $(basename "$py_file")"
        fi
    done

    # Copy essential files from source directory (e.g., __init__.py, _version.py)
    print_info "  Copying package metadata files from source..."
    # Go back to repo root to access source files
    cd "$build_dir"
    if [[ -f "${package_name}/__init__.py" ]]; then
        cp "${package_name}/__init__.py" "$install_dir/"
        print_info "    ✓ Copied: __init__.py"
    else
        # Create a minimal __init__.py if it doesn't exist
        print_info "    Creating minimal __init__.py"
        touch "$install_dir/__init__.py"
    fi
    if [[ -f "${package_name}/_version.py" ]]; then
        cp "${package_name}/_version.py" "$install_dir/"
        print_info "    ✓ Copied: _version.py"
    fi

    # Go back to build directory for verification
    cd "$build_dir/build"

    # Verify installation
    cd /
    print_info "  Verifying $package_name installation..."

    # List what was actually installed
    print_info "  Installed files:"
    if [[ -d "$install_dir" ]]; then
        ls -lh "$install_dir" | tail -n +2 | while read -r line; do
            print_info "    $line"
        done
    else
        print_error "Installation directory not found: $install_dir"
        rm -rf "$build_dir"
        return 1
    fi

    # Check that the .so file exists in the installation
    local main_so_file="$install_dir/_${package_name}.so"
    if [[ ! -f "$main_so_file" ]]; then
        print_error "Main .so file not found at: $main_so_file"
        print_error "Installation appears incomplete"
        rm -rf "$build_dir"
        return 1
    fi
    print_success "  Main .so file verified: $(basename "$main_so_file")"

    # Try to import the package
    if ! "$python_exec" -c "import $package_name" 2>&1; then
        print_error "Failed to import $package_name after installation"
        print_error "Import error output shown above"
        rm -rf "$build_dir"
        return 1
    fi

    # Try to import the native module specifically
    if ! "$python_exec" -c "from $package_name import _${package_name}" 2>&1; then
        print_error "Failed to import native module _${package_name}"
        print_error "The .so file may be incompatible or corrupted"
        rm -rf "$build_dir"
        return 1
    fi

    print_success "$package_name installed successfully"

    # Cleanup
    rm -rf "$build_dir"

    return 0
}

# Main script
main() {
    print_info "QRL macOS Native Dependencies Installer"
    print_info "========================================"
    echo ""

    # Detect architecture
    local arch=$(detect_arch)
    print_info "Architecture: $arch"

    # Get Python version
    local python_version=$(get_python_version)
    local python_exec=$(get_python_executable)
    print_info "Python version: $python_version"
    print_info "Python executable: $python_exec"
    echo ""

    # Check for required tools
    print_info "Checking for required tools..."
    for tool in git cmake python3; do
        if ! command -v $tool &> /dev/null; then
            print_error "$tool is not installed. Please install it first."
            exit 1
        fi
    done
    print_success "All required tools found"
    echo ""

    # Fix GCC include-fixed headers if needed (macOS Sequoia compatibility)
    fix_gcc_include_fixed

    # Define all packages to rebuild
    local packages_to_rebuild=("qrllib:pyqrllib" "qryptonight:pyqryptonight" "qrandomx:pyqrandomx")

    print_info "Removing old modules and rebuilding for Python $python_version..."
    echo ""

    # Get site-packages directory
    local site_packages=$("$python_exec" -c "import site; print(site.getsitepackages()[0])")

    # Remove existing installations
    print_info "Removing existing modules from site-packages..."
    for pkg_name in "pyqrllib" "pyqryptonight" "pyqrandomx"; do
        local install_dir="$site_packages/$pkg_name"
        if [[ -d "$install_dir" ]]; then
            print_info "  Removing: $install_dir"
            rm -rf "$install_dir"
        fi
    done
    echo ""

    print_info "Building all packages..."
    echo ""

    # Rebuild each package
    local failed_packages=()
    for pkg in "${packages_to_rebuild[@]}"; do
        local repo_name="${pkg%%:*}"
        local package_name="${pkg##*:}"

        if ! build_qrl_package "$repo_name" "$package_name" "$python_exec"; then
            failed_packages+=("$package_name")
        fi
        echo ""
    done

    # Summary
    echo ""
    print_info "========================================"
    print_info "Installation Summary"
    print_info "========================================"

    if [[ ${#failed_packages[@]} -eq 0 ]]; then
        print_success "All packages rebuilt successfully!"
        echo ""
        print_info "Running comprehensive verification..."
        echo ""

        # Test all packages together using the correct Python executable
        local verification_failed=false

        # Test pyqrllib
        print_info "Testing pyqrllib..."
        if "$python_exec" -c "import pyqrllib; from pyqrllib.pyqrllib import hstr2bin, bin2hstr; from pyqrllib import _pyqrllib; test = hstr2bin('48656c6c6f'); assert bin2hstr(test) == '48656c6c6f'; print('  ✓ pyqrllib functions work correctly')" 2>&1; then
            print_success "  pyqrllib verification passed"
        else
            print_error "  pyqrllib verification failed"
            verification_failed=true
        fi

        # Test pyqryptonight
        print_info "Testing pyqryptonight..."
        if "$python_exec" -c "import pyqryptonight; from pyqryptonight import _pyqryptonight; print('  ✓ pyqryptonight imported successfully')" 2>&1; then
            print_success "  pyqryptonight verification passed"
        else
            print_error "  pyqryptonight verification failed"
            verification_failed=true
        fi

        # Test pyqrandomx
        print_info "Testing pyqrandomx..."
        if "$python_exec" -c "import pyqrandomx; from pyqrandomx import _pyqrandomx; print('  ✓ pyqrandomx imported successfully')" 2>&1; then
            print_success "  pyqrandomx verification passed"
        else
            print_error "  pyqrandomx verification failed"
            verification_failed=true
        fi

        echo ""

        # Test QRL main module
        print_info "Testing QRL main module..."
        if "$python_exec" -c "from qrl.main import main; print('  ✓ QRL main module imported successfully')" 2>&1; then
            print_success "  QRL main module verification passed"
        else
            print_warning "  QRL main module import check failed"
            print_info "  Try running: $python_exec -c 'from qrl.main import main'"
            verification_failed=true
        fi

        echo ""

        # Verify Python version linkage
        print_info "Verifying Python version linkage..."
        echo ""

        local version_check_failed=false
        if ! check_package_python_version "pyqrllib" "_pyqrllib.so" "$python_exec"; then
            version_check_failed=true
        fi
        echo ""

        if ! check_package_python_version "pyqryptonight" "_pyqryptonight.so" "$python_exec"; then
            version_check_failed=true
        fi
        echo ""

        if ! check_package_python_version "pyqrandomx" "_pyqrandomx.so" "$python_exec"; then
            version_check_failed=true
        fi
        echo ""

        if [[ "$verification_failed" == false ]] && [[ "$version_check_failed" == false ]]; then
            print_success "All verification tests passed!"
            print_success "All modules correctly built for Python $python_version!"
            echo ""
            print_info "========================================"
            print_info "Next Steps"
            print_info "========================================"
            echo ""
            print_info "Start QRL:"
            print_info "  start_qrl"
            echo ""
            print_info "If everything is set up correctly, your QRL node will start running!"
        else
            if [[ "$version_check_failed" == true ]]; then
                print_error "Python version linkage verification failed!"
            fi
            print_warning "Some verification tests failed. See messages above for details."
        fi
    else
        print_error "The following packages failed to build:"
        for pkg in "${failed_packages[@]}"; do
            echo "  - $pkg"
        done
        echo ""
        print_info "Please check the error messages above and try rebuilding manually."
        print_info "See INSTALLING-MAC.md for manual rebuild instructions."
        exit 1
    fi
}

# Run main function
main "$@"
