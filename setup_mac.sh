#!/bin/bash
set -e

# Get absolute path to project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Setting up project in: $PROJECT_ROOT"

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Create vendor directory
mkdir -p vendor
cd vendor

# Clone and build liboqs
if [ ! -d "liboqs" ]; then
    git clone --branch main https://github.com/open-quantum-safe/liboqs.git
fi

cd liboqs
mkdir -p build
cd build

# Clean any previous builds
rm -rf *

# Build liboqs with local installation path
cmake -GNinja .. \
    -DCMAKE_INSTALL_PREFIX="$PROJECT_ROOT/vendor/local" \
    -DOQS_USE_OPENSSL=OFF \
    -DBUILD_SHARED_LIBS=ON

ninja
ninja install

cd ../..

# Clone and build liboqs-python
if [ ! -d "liboqs-python" ]; then
    git clone --branch main https://github.com/open-quantum-safe/liboqs-python.git
fi

cd liboqs-python

# Set environment variables for build
export LIBOQS_INCLUDE_DIR="$PROJECT_ROOT/vendor/local/include"
export LIBOQS_LIB_DIR="$PROJECT_ROOT/vendor/local/lib"
export LD_LIBRARY_PATH="$PROJECT_ROOT/vendor/local/lib:$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$PROJECT_ROOT/vendor/local/lib:$DYLD_LIBRARY_PATH"

# Clean any previous builds
rm -rf build/

# Install liboqs-python
pip install -e .

cd ../..

# Create a .env file for environment variables
cat > .env << EOF
LIBOQS_INCLUDE_DIR="$PROJECT_ROOT/vendor/local/include"
LIBOQS_LIB_DIR="$PROJECT_ROOT/vendor/local/lib"
LD_LIBRARY_PATH="$PROJECT_ROOT/vendor/local/lib:\$LD_LIBRARY_PATH"
DYLD_LIBRARY_PATH="$PROJECT_ROOT/vendor/local/lib:\$DYLD_LIBRARY_PATH"
EOF

echo "Setup completed successfully!"
echo "To activate the environment, run:"
echo "source env_setup.sh"