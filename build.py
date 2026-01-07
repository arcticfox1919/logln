#!/usr/bin/env python3
"""
Logln Build Tool - Cross-platform build and test runner

Usage:
    python build.py [command] [options]

Commands:
    build       Build the library (default)
    test        Build and run tests
    clean       Clean build directory
    install     Build and install

Options:
    -d, --debug     Debug build (default: Release)
    -s, --shared    Build shared library (default: static)
    -e, --examples  Build examples
    -c, --clean     Clean before build
    -j, --jobs N    Parallel jobs (default: auto)
    -h, --help      Show help
"""

import argparse
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

# Project paths
ROOT = Path(__file__).parent.resolve()
BUILD_DIR = ROOT / "build"


def run(cmd, **kwargs):
    """Run command and return exit code."""
    print(f">>> {' '.join(cmd)}")
    return subprocess.call(cmd, **kwargs)


def cmake_configure(args):
    """Configure with CMake."""
    BUILD_DIR.mkdir(exist_ok=True)
    
    cmd = [
        "cmake", str(ROOT),
        f"-DLOGLN_BUILD_SHARED={'ON' if args.shared else 'OFF'}",
        f"-DLOGLN_BUILD_TESTS={'ON' if args.command == 'test' else 'OFF'}",
        f"-DLOGLN_BUILD_EXAMPLES={'ON' if args.examples else 'OFF'}",
    ]
    # CMAKE_BUILD_TYPE is only used by single-config generators (Makefile, Ninja)
    # Multi-config generators (Visual Studio, Xcode) use --config at build time
    if sys.platform != "win32":
        cmd.append(f"-DCMAKE_BUILD_TYPE={args.build_type}")
    return run(cmd, cwd=BUILD_DIR)


def cmake_build(args):
    """Build with CMake."""
    cmd = ["cmake", "--build", str(BUILD_DIR), "--config", args.build_type]
    if args.jobs:
        cmd += ["--parallel", str(args.jobs)]
    else:
        cmd += ["--parallel"]
    return run(cmd)


def cmake_install(args):
    """Install with CMake."""
    cmd = ["cmake", "--install", str(BUILD_DIR), "--config", args.build_type]
    if args.prefix:
        cmd += ["--prefix", args.prefix]
    return run(cmd)


def ctest_run(args):
    """Run tests with CTest."""
    cmd = [
        "ctest", "--test-dir", str(BUILD_DIR),
        "--config", args.build_type,
        "--output-on-failure",
    ]
    if args.verbose:
        cmd.append("--verbose")
    return run(cmd)


def clean():
    """Clean build directory."""
    if BUILD_DIR.exists():
        print(f"Removing {BUILD_DIR}")
        # Handle read-only files (e.g., .git objects)
        def remove_readonly(func, path, exc_info):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        # Python 3.12+ uses onexc, older versions use onerror
        if sys.version_info >= (3, 12):
            shutil.rmtree(BUILD_DIR, onexc=lambda f, p, e: remove_readonly(f, p, None))
        else:
            shutil.rmtree(BUILD_DIR, onerror=remove_readonly)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Logln Build Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python build.py                 # Build in Release mode
    python build.py test            # Build and run tests
    python build.py test -d         # Test in Debug mode
    python build.py -c -s           # Clean build, shared library
    python build.py install         # Build and install
""")
    
    parser.add_argument("command", nargs="?", default="build",
                        choices=["build", "test", "clean", "install"],
                        help="Command to run (default: build)")
    parser.add_argument("-d", "--debug", dest="build_type",
                        action="store_const", const="Debug", default="Release",
                        help="Debug build (default: Release)")
    parser.add_argument("-s", "--shared", action="store_true",
                        help="Build shared library")
    parser.add_argument("-e", "--examples", action="store_true",
                        help="Build examples")
    parser.add_argument("-c", "--clean", action="store_true",
                        help="Clean before build")
    parser.add_argument("-j", "--jobs", type=int, metavar="N",
                        help="Parallel jobs")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--prefix", metavar="PATH",
                        help="Install prefix")
    
    args = parser.parse_args()
    
    print(f"\n{'=' * 60}")
    print(f"  Logln Build Tool")
    print(f"{'=' * 60}")
    print(f"  Command:    {args.command}")
    print(f"  Build Type: {args.build_type}")
    print(f"  Library:    {'Shared' if args.shared else 'Static'}")
    print(f"  Examples:   {'Yes' if args.examples else 'No'}")
    print(f"{'=' * 60}\n")
    
    # Clean
    if args.command == "clean":
        return clean()
    
    if args.clean:
        clean()
    
    # Configure
    if (ret := cmake_configure(args)) != 0:
        return ret
    
    # Build
    if (ret := cmake_build(args)) != 0:
        return ret
    
    # Test
    if args.command == "test":
        if (ret := ctest_run(args)) != 0:
            print(f"\n{'=' * 60}")
            print("  Some tests FAILED!")
            print(f"{'=' * 60}\n")
            return ret
        print(f"\n{'=' * 60}")
        print("  All tests PASSED!")
        print(f"{'=' * 60}\n")
    
    # Install
    if args.command == "install":
        if (ret := cmake_install(args)) != 0:
            return ret
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
