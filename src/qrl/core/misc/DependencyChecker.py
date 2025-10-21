#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys
import os

try:
    from packaging.requirements import Requirement
    from importlib.metadata import version
    MODERN_PACKAGING = True
except ImportError:
    MODERN_PACKAGING = False

# Always import pkg_resources as fallback
try:
    import pkg_resources
except ImportError:
    pkg_resources = None


class DependencyChecker:
    @staticmethod
    def _get_requirements_path():
        return os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            os.path.pardir,
                                            os.path.pardir,
                                            os.path.pardir,
                                            os.path.pardir,
                                            "requirements.txt"))

    @staticmethod
    def check():
        requirements_path = DependencyChecker._get_requirements_path()

        requirements = []
        git_requirements = []
        with open(requirements_path, "r") as fp:
            for line in fp.readlines():
                line = line.strip("\n").strip()
                if line.startswith("#") or not line:
                    continue
                if line.startswith("git+"):
                    # Extract package name from git URL for separate validation
                    git_requirements.append(line)
                else:
                    requirements.append(line)

        try:
            # Check standard pip requirements
            if MODERN_PACKAGING:
                # Use modern packaging (preferred)
                for req_line in requirements:
                    try:
                        # Remove inline comments for parsing
                        clean_req = req_line.split('#')[0].strip()
                        if not clean_req:
                            continue
                        req = Requirement(clean_req)
                        # Check if package is installed
                        try:
                            version(req.name)
                        except Exception:
                            raise ImportError(f"Package {req.name} not found")
                        # Basic version checking could be added here if needed
                    except Exception as e:
                        raise ImportError(f"Requirement '{req_line}' not satisfied: {e}")
            else:
                # Fallback to pkg_resources
                if pkg_resources is None:
                    raise ImportError("Neither modern packaging nor pkg_resources is available")
                pkg_resources.require(requirements)

            # Check git-based requirements separately
            missing_git_packages = []
            for git_req in git_requirements:
                # Extract package name from git URL
                if "qrllib" in git_req:
                    package_name = "pyqrllib"
                elif "qryptonight" in git_req:
                    package_name = "pyqryptonight"
                elif "qrandomx" in git_req:
                    package_name = "pyqrandomx"
                else:
                    continue

                try:
                    __import__(package_name)
                except ImportError:
                    missing_git_packages.append(git_req)

            if missing_git_packages:
                raise ImportError(f"Git packages not installed: {', '.join(missing_git_packages)}")

        except Exception as e:
            sys.exit("dependencies not satisfied, run [pip3 install -r requirements.txt] first. \n {}".format(e))
