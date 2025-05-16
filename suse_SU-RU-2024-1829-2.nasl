#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-SUSE-RU-2024:1829-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207549);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/21");

  script_cve_id("CVE-2023-52323");
  script_xref(name:"SuSE", value:"SUSE-RU-2024:1829-2");

  script_name(english:"SUSE SLES15 : Recommended update for python-aliyun-python-sdk, python-aliyun-python-sdk-aas, python-aliyun-python-sdk-acm, python-aliyun-python-sdk-acms-open, python-aliyun-python-sdk-actiontrail, python-aliyun-python-sdk-adb, python-aliyun-python-sdk-adcp, python-aliyun-python-sdk-address-purification, python-aliyun-python-sdk-aegis, python-aliyun-python-sdk-afs, python-aliyun-python-sdk-aigen, python-aliyun-python-sdk-aimiaobi, python-aliyun-python-sdk-airec, python-aliyun-python-sdk-airticketopen, python-aliyun-python-sdk-alb, python-aliyun-python-sdk-alidns, python-aliyun-python-sdk-aligreen-console, python-aliyun-python-sdk-alikafka, python-aliyun-python-sdk-alimt, python-aliyun-python-sdk-alinlp, python-aliyun-python-sdk-aliyuncvc, python-aliyun-python-sdk-amptest, python-aliyun-python-sdk-amqp-open, python-aliyun-python-sdk-antiddos-public, python-aliyun-python-sdk-apds (SUSE-SU-SUSE-RU-2024:1829-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by a vulnerability as referenced
in the SUSE-SU-SUSE-RU-2024:1829-2 advisory.

    Changes in python-aliyun-python-sdk:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Add new Aliyun SDK component packages to Requires

    Changes in python-aliyun-python-sdk-aas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Do not build for Python 2 distros 15 and higher

    - Add ChangeLog.txt from upstream git
    - Add python-cryptography to BuildRequires
    - Drop python-devel from BuildRequires
    - Drop obsolete Group field

    Changes in python-aliyun-python-sdk-acm:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-acms-open:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-actiontrail:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.2.0
      + Version 2.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-adb:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.10
      + Version 1.1.9
      + Version 1.1.8
      + Version 1.1.7
      + Version 1.1.6
      + Version 1.1.5
      + Version 1.0.9
      + Version 1.0.7
      + Version 1.0.6
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-adcp:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-address-purification:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-aegis:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-afs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-aigen:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-aimiaobi:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-airec:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.1.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-airticketopen:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.0.3
      + Version 3.0.0
      + Version 2.0.1
      + Version 1.0.6
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-alb:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.16
      + Version 1.0.15
      + Version 1.0.14
      + Version 1.0.13
      + Version 1.0.12
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.8

    Changes in python-aliyun-python-sdk-alidns:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.0.7
      + Version 3.0.1
      + Version 3.0.0
      + Version 2.6.32
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-aligreen-console:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-alikafka:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.6
      + Version 1.0.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.4

    Changes in python-aliyun-python-sdk-alimt:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.2.0
      + Version 3.1.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-alinlp:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.24
      + Version 1.0.23
      + Version 1.0.22
      + Version 1.0.21
      + Version 1.0.20
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-aliyuncvc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-amptest:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-amqp-open:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.4
      + Version 1.1.3
      + Version 1.1.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Do not build for Python 2 distros 15 and higher

    - Add ChangeLog.txt from upstream git
    - Drop python-devel from BuildRequires
    - Drop obsolete Group field

    Changes in python-aliyun-python-sdk-antiddos-public:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-apds:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-appmallsservice:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-appstream-center:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-aps:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-arms:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.7.30
      + Version 2.7.29
      + Version 2.7.26
      + Version 2.7.25
      + Version 2.7.24
      + Version 2.7.22
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-arms4finance:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-avatar:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.0.7
      + Version 2.0.6
      + Version 2.0.5
      + Version 2.0.4
      + Version 2.0.3
      + Version 2.0.2
      + Version 2.0.1
      + Version 2.0.0
      + Version 1.0.23
      + Version 1.0.22
      + Version 1.0.21
      + Version 1.0.18
      + Version 1.0.15
      + Version 1.0.13
      + Version 1.0.12
      + Version 1.0.11
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.9

    Changes in python-aliyun-python-sdk-baas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-bpstudio:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.4
      + Version 1.0.3
      + Version 1.0.2
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-brinekingdom:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-bss:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-bssopenapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-btripopen:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-cams:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.9
      + Version 1.0.8
      + Version 1.0.7
      + Version 1.0.6
      + Version 1.0.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-captcha:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-cas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.18
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-cassandra:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-cbn:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.41
      + Version 1.0.40
      + Version 1.0.39
      + Version 1.0.38
      + Version 1.0.37
      + Version 1.0.32
      + Version 1.0.31
      + Version 1.0.30
      + Version 1.0.29
      + Version 1.0.28
      + Version 1.0.26
      + Version 1.0.25
      + Version 1.0.24
      + Version 1.0.21
      + Version 1.0.14
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-cc5g:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.7
      + Version 1.0.6
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.3

    Changes in python-aliyun-python-sdk-ccc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.10.3
      + Version 2.10.2
      + Version 2.4.3
      + Version 2.3.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-cciotgw:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.1

    Changes in python-aliyun-python-sdk-ccs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cdn:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.8.8
      + Version 3.8.7
      + Version 3.8.1
      + Version 3.8.0
      + Version 3.7.10
      + Version 3.7.8
      + Version 3.7.7
      + Version 3.7.5
      + Version 3.7.4
      + Version 3.7.2
      + Version 3.7.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-cdrs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-chatbot:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-clickhouse:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.1.5
      + Version 3.1.4
      + Version 3.1.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-cloud-siem:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.2
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-cloudapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cloudauth:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.35
      + Version 2.0.33
      + Version 2.0.31
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-cloudauth-console:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 2.0.0

    Changes in python-aliyun-python-sdk-cloudesl:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.1.1
      + Version 2.0.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-cloudgame:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cloudmarketing:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cloudphone:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-cloudphoto:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cloudwf:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cms:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 7.0.33
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 7.0.32
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 7.0.30
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-codeup:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 0.1.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-companyreg:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.2.5
      + Version 1.2.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-computenest:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-computenestsupplier:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.5
      + Version 1.0.4
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-config:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.2.12
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.2.11
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.2.10
      + Version 2.2.9
      + Version 2.2.8
      + Version 2.2.3
      + Version 2.2.2
      + Version 2.2.1
      + Version 2.2.0
      + Version 2.1.5
      + Version 2.0.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-core:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.15.1
      + Version 2.15.0
      + Version 2.14.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Add patch to relax version constraint for python-jmespath build dependency

    - New upstream release
      + Version 2.13.36
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package
    - Drop patches for issues fixed upstream
    - Refresh and rename patches

    Changes in python-aliyun-python-sdk-cr:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-crm:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-csas:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - New upstream release
      + Version 1.0.4
      + Version 1.0.3
      + Version 1.0.2
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-csb:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cspro:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-cusanalytic_sc_online:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-das:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.36
      + Version 2.0.35
      + Version 2.0.32
      + Version 1.0.29
      + Version 1.0.27
      + Version 1.0.25
      + Version 1.0.20
      + Version 1.0.10
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dataphin-public:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - New upstream release
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-dataworks-public:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 5.0.1
      + Version 5.0.0
      + Version 4.2.13
      + Version 4.2.12
      + Version 4.2.11
      + Version 4.2.8
      + Version 4.2.7
      + Version 4.1.5
      + Version 4.1.2
      + Version 4.1.0
      + Version 3.4.23
      + Version 3.4.22
      + Version 3.4.21
      + Version 3.4.19
      + Version 3.4.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dbfs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.7
      + Version 2.0.6
      + Version 2.0.5
      + Version 2.0.4
      + Version 2.0.2
      + Version 2.0.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dbs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.36
      + Version 1.0.35
      + Version 1.0.34
      + Version 1.0.33
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dcdn:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.2.18
      + Version 2.2.17
      + Version 2.2.16
      + Version 2.2.15
      + Version 2.2.14
      + Version 2.2.10
      + Version 2.2.9
      + Version 2.2.8
      + Version 2.2.6
      + Version 2.2.5
      + Version 2.2.4
      + Version 2.2.3
      + Version 2.2.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ddosbgp:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Fix missing installation of ChangeLog.txt in %prep section
    - Fix file pattern for %{python_sitelib} in %files section

    - Initial build
      + Version 1.0.1

    Changes in python-aliyun-python-sdk-ddoscoo:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.5
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ddosdiversion:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-dds:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.7.17
      + Version 3.7.16
      + Version 3.7.15
      + Version 3.7.14
      + Version 3.7.13
      + Version 3.7.12
      + Version 3.7.11
      + Version 3.7.10
      + Version 3.7.9
      + Version 3.7.5
      + Version 3.7.4
      + Version 3.7.3
      + Version 3.7.2
      + Version 3.7.1
      + Version 3.7.0
      + Version 3.6.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-democenter:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-devops-rdc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dg:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.10
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dms-enterprise:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.53.7
      + Version 1.53.6
      + Version 1.53.5
      + Version 1.53.4
      + Version 1.53.2
      + Version 1.53.1
      + Version 1.53.0
      + Version 1.52.0
      + Version 1.51.0
      + Version 1.50.0
      + Version 1.49.0
      + Version 1.48.0
      + Version 1.44.0
      + Version 1.43.0
      + Version 1.42.0
      + Version 1.41.0
      + Version 1.40.0
      + Version 1.38.0
      + Version 1.37.0
      + Version 1.28.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-documentautoml:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-domain:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.14.9
      + Version 3.14.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-domain-intl:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-drds:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 20210523.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 20210523.0.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dt-oc-info:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-dts:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 5.1.29
      + Version 5.1.28
      + Version 5.1.27
      + Version 5.1.26
      + Version 5.1.25
      + Version 5.1.23
      + Version 5.1.21
      + Version 5.1.19
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dybaseapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dyplsapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.3.5
      + Version 1.3.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dypnsapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.11
      + Version 1.1.10
      + Version 1.1.9
      + Version 1.1.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dypnsapi-intl:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-dysmsapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.1.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-dytnsapi:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.8
      + Version 1.1.7
      + Version 1.1.2
      + Version 1.1.1
      + Version 1.1.0
      + Version 1.0.9
      + Version 1.0.8
      + Version 1.0.7
      + Version 1.0.6
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.4

    Changes in python-aliyun-python-sdk-dyvmsapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.2.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-eais:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.1.4
      + Version 2.1.3
      + Version 2.1.2
      + Version 2.1.1
      + Version 2.1.0
      + Version 2.0.5
      + Version 2.0.4
      + Version 2.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-eas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 0.0.9
      + Version 0.0.8
      + Version 0.0.7
      + Version 0.0.6
      + Version 0.0.5
      + Version 0.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ebs:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.3.7

    Changes in python-aliyun-python-sdk-ecd:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-eci:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.3.0
      + Version 1.2.9
      + Version 1.2.8
      + Version 1.2.5
      + Version 1.2.4
      + Version 1.2.2
      + Version 1.1.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ecs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 4.24.71
      + Version 4.24.69
      + Version 4.24.68
      + Version 4.24.67
      + Version 4.24.66
      + Version 4.24.65
      + Version 4.24.64
      + Version 4.24.63
      + Version 4.24.62
      + Version 4.24.26
      + Version 4.24.25
      + Version 4.24.24
      + Version 4.24.23
      + Version 4.24.22
      + Version 4.24.13
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ecs-workbench:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - New upstream release
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-edas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.26.9
      + Version 3.26.8
      + Version 3.26.6
      + Version 3.26.5
      + Version 3.23.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-eflo:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.12
      + Version 1.0.10
      + Version 1.0.9
      + Version 1.0.7
      + Version 1.0.6
      + Version 1.0.5
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-eflo-controller:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.3
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-ehpc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.14.21
      + Version 1.14.20
      + Version 1.14.19
      + Version 1.14.18
      + Version 1.14.17
      + Version 1.14.16
      + Version 1.14.15
      + Version 1.14.14
      + Version 1.14.12
      + Version 1.14.10
      + Version 1.14.9
      + Version 1.14.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-eipanycast:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.5
      + Version 1.0.4
      + Version 1.0.3
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.1

    Changes in python-aliyun-python-sdk-elasticsearch:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.1.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 3.0.29
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-emap:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-emas-appmonitor:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-emr:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.3.10
      + Version 3.3.6
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-emrstudio:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-ens:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.0.14
      + Version 3.0.13
      + Version 3.0.12
      + Version 3.0.11
      + Version 3.0.10
      + Version 3.0.9
      + Version 3.0.8
      + Version 3.0.7
      + Version 3.0.6
      + Version 3.0.5
      + Version 3.0.4
      + Version 3.0.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-es-serverless:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-ess:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.3.19
      + Version 2.3.17
      + Version 2.3.16
      + Version 2.3.14
      + Version 2.3.13
      + Version 2.3.12
      + Version 2.3.11
      + Version 2.3.10
      + Version 2.3.9
      + Version 2.3.7
      + Version 2.3.6
      + Version 2.3.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-et-industry-openapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-eventbridge:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.14
      + Version 1.0.11
      + Version 1.0.10
      + Version 1.0.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.8

    Changes in python-aliyun-python-sdk-faas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-facebody:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.13
      + Version 2.0.12
      + Version 2.0.11
      + Version 2.0.10
      + Version 2.0.6
      + Version 2.0.5
      + Version 2.0.4
      + Version 1.2.35
      + Version 1.2.34
      + Version 1.2.33
      + Version 1.2.32
      + Version 1.2.30
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-fnf:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.8.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.8.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-foas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.11.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ft:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-ga:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.19
      + Version 1.0.17
      + Version 1.0.15
      + Version 1.0.14
      + Version 1.0.13
      + Version 1.0.12
      + Version 1.0.11
      + Version 1.0.10
      + Version 1.0.7
      + Version 1.0.6
      + Version 1.0.5
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.3

    Changes in python-aliyun-python-sdk-gdb:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-geoip:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-goodstech:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-gpdb:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.7
      + Version 1.1.6
      + Version 1.1.5
      + Version 1.1.4
      + Version 1.1.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-grace:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-green:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.6.6
      + Version 3.6.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-gts-phd:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-hbase:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.9.9
      + Version 2.9.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-hbr:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.2.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.2.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-hcs-mgw:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-highddos:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-hiknoengine:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-hitsdb:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.1.15
      + Version 3.1.14
      + Version 3.1.13
      + Version 3.0.8
      + Version 3.0.7
      + Version 3.0.6
      + Version 3.0.4
      + Version 3.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-hivisengine:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-hpc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-hsm:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-httpdns:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-ice:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.2

    Changes in python-aliyun-python-sdk-idaas-doraemon:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-idrsservice:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-idsp:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-imageaudit:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-imageenhan:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.12
      + Version 1.1.11
      + Version 1.1.9
      + Version 1.1.7
      + Version 1.1.6
      + Version 1.1.5
      + Version 1.1.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-imageprocess:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.7
      + Version 2.0.6
      + Version 2.0.5
      + Version 2.0.1
      + Version 2.0.0
      + Version 1.0.31
      + Version 1.0.30
      + Version 1.0.29
      + Version 1.0.28
      + Version 1.0.27
      + Version 1.0.26
      + Version 1.0.25
      + Version 1.0.16
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-imagerecog:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.19
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.18
      + Version 1.0.17
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-imagesearch:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-imageseg:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.13
      + Version 1.1.12
      + Version 1.1.11
      + Version 1.1.10
      + Version 1.1.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-imarketing:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 5.0.2

    Changes in python-aliyun-python-sdk-imgsearch:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-imm:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.1.17
      + Version 2.1.16
      + Version 2.1.15
      + Version 1.24.0
      + Version 1.23.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-industry-brain:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-iot:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 8.59.0
      + Version 8.58.0
      + Version 8.57.0
      + Version 8.56.0
      + Version 8.55.0
      + Version 8.53.0
      + Version 8.49.0
      + Version 8.48.0
      + Version 8.47.0
      + Version 8.45.0
      + Version 8.44.0
      + Version 8.43.0
      + Version 8.42.0
      + Version 8.41.0
      + Version 8.33.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-iotcc:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 2.0.2

    Changes in python-aliyun-python-sdk-iqa:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-ivision:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.2.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ivpd:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-jaq:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-jarvis:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-jarvis-public:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-kms:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.16.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.16.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.16.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.15.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ledgerdb:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-linkedmall:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-linkface:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-linkvisual:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.5.8

    Changes in python-aliyun-python-sdk-linkwan:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-live:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.9.49
      + Version 3.9.45
      + Version 3.9.43
      + Version 3.9.41
      + Version 3.9.40
      + Version 3.9.39
      + Version 3.9.38
      + Version 3.9.37
      + Version 3.9.31
      + Version 3.9.30
      + Version 3.9.27
      + Version 3.9.23
      + Version 3.9.22
      + Version 3.9.19
      + Version 3.9.14
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ltl:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-lto:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-lubancloud:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-market:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-maxcompute:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - New upstream release
      + Version 1.0.3
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-metering:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-mns-open:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.1

    Changes in python-aliyun-python-sdk-moguan-sdk:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.1.0

    Changes in python-aliyun-python-sdk-mopen:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-mpaas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-msccommonquery:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 0.0.1

    Changes in python-aliyun-python-sdk-mse:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.0.24
      + Version 3.0.23
      + Version 3.0.21
      + Version 3.0.19
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 3.0.6

    Changes in python-aliyun-python-sdk-mts:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.3.41
      + Version 3.3.40
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-multimediaai:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-nas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.14.2
      + Version 3.14.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-netana:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-nis:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-nlb:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.12
      + Version 1.0.11
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.10

    Changes in python-aliyun-python-sdk-nlp-automl:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 0.0.15
      + Version 0.0.13
      + Version 0.0.10
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-nls-cloud-meta:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-objectdet:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.16
      + Version 1.0.15
      + Version 1.0.14
      + Version 1.0.13
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-oceanbasepro:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.15
      + Version 1.0.14
      + Version 1.0.12
      + Version 1.0.11
      + Version 1.0.10
      + Version 1.0.9
      + Version 1.0.8
      + Version 1.0.7
      + Version 1.0.5
      + Version 1.0.4
      + Version 1.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.2

    Changes in python-aliyun-python-sdk-ocr:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.25
      + Version 1.0.24
      + Version 1.0.23
      + Version 1.0.22
      + Version 1.0.21
      + Version 1.0.20
      + Version 1.0.19
      + Version 1.0.18
      + Version 1.0.13
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ocs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-oms:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ons:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.2.3
      + Version 3.2.2
      + Version 3.2.1
      + Version 3.1.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-onsmqtt:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-oos:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.5.15
      + Version 1.5.13
      + Version 1.5.11
      + Version 1.5.10
      + Version 1.5.9
      + Version 1.5.8
      + Version 1.5.7
      + Version 1.5.6
      + Version 1.5.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-openanalytics:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-openanalytics-open:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-openitag:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-opensearch:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 0.12.2
      + Version 0.12.1
      + Version 0.12.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ossadmin:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-ots:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-outboundbot:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.6.2
      + Version 1.6.1
      + Version 1.6.0
      + Version 1.5.0
      + Version 1.2.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-pai-dsw:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-paielasticdatasetaccelerator:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-paifeaturestore:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - New upstream release
      + Version 1.0.11
      + Version 1.0.7
      + Version 1.0.6
      + Version 1.0.5
      + Version 1.0.3
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.1

    Changes in python-aliyun-python-sdk-pairecservice:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - New upstream release
      + Version 1.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Fix missing installation of ChangeLog.txt in %prep section
    - Fix file pattern for %{python_sitelib} in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-paistudio:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-petadata:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-polardb:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.8.47
      + Version 1.8.46
      + Version 1.8.45
      + Version 1.8.44
      + Version 1.8.43
      + Version 1.8.42
      + Version 1.8.37
      + Version 1.8.36
      + Version 1.8.35
      + Version 1.8.34
      + Version 1.8.33
      + Version 1.8.32
      + Version 1.8.31
      + Version 1.8.30
      + Version 1.8.29
      + Version 1.8.24
      + Version 1.8.23
      + Version 1.8.22
      + Version 1.8.21
      + Version 1.8.20
      + Version 1.8.18
      + Version 1.8.15
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-polardbx:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-privatelink:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.8
      + Version 1.0.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-productcatalog:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-pts:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-push:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.13.14
      + Version 3.13.13
      + Version 3.13.12
      + Version 3.13.11
      + Version 3.13.10
      + Version 3.13.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-pvtz:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.3.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-qualitycheck:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 4.7.1
      + Version 4.1.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-quickbi-public:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.1.5
      + Version 2.1.3
      + Version 2.1.2
      + Version 2.1.1
      + Version 2.0.2
      + Version 1.8.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-quotas:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.2
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-r-kvstore:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.20.11
      + Version 2.20.10
      + Version 2.20.9
      + Version 2.20.8
      + Version 2.20.7
      + Version 2.20.6
      + Version 2.20.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-ram:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.3.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-rdc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-rds:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.7.43
      + Version 2.7.31
      + Version 2.7.28
      + Version 2.7.24
      + Version 2.7.21
      + Version 2.7.16
      + Version 2.7.15
      + Version 2.7.10
      + Version 2.7.8
      + Version 2.7.7
      + Version 2.7.6
      + Version 2.7.5
      + Version 2.7.3
      + Version 2.7.2
      + Version 2.7.1
      + Version 2.7.0
      + Version 2.6.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-rds-data:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-reid:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-reid_cloud:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.2.2

    Changes in python-aliyun-python-sdk-resourcecenter:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.3
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.1

    Changes in python-aliyun-python-sdk-resourcemanager:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.2.6
      + Version 1.2.5
      + Version 1.2.4
      + Version 1.2.3
      + Version 1.2.2
      + Version 1.2.1
      + Version 1.2.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-resourcesharing:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.1

    Changes in python-aliyun-python-sdk-retailcloud:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.20
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-risk:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-ros:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-rsimganalys:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 4.3.1

    Changes in python-aliyun-python-sdk-rtc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.3.5
      + Version 1.3.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-sae:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.22.15
      + Version 1.22.9
      + Version 1.22.6
      + Version 1.22.5
      + Version 1.20.1
      + Version 1.18.16
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-saf:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-safconsole:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-sas:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.3
      + Version 2.0.2
      + Version 2.0.0
      + Version 1.1.32
      + Version 1.1.31
      + Version 1.1.30
      + Version 1.1.29
      + Version 1.1.27
      + Version 1.1.26
      + Version 1.1.24
      + Version 1.1.23
      + Version 1.1.21
      + Version 1.1.10
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-sas-api:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-sasti:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-scdn:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.2.9
      + Version 2.2.8
      + Version 2.2.7
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-schedulerx2:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.12
      + Version 1.1.11
      + Version 1.1.10
      + Version 1.1.9
      + Version 1.1.5
      + Version 1.1.4
      + Version 1.1.2
      + Version 1.0.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-scsp:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-sddp:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.10
      + Version 1.0.8
      + Version 1.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-servicemesh:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-sgw:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-slb:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.3.21
      + Version 3.3.20
      + Version 3.3.19
      + Version 3.3.18
      + Version 3.3.17
      + Version 3.3.16
      + Version 3.3.10
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-sls:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-smartag:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-smarthosting:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-smartsales:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-smc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-snsuapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-status:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-sts:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.1.2
      + Version 3.1.1
      + Version 3.1.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-swas-open:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.6
      + Version 1.0.5
      + Version 1.0.4
      + Version 1.0.3
      + Version 1.0.2
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-tag:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.5
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.2
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-tdsr:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-teambition-aliyun:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-tesladam:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-teslamaxcompute:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-teslastream:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-threedvision:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.3

    Changes in python-aliyun-python-sdk-tingwu:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions

    - New upstream release
      + Version 1.0.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-trademark:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-ubsms:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-uis:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-unimkt:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.4.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 2.4.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-vcs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-ververica:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.2

    Changes in python-aliyun-python-sdk-viapi:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-viapi-oxs-cross:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-viapi-regen:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.4

    Changes in python-aliyun-python-sdk-viapiutils:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-videoenhan:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.23
      + Version 1.0.22
      + Version 1.0.21
      + Version 1.0.20
      + Version 1.0.19
      + Version 1.0.18
      + Version 1.0.17
      + Version 1.0.14
      + Version 1.0.12
      + Version 1.0.11
      + Version 1.0.10
      + Version 1.0.9
      + Version 1.0.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-videorecog:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.9
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 1.0.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-videosearch:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-videoseg:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-visionai:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-visionai-poc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-vod:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.16.21
      + Version 2.16.19
      + Version 2.16.17
      + Version 2.16.16
      + Version 2.16.12
      + Version 2.16.11
      + Version 2.16.10
      + Version 2.16.9
      + Version 2.16.8
      + Version 2.16.5
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-voicenavigator:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.7.0
      + Version 1.6.0
      + Version 1.5.0
      + Version 1.2.0
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-vpc:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.0.45
      + Version 3.0.44
      + Version 3.0.42
      + Version 3.0.41
      + Version 3.0.40
      + Version 3.0.38
      + Version 3.0.33
      + Version 3.0.31
      + Version 3.0.30
      + Version 3.0.29
      + Version 3.0.27
      + Version 3.0.26
      + Version 3.0.25
      + Version 3.0.24
      + Version 3.0.22
      + Version 3.0.19
      + Version 3.0.18
      + Version 3.0.17
      + Version 3.0.16
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-vpcpeer:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.0.3
      + Version 1.0.2
      + Version 1.0.1
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-vs:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.10.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-waf-openapi:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 1.1.9
      + Version 1.1.8
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-webplus:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-welfare-inner:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-wfts:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 1.0.0

    Changes in python-aliyun-python-sdk-workbench-ide:

    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - Initial build
      + Version 2.0.5

    Changes in python-aliyun-python-sdk-workorder:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 3.1.4
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    - New upstream release
      + Version 3.1.3
      + For detailed information about changes see the
        ChangeLog.txt file provided with this package

    Changes in python-aliyun-python-sdk-xspace:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-xtrace:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-yundun:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-aliyun-python-sdk-yundun-ds:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    Changes in python-crcmod:
    - Switch package to modern Python Stack on SLE-15
      + Add %{?sle15_python_module_pythons}
    - Switch to autosetup and pyproject macros.
    - Add patch to Switch to setuptools to build, rather than distutils.
    - Stop using greedy globs in %files.

    - Replace python-base with python-devel in BuildRequires (bsc#1203453)
    - Run spec-cleaner

    Changes in python-oss2:
    - Switch package to modern Python Stack on SLE-15
      + Use Python 3.11 on SLE-15 by default
      + Add Obsoletes for old python3 package on SLE-15
      + Drop support for older Python versions
    - Switch build system from setuptools to pyproject.toml
      + Add python-pip and python-wheel to BuildRequires
      + Replace %python_build with %pyproject_wheel
      + Replace %python_install with %pyproject_install
    - Limit Python files matched in %files section

    - New upstream release
      + Version 2.18.4
      + For detailed information about changes see the
        CHANGELOG.rst file provided with this package
    - Refresh patches for new version
    - Replace deprecated %patchN with %patch -PN for compatibility with RPM 4.20

    - New upstream release
      + Version 2.18.1
      + For detailed information about changes see the
        CHANGELOG.rst file provided with this package

    - Refresh patches for new version

    - New upstream release
      + Version 2.18.0
      + Version 2.17.0
      + For detailed information about changes see the
        CHANGELOG.rst file provided with this package

    - Add patch to switch from external mock to unittest.mock
    - Drop python-mock from BuildRequires

    - New upstream release
      + Version 2.16.0
      + For detailed information about changes see the
        CHANGELOG.rst file provided with this package

    - Use nose2 for unit testing

    - New upstream release
      + Version 2.15.0
      + For detailed information about changes see the
        CHANGELOG.rst file provided with this package

    Changes in python-pycryptodome:
    - update to 3.20.0:
      * Added support for TurboSHAKE128 and TurboSHAKE256.
      * Added method Crypto.Hash.new() to generate a hash object
        given a hash name.
      * Added support for AES-GCM encryption of PBES2 and PKCS#8
        containers.
      * Added support for SHA-2 and SHA-3 algorithms in PBKDF2 when
        creating PBES2 and PKCS#8 containers.
      * Export of RSA keys accepts the prot_params dictionary as
        parameter to control the number of iterations for PBKDF2 and
        scrypt.
      * C unit tests also run on non-x86 architectures.
      * GH#787: Fixed autodetect logic for GCC 14 in combination with
        LTO.

    - update to 3.19.1 (bsc#1218564, CVE-2023-52323):
      * Fixed a side-channel leakage with OAEP decryption that could be
        exploited to carry out a Manger attack

    - update to 3.19.0:
      * The ``update()`` methods of TupleHash128 and TupleHash256
        objects can now hash multiple items (byte strings) at once.
      * Added support for ECDH, with ``Crypto.Protocol.DH``.
      * GH#754: due to a bug in ``cffi``, do not use it on Windows
        with Python 3.12+.

    - Add %{?sle15_python_module_pythons}

    - update to 3.18.0:
      * Added support for DER BOOLEAN encodings.
      * The library now compiles on Windows ARM64. Thanks to Niyas
        Sait.
      * GH#722: ``nonce`` attribute was not correctly set for
        XChaCha20_Poly1305 ciphers. Thanks to Liam Haber.
      * GH#728: Workaround for a possible x86 emulator bug in Windows
        for ARM64.
      * GH#739: OID encoding for arc 2 didn't accept children larger
        than 39. Thanks to James.
      * Correctly check that the scalar matches the point when
        importing an ECC private key.

    - Fix %%files to work with %pyproject_ style building.

    - update to 3.17.0:
      * Added support for the Counter Mode KDF defined in SP 800-108
        Rev 1.
      * Reduce the minimum tag length for the EAX cipher to 2 bytes.
      * An RSA object has 4 new properties for the CRT coefficients:
        ``dp``, ``dq``, ``invq`` and ``invq`` (``invp`` is the same
        value  as the existing ``u``).
      * GH#526: improved typing for ``RSA.construct``.
      * GH#534: reduced memory consumption when using a large number
        of cipher objects.
      * GH#598: fixed missing error handling for
        ``Util.number.inverse``.
      * GH#629: improved typing for ``AES.new`` and the various
        mode-specific types it returns. Thanks to Greg Werbin.
      * GH#653: added workaround for an alleged GCC compiler bug
        that affected Ed25519 code compiled for AVX2.
      * GH#658: attribute ``curve`` of an ECC key was not always
        the preferred curve name, as it used to be in v3.15.0
        (independently of the curve name specified when generating
        the key).
      * GH#637: fixed typing for legacy modules ``PKCS1_v1_5`` and
        ``PKCS1_PSS``, as their ``verify()`` returned a boolean.
      * GH#664: with OCB mode, nonces of maximum length (15 bytes)
        were actually used as 14 bytes nonces.
        After this fix, data that was encrypted in past using the
        (default) nonce length of 15 bytes can still be decrypted
        by reducing the nonce to its first 14 bytes.
      * GH#705: improved typing for ``nonce``, ``iv``, and ``IV``
        parameters of cipher objects.

    - update to 3.17.0:
      * ++++++++++++++++++++++++++
      * New features
      * Added support for the Counter Mode KDF defined in SP 800-108
        Rev 1.
      * Reduce the minimum tag length for the EAX cipher to 2 bytes.
      * An RSA object has 4 new properties for the CRT coefficients
      * ``dp``, ``dq``, ``invq`` and ``invq`` (``invp`` is the same
        value
      * as the existing ``u``).
      * Resolved issues
      * GH#526: improved typing for ``RSA.construct``.
      * GH#534: reduced memory consumption when using a large number
      * of cipher objects.
      * GH#598: fixed missing error handling for
        ``Util.number.inverse``.
      * GH#629: improved typing for ``AES.new`` and the various
      * mode-specific types it returns. Thanks to Greg Werbin.
      * GH#653: added workaround for an alleged GCC compiler bug
      * hat affected Ed25519 code compiled for AVX2.
      * GH#658: attribute ``curve`` of an ECC key was not always
      * he preferred curve name, as it used to be in v3.15.0
      * independently of the curve name specified when generating
      * he key).
      * GH#637: fixed typing for legacy modules ``PKCS1_v1_5`` and
        ``PKCS1_PSS``,
      * as their ``verify()`` returned a boolean.
      * GH#664: with OCB mode, nonces of maximum length (15 bytes
      * were actually used as 14 bytes nonces.
      * After this fix, data that was encrypted in past using the
      * default) nonce length of 15 bytes can still be decrypted
      * by reducing the nonce to its first 14 bytes.
      * GH#705: improved typing for ``nonce``, ``iv``, and ``IV``
        parameters
      * of cipher objects.
      * Other changes
      * Build PyPy wheels only for versions 3.8 and 3.9, and not for
        3.7 anymore.

    - Update to version 3.16.0
      * New features
        Build wheels for musl Linux. Thanks to Ben Raz.
      * Resolved issues
        GH#639: ARC4 now also works with 'keys' as short as 8 bits.
        GH#669: fix segfaults when running in a manylinux2010 i686 image.

    - update to 3.15.0:
      * Add support for curves Ed25519 and Ed448, including export and import of keys.
      * Add support for EdDSA signatures.
      * Add support for Asymmetric Key Packages (RFC5958) to import private keys.
      * GH#620: for Crypto.Util.number.getPrime , do not sequentially scan numbers searching for a prime.

    - do not use setup.py test construct
      https://trello.com/c/me9Z4sIv/121-setuppy-test-leftovers

    - update to 3.14.1:
      * GH#595: Fixed memory leak for GMP integers.
      * Add support for curve NIST P-192.
      * Add support for curve NIST P-224.
      * GH#590: Fixed typing info for ``Crypto.PublicKey.ECC``.
      * Relaxed ECDSA requirements for FIPS 186 signatures and accept any SHA-2 or
      * SHA-3 hash.  ``sign()`` and ``verify()`` will be performed even if the hash is stronger
        than the ECC key.

    - update to 3.12.0:
      * ECC keys in the SEC1 format can be exported and imported.
      * Add support for KMAC128, KMAC256, TupleHash128, and TupleHash256 (NIST SP-800 185).
      * Add support for KangarooTwelve.
      * GH#563: An asymmetric key could not be imported as a ``memoryview``.
      * GH#566: cSHAKE128/256 generated a wrong output for customization strings
      * GH#582: CBC decryption generated the wrong plaintext when the input and the output were the same
    buffer.

    - update to 3.11.0:
      * GH#512: Especially for very small bit sizes, ``Crypto.Util.number.getPrime()`` was
        occasionally generating primes larger than given the bit size.
      * GH#552: Correct typing annotations for ``PKCS115_Cipher.decrypt()``.
      * GH#555: ``decrypt()`` method of a PKCS#1v1.5 cipher returned a ``bytearray`` instead of ``bytes``.
      * GH#557: External DSA domain parameters were accepted even when the modulus (``p``) was not prime.
        This affected ``Crypto.PublicKey.DSA.generate()`` and ``Crypto.PublicKey.DSA.construct()``.
      * Added cSHAKE128 and cSHAKE256 (of SHA-3 family).
      * GH#558: The flag RTLD_DEEPBIND passed to ``dlopen()`` is not well supported by
        `address sanitizers <https://github.com/google/sanitizers/issues/611>`_.
        It is now possible to set the environment variable ``PYCRYPTDOME_DISABLE_DEEPBIND``
        to drop that flag and allow security testing.

    - update to 3.10.1:
      * Fixed a potential memory leak when initializing block ciphers.
      * GH#466: ``Crypto.Math.miller_rabin_test()`` was still using the system random
        source and not the one provided as parameter.
      * GH#469: RSA objects have the method ``public_key()`` like ECC objects.
        The old method ``publickey()`` is still available for backward compatibility.
      * GH#476: ``Crypto.Util.Padding.unpad()`` was raising an incorrect exception
        in case of zero-length inputs. Thanks to Captainowie.
      * GH#491: better exception message when ``Counter.new()`` is called with an integer
        ``initial_value`` than doesn't fit into ``nbits`` bits.
      * GH#496: added missing ``block_size`` member for ECB cipher objects. Thanks to willem.
      * GH#500: ``nonce`` member of an XChaCha20 cipher object was not matching the original nonce.

    - update to 3.9.9:
      * GH#435: Fixed Crypto.Util.number.size for negative numbers

    - update to 3.9.8:
      * GH#426: The Shamir's secret sharing implementation is not actually compatible with ``ssss``.
      Added an optional parameter to enable interoperability.
      * GH#427: Skip altogether loading of ``gmp.dll`` on Windows.
      * GH#420: Fix incorrect CFB decryption when the input and the output are the same buffer.
      * Speed up Shamir's secret sharing routines. Thanks to ncarve.

    - Update to 3.9.7
      * Align stack of functions using SSE2 intrinsics to avoid crashes,
        when compiled with gcc on 32-bit x86 platforms.
      * Prevent key_to_english from creating invalid data when fed with
        keys of length not multiple of 8.
      * Fix blocking RSA signing/decryption when key has very small factor.
      * fixed memory leak for operations that use memoryviews when cffi
        is not installed.
      * RSA OAEP decryption was not verifying that all PS bytes are zero.
      * Fixed wrong ASN.1 OID for HMAC-SHA512 in PBE2.

    - Update to 3.9.2 (10 November 2019):
      + New features
        * Add Python 3.8 wheels for Mac.
      + Resolved issues
        * GH#308: Avoid allocating arrays of __m128i on the stack, to
          cope with buggy compilers.
        * GH#322: Remove blanket -O3 optimization for gcc and clang, to
          cope with buggy compilers.
        * GH#337: Fix typing stubs for signatures.
        * GH#338: Deal with gcc installations that don't have
          x86intrin.h.
    - Update to version 3.9.1 (1 November 2019):
      + New features
        * Add Python 3.8 wheels for Linux and Windows.
      + Resolved issues
        * GH#328: minor speed-up when importing RSA.
    - Add export LC_ALL=en_US.UTF-8 to %build, %install and %check to
      fix the build on older distros
      (as done from Thomas Bechtold in python-pycryptodomex)
      * Add support for loading PEM files encrypted with AES192-CBC,
      * When importing ECC keys, ignore EC PARAMS section that was
      * Speed-up ECC performance. ECDSA is 33 times faster on the
      * Support HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512
      * DER objects were not rejected if their length field had
      * point_at_infinity() becomes an instance method for
      * GH#258: False positive on PSS signatures when externally
    - fix tarball: use the one from PyPI...

        * New parameter output for Crypto.Util.strxor.strxor,
          Crypto.Util.strxor.strxor_c, encrypt and decrypt methods in
          symmetric ciphers (Crypto.Cipher package). output is a
          pre-allocated buffer (a bytearray or a writeable memoryview)
          where the result must be stored. This requires less memory for
          very large payloads; it is also more efficient when encrypting
        * Fix vulnerability on AESNI ECB with payloads smaller than
        * Fixed incorrect AES encryption/decryption with AES
          acceleration on x86 due to gccs optimization and strict
        * More prime number candidates than necessary where discarded
          as composite due to the limited way D values were searched
        * More meaningful exceptions in case of mismatch in IV length

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218564");
  # https://lists.suse.com/pipermail/sle-updates/2024-September/036994.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?424feb21");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52323");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52323");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-aas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-acm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-acms-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-actiontrail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-adb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-adcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-address-purification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-aegis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-afs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-aigen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-aimiaobi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-airec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-airticketopen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-alb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-alidns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-aligreen-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-alikafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-alimt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-alinlp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-aliyuncvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-amptest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-amqp-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-antiddos-public");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-apds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-appmallsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-appstream-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-aps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-arms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-arms4finance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-avatar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-baas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-bpstudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-brinekingdom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-bss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-bssopenapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-btripopen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-captcha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cassandra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cbn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cc5g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ccc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cciotgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ccs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cdn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cdrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-chatbot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-clickhouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloud-siem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudauth-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudesl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudgame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudmarketing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudphone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudphoto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cloudwf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-codeup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-companyreg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-computenest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-computenestsupplier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-crm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-csas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cspro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-cusanalytic_sc_online");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-das");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dataphin-public");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dataworks-public");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dbfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dcdn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ddosbgp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ddoscoo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ddosdiversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-democenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-devops-rdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dms-enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-documentautoml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-domain-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-drds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dt-oc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dybaseapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dyplsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dypnsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dypnsapi-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dysmsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dytnsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-dyvmsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-eais");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-eas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ebs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ecd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-eci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ecs-workbench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-edas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-eflo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-eflo-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ehpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-eipanycast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-emap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-emas-appmonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-emr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-emrstudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ens");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-es-serverless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-et-industry-openapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-eventbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-faas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-facebody");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-fnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-foas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-goodstech");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-gpdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-grace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-green");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-gts-phd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-hbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-hbr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-hcs-mgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-highddos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-hiknoengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-hitsdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-hivisengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-hsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-httpdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-idaas-doraemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-idrsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-idsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imageaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imageenhan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imageprocess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imagerecog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imagesearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imageseg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imarketing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imgsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-imm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-industry-brain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-iot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-iotcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-iqa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ivision");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ivpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-jaq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-jarvis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-jarvis-public");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-kms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ledgerdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-linkedmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-linkface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-linkvisual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-linkwan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-live");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ltl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-lto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-lubancloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-market");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-maxcompute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-metering");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-mns-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-moguan-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-mopen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-mpaas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-msccommonquery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-mse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-mts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-multimediaai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-nas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-netana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-nlb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-nlp-automl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-nls-cloud-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-objectdet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-oceanbasepro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ocr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-oms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-onsmqtt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-oos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-openanalytics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-openanalytics-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-openitag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-opensearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ossadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ots");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-outboundbot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-pai-dsw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-paielasticdatasetaccelerator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-paifeaturestore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-pairecservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-paistudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-petadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-polardb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-polardbx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-privatelink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-productcatalog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-pts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-push");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-pvtz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-qualitycheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-quickbi-public");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-quotas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-r-kvstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-rdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-rds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-rds-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-reid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-reid_cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-resourcecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-resourcemanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-resourcesharing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-retailcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-risk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-rsimganalys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-rtc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-sae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-saf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-safconsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-sas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-sas-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-sasti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-scdn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-schedulerx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-scsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-sddp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-servicemesh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-sgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-slb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-sls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-smartag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-smarthosting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-smartsales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-smc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-snsuapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-status");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-sts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-swas-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-tag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-tdsr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-teambition-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-tesladam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-teslamaxcompute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-teslastream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-threedvision");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-tingwu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-trademark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ubsms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-uis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-unimkt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-vcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-ververica");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-viapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-viapi-oxs-cross");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-viapi-regen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-viapiutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-videoenhan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-videorecog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-videosearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-videoseg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-visionai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-visionai-poc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-vod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-voicenavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-vpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-vpcpeer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-vs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-waf-openapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-webplus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-welfare-inner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-wfts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-workbench-ide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-workorder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-xspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-xtrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-yundun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aliyun-python-sdk-yundun-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-crcmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-oss2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pycryptodome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'python311-aliyun-python-sdk-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aas-2.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-acm-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-acms-open-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-actiontrail-2.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-adb-1.1.10-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-adcp-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-address-purification-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aegis-1.0.6-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-afs-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aigen-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aimiaobi-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-airec-2.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-airticketopen-3.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alb-1.0.16-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alidns-3.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aligreen-console-1.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alikafka-1.0.6-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alimt-3.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alinlp-1.0.24-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aliyuncvc-1.0.10.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-amptest-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-amqp-open-1.1.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-antiddos-public-2.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-apds-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-appmallsservice-1.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-appstream-center-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aps-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-arms-2.7.30-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-arms4finance-2.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-avatar-2.0.8-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-baas-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-bpstudio-1.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-brinekingdom-1.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-bss-0.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-bssopenapi-2.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-btripopen-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cams-1.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-captcha-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cas-1.0.18-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cassandra-1.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cbn-1.0.41-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cc5g-1.0.7-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ccc-2.10.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cciotgw-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ccs-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cdn-3.8.8-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cdrs-1.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-chatbot-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-clickhouse-3.1.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloud-siem-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudapi-4.9.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudauth-2.0.35-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudauth-console-2.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudesl-2.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudgame-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudmarketing-2.7.16-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudphone-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudphoto-1.1.19-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudwf-1.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cms-7.0.33-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-codeup-0.1.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-companyreg-2.2.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-computenest-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-computenestsupplier-1.0.5-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-config-2.2.12-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-core-2.15.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cr-4.1.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-crm-2.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cs-4.8.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-csas-1.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-csb-1.2.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cspro-1.3.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cusanalytic_sc_online-1.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-das-2.0.36-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dataphin-public-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dataworks-public-5.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dbfs-2.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dbs-1.0.36-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dcdn-2.2.18-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ddosbgp-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ddoscoo-1.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ddosdiversion-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dds-3.7.17-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-democenter-1.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-devops-rdc-2.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dg-1.0.10-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dms-enterprise-1.53.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-documentautoml-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-domain-3.14.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-domain-intl-1.6.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-drds-20210523.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dt-oc-info-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dts-5.1.29-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dybaseapi-1.0.8-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dyplsapi-1.3.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dypnsapi-1.1.11-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dypnsapi-intl-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dysmsapi-2.1.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dytnsapi-1.1.8-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dyvmsapi-3.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eais-2.1.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eas-0.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ebs-1.3.7-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ecd-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eci-1.3.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ecs-4.24.71-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ecs-workbench-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-edas-3.26.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eflo-1.0.12-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eflo-controller-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ehpc-1.14.21-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eipanycast-1.0.5-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-elasticsearch-3.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-emap-1.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-emas-appmonitor-1.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-emr-3.3.10-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-emrstudio-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ens-3.0.14-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-es-serverless-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ess-2.3.19-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-et-industry-openapi-3.6-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eventbridge-1.0.14-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-faas-2.7.11-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-facebody-2.0.13-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-fnf-1.8.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-foas-2.11.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ft-5.6.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ga-1.0.19-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-gdb-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-geoip-1.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-goodstech-1.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-gpdb-1.1.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-grace-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-green-3.6.6-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-gts-phd-1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hbase-2.9.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hbr-1.2.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hcs-mgw-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-highddos-2.1.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hiknoengine-0.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hitsdb-3.1.15-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hivisengine-0.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hpc-2.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hsm-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-httpdns-2.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ice-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-idaas-doraemon-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-idrsservice-3.7.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-idsp-1.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imageaudit-1.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imageenhan-1.1.12-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imageprocess-2.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imagerecog-1.0.19-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imagesearch-2.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imageseg-1.1.13-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imarketing-5.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imgsearch-1.1.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imm-2.1.17-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-industry-brain-5.0.52-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-iot-8.59.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-iotcc-2.0.7-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-iqa-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ivision-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ivpd-1.0.6.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-jaq-2.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-jarvis-1.2.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-jarvis-public-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-kms-2.16.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ledgerdb-0.7.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-linkedmall-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-linkface-1.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-linkvisual-1.5.8-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-linkwan-1.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-live-3.9.49-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ltl-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-lto-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-lubancloud-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-market-2.0.24-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-maxcompute-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-metering-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mns-open-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-moguan-sdk-1.1.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mopen-1.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mpaas-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-msccommonquery-0.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mse-3.0.24-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mts-3.3.41-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-multimediaai-1.1.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nas-3.14.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-netana-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nis-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nlb-1.0.12-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nlp-automl-0.0.15-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nls-cloud-meta-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-objectdet-1.0.16-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-oceanbasepro-1.0.15-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ocr-1.0.25-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ocs-0.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-oms-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ons-3.2.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-onsmqtt-1.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-oos-1.5.15-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-openanalytics-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-openanalytics-open-2.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-openitag-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-opensearch-0.12.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ossadmin-0.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ots-4.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-outboundbot-1.6.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-pai-dsw-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-paielasticdatasetaccelerator-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-paifeaturestore-1.0.11-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-pairecservice-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-paistudio-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-petadata-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-polardb-1.8.47-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-polardbx-20201028-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-privatelink-1.0.8-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-productcatalog-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-pts-2.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-push-3.13.14-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-pvtz-1.3.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-qualitycheck-4.7.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-quickbi-public-2.1.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-quotas-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-r-kvstore-2.20.11-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ram-3.3.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rdc-1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rds-2.7.43-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rds-data-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-reid-1.1.8.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-reid_cloud-1.2.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-resourcecenter-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-resourcemanager-1.2.6-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-resourcesharing-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-retailcloud-2.0.20-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-risk-0.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ros-3.6.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rsimganalys-4.3.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rtc-1.3.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sae-1.22.15-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-saf-3.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-safconsole-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sas-2.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sas-api-2.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sasti-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-scdn-2.2.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-schedulerx2-1.1.12-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-scsp-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sddp-1.0.10-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-servicemesh-1.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sgw-1.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-slb-3.3.21-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sls-1.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-smartag-2.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-smarthosting-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-smartsales-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-smc-1.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-snsuapi-1.7.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-status-3.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sts-3.1.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-swas-open-1.0.6-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-tag-1.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-tdsr-0.9.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-teambition-aliyun-1.0.8-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-tesladam-1.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-teslamaxcompute-1.5.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-teslastream-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-threedvision-1.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-tingwu-1.0.5-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-trademark-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ubsms-2.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-uis-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-unimkt-2.4.8-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vcs-2.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ververica-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-viapi-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-viapi-oxs-cross-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-viapi-regen-1.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-viapiutils-1.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-videoenhan-1.0.23-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-videorecog-1.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-videosearch-1.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-videoseg-1.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-visionai-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-visionai-poc-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vod-2.16.21-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-voicenavigator-1.7.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vpc-3.0.45-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vpcpeer-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vs-1.10.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-waf-openapi-1.1.9-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-webplus-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-welfare-inner-1.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-wfts-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-workbench-ide-2.0.5-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-workorder-3.1.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-xspace-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-xtrace-0.2.2-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-yundun-2.1.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-yundun-ds-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-crcmod-1.7-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-oss2-2.18.4-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pycryptodome-3.20.0-150400.15.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aas-2.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-acm-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-acms-open-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-actiontrail-2.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-adb-1.1.10-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-adcp-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-address-purification-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aegis-1.0.6-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-afs-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aigen-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aimiaobi-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-airec-2.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-airticketopen-3.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alb-1.0.16-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alidns-3.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aligreen-console-1.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alikafka-1.0.6-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alimt-3.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-alinlp-1.0.24-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aliyuncvc-1.0.10.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-amptest-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-amqp-open-1.1.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-antiddos-public-2.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-apds-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-appmallsservice-1.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-appstream-center-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-aps-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-arms-2.7.30-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-arms4finance-2.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-avatar-2.0.8-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-baas-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-bpstudio-1.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-brinekingdom-1.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-bss-0.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-bssopenapi-2.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-btripopen-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cams-1.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-captcha-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cas-1.0.18-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cassandra-1.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cbn-1.0.41-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cc5g-1.0.7-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ccc-2.10.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cciotgw-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ccs-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cdn-3.8.8-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cdrs-1.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-chatbot-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-clickhouse-3.1.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloud-siem-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudapi-4.9.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudauth-2.0.35-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudauth-console-2.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudesl-2.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudgame-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudmarketing-2.7.16-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudphone-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudphoto-1.1.19-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cloudwf-1.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cms-7.0.33-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-codeup-0.1.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-companyreg-2.2.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-computenest-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-computenestsupplier-1.0.5-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-config-2.2.12-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-core-2.15.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cr-4.1.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-crm-2.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cs-4.8.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-csas-1.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-csb-1.2.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cspro-1.3.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-cusanalytic_sc_online-1.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-das-2.0.36-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dataphin-public-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dataworks-public-5.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dbfs-2.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dbs-1.0.36-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dcdn-2.2.18-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ddosbgp-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ddoscoo-1.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ddosdiversion-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dds-3.7.17-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-democenter-1.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-devops-rdc-2.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dg-1.0.10-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dms-enterprise-1.53.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-documentautoml-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-domain-3.14.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-domain-intl-1.6.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-drds-20210523.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dt-oc-info-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dts-5.1.29-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dybaseapi-1.0.8-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dyplsapi-1.3.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dypnsapi-1.1.11-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dypnsapi-intl-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dysmsapi-2.1.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dytnsapi-1.1.8-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-dyvmsapi-3.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eais-2.1.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eas-0.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ebs-1.3.7-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ecd-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eci-1.3.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ecs-4.24.71-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ecs-workbench-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-edas-3.26.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eflo-1.0.12-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eflo-controller-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ehpc-1.14.21-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eipanycast-1.0.5-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-elasticsearch-3.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-emap-1.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-emas-appmonitor-1.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-emr-3.3.10-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-emrstudio-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ens-3.0.14-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-es-serverless-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ess-2.3.19-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-et-industry-openapi-3.6-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-eventbridge-1.0.14-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-faas-2.7.11-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-facebody-2.0.13-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-fnf-1.8.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-foas-2.11.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ft-5.6.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ga-1.0.19-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-gdb-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-geoip-1.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-goodstech-1.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-gpdb-1.1.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-grace-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-green-3.6.6-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-gts-phd-1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hbase-2.9.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hbr-1.2.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hcs-mgw-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-highddos-2.1.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hiknoengine-0.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hitsdb-3.1.15-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hivisengine-0.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hpc-2.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-hsm-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-httpdns-2.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ice-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-idaas-doraemon-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-idrsservice-3.7.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-idsp-1.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imageaudit-1.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imageenhan-1.1.12-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imageprocess-2.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imagerecog-1.0.19-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imagesearch-2.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imageseg-1.1.13-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imarketing-5.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imgsearch-1.1.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-imm-2.1.17-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-industry-brain-5.0.52-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-iot-8.59.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-iotcc-2.0.7-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-iqa-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ivision-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ivpd-1.0.6.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-jaq-2.0.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-jarvis-1.2.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-jarvis-public-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-kms-2.16.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ledgerdb-0.7.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-linkedmall-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-linkface-1.2.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-linkvisual-1.5.8-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-linkwan-1.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-live-3.9.49-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ltl-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-lto-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-lubancloud-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-market-2.0.24-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-maxcompute-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-metering-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mns-open-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-moguan-sdk-1.1.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mopen-1.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mpaas-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-msccommonquery-0.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mse-3.0.24-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-mts-3.3.41-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-multimediaai-1.1.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nas-3.14.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-netana-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nis-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nlb-1.0.12-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nlp-automl-0.0.15-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-nls-cloud-meta-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-objectdet-1.0.16-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-oceanbasepro-1.0.15-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ocr-1.0.25-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ocs-0.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-oms-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ons-3.2.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-onsmqtt-1.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-oos-1.5.15-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-openanalytics-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-openanalytics-open-2.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-openitag-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-opensearch-0.12.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ossadmin-0.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ots-4.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-outboundbot-1.6.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-pai-dsw-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-paielasticdatasetaccelerator-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-paifeaturestore-1.0.11-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-pairecservice-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-paistudio-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-petadata-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-polardb-1.8.47-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-polardbx-20201028-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-privatelink-1.0.8-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-productcatalog-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-pts-2.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-push-3.13.14-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-pvtz-1.3.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-qualitycheck-4.7.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-quickbi-public-2.1.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-quotas-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-r-kvstore-2.20.11-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ram-3.3.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rdc-1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rds-2.7.43-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rds-data-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-reid-1.1.8.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-reid_cloud-1.2.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-resourcecenter-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-resourcemanager-1.2.6-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-resourcesharing-1.0.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-retailcloud-2.0.20-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-risk-0.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ros-3.6.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rsimganalys-4.3.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-rtc-1.3.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sae-1.22.15-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-saf-3.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-safconsole-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sas-2.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sas-api-2.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sasti-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-scdn-2.2.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-schedulerx2-1.1.12-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-scsp-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sddp-1.0.10-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-servicemesh-1.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sgw-1.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-slb-3.3.21-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sls-1.1.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-smartag-2.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-smarthosting-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-smartsales-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-smc-1.0.3-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-snsuapi-1.7.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-status-3.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-sts-3.1.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-swas-open-1.0.6-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-tag-1.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-tdsr-0.9.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-teambition-aliyun-1.0.8-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-tesladam-1.0.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-teslamaxcompute-1.5.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-teslastream-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-threedvision-1.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-tingwu-1.0.5-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-trademark-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ubsms-2.0.5-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-uis-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-unimkt-2.4.8-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vcs-2.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-ververica-1.0.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-viapi-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-viapi-oxs-cross-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-viapi-regen-1.0.4-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-viapiutils-1.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-videoenhan-1.0.23-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-videorecog-1.0.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-videosearch-1.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-videoseg-1.0.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-visionai-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-visionai-poc-1.0.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vod-2.16.21-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-voicenavigator-1.7.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vpc-3.0.45-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vpcpeer-1.0.3-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-vs-1.10.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-waf-openapi-1.1.9-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-webplus-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-welfare-inner-1.1.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-wfts-1.0.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-workbench-ide-2.0.5-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-workorder-3.1.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-xspace-1.2.1-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-xtrace-0.2.2-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-yundun-2.1.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-aliyun-python-sdk-yundun-ds-1.0.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-crcmod-1.7-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-oss2-2.18.4-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pycryptodome-3.20.0-150400.15.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python311-aliyun-python-sdk / python311-aliyun-python-sdk-aas / etc');
}
