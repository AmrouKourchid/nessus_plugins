#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6258-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178947);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-29932",
    "CVE-2023-29933",
    "CVE-2023-29934",
    "CVE-2023-29939"
  );
  script_xref(name:"USN", value:"6258-1");

  script_name(english:"Ubuntu 22.04 LTS / 23.04 : LLVM Toolchain vulnerabilities (USN-6258-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 23.04 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6258-1 advisory.

    It was discovered that LLVM Toolchain did not properly manage memory under certain circumstances. If a
    user were tricked into opening a specially crafted MLIR file, an attacker could possibly use this issue to
    cause LLVM Toolchain to crash, resulting in a denial of service. (CVE-2023-29932, CVE-2023-29934,
    CVE-2023-29939)

    It was discovered that LLVM Toolchain did not properly manage memory under

    certain circumstances. If a user were tricked into opening a specially

    crafted MLIR file, an attacker could possibly use this issue to cause LLVM

    Toolchain to crash, resulting in a denial of service. This issue only affected llvm-toolchain-15.
    (CVE-2023-29933)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6258-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29939");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bolt-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-13-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-14-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-15-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-format-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-format-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-format-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-tidy-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-tidy-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-tidy-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-tools-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-tools-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clang-tools-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clangd-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clangd-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clangd-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flang-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbolt-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++-14-dev-wasm32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++-15-dev-wasm32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++1-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++1-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++1-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++abi-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++abi-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++abi-14-dev-wasm32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++abi-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++abi-15-dev-wasm32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++abi1-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++abi1-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc++abi1-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-common-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-common-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-common-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-cpp13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-cpp13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-cpp14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-cpp14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-cpp15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-cpp15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-rt-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-rt-14-dev-wasm32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-rt-14-dev-wasm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-rt-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-rt-15-dev-wasm32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang-rt-15-dev-wasm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang1-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang1-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclang1-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclc-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclc-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclc-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclc-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclc-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclc-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflang-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfuzzer-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfuzzer-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfuzzer-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblld-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblld-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblld-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblld-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblld-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblld-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblldb-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblldb-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblldb-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblldb-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblldb-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblldb-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libllvm-13-ocaml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libllvm-14-ocaml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libllvm-15-ocaml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libllvm13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libllvm14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libllvm15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmlir-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmlir-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmlir-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmlir-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmlir-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmlir-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libomp-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libomp-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libomp-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libomp5-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libomp5-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libomp5-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpolly-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpolly-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunwind-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunwind-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunwind-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunwind-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunwind-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunwind-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lld-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lld-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lld-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lldb-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lldb-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lldb-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-13-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-13-linker-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-13-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-13-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-14-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-14-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-14-linker-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-14-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-14-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-15-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-15-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-15-linker-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-15-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:llvm-15-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mlir-13-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mlir-14-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mlir-15-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-clang-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-clang-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-clang-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-lldb-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-lldb-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-lldb-15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'bolt-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'clang-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'clang-13-examples', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'clang-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'clang-14-examples', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'clang-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'clang-15-examples', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'clang-format-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'clang-format-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'clang-format-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'clang-tidy-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'clang-tidy-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'clang-tidy-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'clang-tools-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'clang-tools-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'clang-tools-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'clangd-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'clangd-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'clangd-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libbolt-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libc++-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libc++-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libc++-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libc++1-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libc++1-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libc++1-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libc++abi-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libc++abi-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libc++abi-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libc++abi1-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libc++abi1-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libc++abi1-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libclang-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libclang-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libclang-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libclang-common-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libclang-common-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libclang-common-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libclang-cpp13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libclang-cpp13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libclang-cpp14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libclang-cpp14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libclang-cpp15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libclang-cpp15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libclang1-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libclang1-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libclang1-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libclc-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libclc-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libclc-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libclc-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libclc-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libclc-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libfuzzer-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libfuzzer-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libfuzzer-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'liblld-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'liblld-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'liblld-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'liblld-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'liblld-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'liblld-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'liblldb-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'liblldb-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'liblldb-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'liblldb-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'liblldb-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'liblldb-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libllvm-13-ocaml-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libllvm-14-ocaml-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libllvm-15-ocaml-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libllvm13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libllvm14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libllvm15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmlir-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libmlir-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libmlir-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libmlir-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libmlir-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libmlir-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libomp-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libomp-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libomp-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libomp5-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libomp5-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libomp5-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libunwind-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libunwind-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libunwind-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libunwind-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libunwind-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'libunwind-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'lld-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'lld-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'lld-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'lldb-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'lldb-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'lldb-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'llvm-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'llvm-13-dev', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'llvm-13-examples', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'llvm-13-linker-tools', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'llvm-13-runtime', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'llvm-13-tools', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'llvm-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'llvm-14-dev', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'llvm-14-examples', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'llvm-14-linker-tools', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'llvm-14-runtime', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'llvm-14-tools', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'llvm-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'llvm-15-dev', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'llvm-15-examples', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'llvm-15-linker-tools', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'llvm-15-runtime', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'llvm-15-tools', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'mlir-13-tools', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'mlir-14-tools', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'mlir-15-tools', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-clang-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'python3-clang-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'python3-clang-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '22.04', 'pkgname': 'python3-lldb-13', 'pkgver': '1:13.0.1-2ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'python3-lldb-14', 'pkgver': '1:14.0.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'python3-lldb-15', 'pkgver': '1:15.0.7-0ubuntu0.22.04.3'},
    {'osver': '23.04', 'pkgname': 'bolt-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'clang-13-examples', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'clang-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-14-examples', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-15-examples', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-format-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'clang-format-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-format-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-tidy-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'clang-tidy-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-tidy-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-tools-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'clang-tools-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clang-tools-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clangd-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'clangd-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'clangd-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'flang-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libbolt-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libc++-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++-14-dev-wasm32', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++-15-dev-wasm32', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++1-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libc++1-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++1-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++abi-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libc++abi-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++abi-14-dev-wasm32', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++abi-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++abi-15-dev-wasm32', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++abi1-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libc++abi1-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libc++abi1-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libclang-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-common-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libclang-common-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-common-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-cpp13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libclang-cpp13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libclang-cpp14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-cpp14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-cpp15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-cpp15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-rt-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-rt-14-dev-wasm32', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-rt-14-dev-wasm64', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-rt-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-rt-15-dev-wasm32', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang-rt-15-dev-wasm64', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang1-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libclang1-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclang1-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclc-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libclc-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libclc-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclc-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclc-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libclc-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libflang-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libfuzzer-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libfuzzer-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libfuzzer-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'liblld-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'liblld-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'liblld-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'liblld-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'liblld-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'liblld-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'liblldb-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'liblldb-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'liblldb-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'liblldb-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'liblldb-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'liblldb-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libllvm-13-ocaml-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libllvm-14-ocaml-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libllvm-15-ocaml-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libllvm13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libllvm14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libllvm15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmlir-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libmlir-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libmlir-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmlir-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmlir-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmlir-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libomp-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libomp-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libomp-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libomp5-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libomp5-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libomp5-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libpolly-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libpolly-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libunwind-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libunwind-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'libunwind-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libunwind-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libunwind-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libunwind-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'lld-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'lld-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'lld-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'lldb-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'lldb-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'lldb-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'llvm-13-dev', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'llvm-13-examples', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'llvm-13-linker-tools', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'llvm-13-runtime', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'llvm-13-tools', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'llvm-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-14-dev', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-14-examples', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-14-linker-tools', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-14-runtime', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-14-tools', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-15-dev', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-15-examples', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-15-linker-tools', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-15-runtime', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'llvm-15-tools', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mlir-13-tools', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'mlir-14-tools', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'mlir-15-tools', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'python3-clang-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'python3-clang-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'python3-clang-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'python3-lldb-13', 'pkgver': '1:13.0.1-11ubuntu14.1'},
    {'osver': '23.04', 'pkgname': 'python3-lldb-14', 'pkgver': '1:14.0.6-12ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'python3-lldb-15', 'pkgver': '1:15.0.7-3ubuntu0.23.04.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bolt-15 / clang-13 / clang-13-examples / clang-14 / etc');
}
