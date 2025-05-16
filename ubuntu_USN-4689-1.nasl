##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4689-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144897);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2021-1052", "CVE-2021-1053", "CVE-2021-1056");
  script_xref(name:"USN", value:"4689-1");
  script_xref(name:"IAVB", value:"2021-B-0005-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : NVIDIA graphics drivers vulnerabilities (USN-4689-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4689-1 advisory.

    It was discovered that the NVIDIA GPU display driver for the Linux kernel contained a vulnerability that
    allowed user-mode clients to access legacy privileged APIs. A local attacker could use this to cause a
    denial of service or escalate privileges. (CVE-2021-1052)

    It was discovered that the NVIDIA GPU display driver for the Linux kernel did not properly validate a
    pointer received from userspace in some situations. A local attacker could use this to cause a denial of
    service. (CVE-2021-1053)

    Xinyuan Lyu discovered that the NVIDIA GPU display driver for the Linux kernel did not properly restrict
    device-level GPU isolation. A local attacker could use this to cause a denial of service or possibly
    expose sensitive information. (CVE-2021-1056)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4689-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1052");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-384");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-384");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-384-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-384");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-384");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-440");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-450");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-455");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-460");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libcuda1-384', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-384', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-384-dev', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-libopencl1-384', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-opencl-icd-384', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-390', 'pkgver': '390.141-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-440', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-450', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-455', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-460', 'pkgver': '460.32.03-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libcuda1-384', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-384', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-384-dev', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-libopencl1-384', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-opencl-icd-384', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-390', 'pkgver': '390.141-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-440', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-450', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-455', 'pkgver': '460.32.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-460', 'pkgver': '460.32.03-0ubuntu0.20.04.1'}
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
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcuda1-384 / libnvidia-cfg1-390 / libnvidia-cfg1-440 / etc');
}
