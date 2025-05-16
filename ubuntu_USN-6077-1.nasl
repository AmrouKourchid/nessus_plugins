#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6077-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175915);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2023-21930",
    "CVE-2023-21937",
    "CVE-2023-21938",
    "CVE-2023-21939",
    "CVE-2023-21954",
    "CVE-2023-21967",
    "CVE-2023-21968"
  );
  script_xref(name:"USN", value:"6077-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.04 : OpenJDK vulnerabilities (USN-6077-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.04 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6077-1 advisory.

    Ben Smyth discovered that OpenJDK incorrectly handled half-duplex connections during TLS handshake. A
    remote attacker could possibly use this issue to insert, edit or obtain sensitive information.
    (CVE-2023-21930)

    It was discovered that OpenJDK incorrectly handled certain inputs. An attacker could possibly use this
    issue to insert, edit or obtain sensitive information. (CVE-2023-21937)

    It was discovered that OpenJDK incorrectly handled command arguments. An attacker could possibly use this
    issue to insert, edit or obtain sensitive information. (CVE-2023-21938)

    It was discovered that OpenJDK incorrectly validated HTML documents. An attacker could possibly use this
    issue to insert, edit or obtain sensitive information. (CVE-2023-21939)

    Ramki Ramakrishna discovered that OpenJDK incorrectly handled garbage collection. An attacker could
    possibly use this issue to bypass Java sandbox restrictions. (CVE-2023-21954)

    Jonathan Looney discovered that OpenJDK incorrectly handled certificate chains during TLS session
    negotiation. A remote attacker could possibly use this issue to cause a denial of service.
    (CVE-2023-21967)

    Adam Reziouk discovered that OpenJDK incorrectly sanitized URIs. An attacker could possibly use this issue
    to bypass Java sandbox restrictions. (CVE-2023-21968)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6077-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-source");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-20-demo', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jdk', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jdk-headless', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre-headless', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre-zero', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-20-source', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE},
    {'osver': '23.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-11-demo / openjdk-11-jdk / openjdk-11-jdk-headless / etc');
}
