#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5756. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206012);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/21");

  script_cve_id("CVE-2024-32498");

  script_name(english:"Debian dsa-5756 : nova-api - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5756
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5756-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    August 21, 2024                       https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : nova
    CVE ID         : CVE-2024-32498

    Martin Kaesberger discovered a vulnerability which affects multiple
    OpenStack components (Nova, Glance and Cinder): Malformed QCOW2 disk
    images may result in the disclosure of arbitrary files.

    For the stable distribution (bookworm), this problem has been fixed in
    version 2:26.2.2-1~deb12u3.

    We recommend that you upgrade your nova packages.

    For the detailed security status of nova please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/nova

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nova");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32498");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/nova");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nova-api packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute-ironic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-consoleproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-nova");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'nova-api', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-common', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-compute', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-compute-ironic', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-compute-kvm', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-compute-lxc', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-compute-qemu', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-conductor', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-consoleproxy', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-doc', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'nova-scheduler', 'reference': '2:26.2.2-1~deb12u3'},
    {'release': '12.0', 'prefix': 'python3-nova', 'reference': '2:26.2.2-1~deb12u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nova-api / nova-common / nova-compute / nova-compute-ironic / etc');
}
