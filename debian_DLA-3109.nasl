#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3109. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165186);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2019-14433");

  script_name(english:"Debian dla-3109 : nova-api - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3109
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3109-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/               Emilio Pozuelo Monfort
    September 15, 2022                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : nova
    Version        : 2:18.1.0-6+deb10u1
    CVE ID         : CVE-2019-14433
    Debian Bug     : 934114

    It was found that authenticated users could trigger a fault in Nova, a
    cloud computing fabric controller, to cause information leak.

    In addition, this update includes some fixes for volume live migration,
    as well as the addition of a /healthcheck URL for monitoring.

    For Debian 10 buster, this problem has been fixed in version
    2:18.1.0-6+deb10u1.

    We recommend that you upgrade your nova packages.

    For the detailed security status of nova please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/nova

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nova");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14433");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/nova");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nova-api packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14433");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-cells");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute-ironic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-compute-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-consoleauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-consoleproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-placement-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-nova");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'nova-api', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-cells', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-common', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-compute', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-compute-ironic', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-compute-kvm', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-compute-lxc', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-compute-qemu', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-conductor', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-console', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-consoleauth', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-consoleproxy', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-doc', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-placement-api', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-scheduler', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'nova-volume', 'reference': '2:18.1.0-6+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-nova', 'reference': '2:18.1.0-6+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nova-api / nova-cells / nova-common / nova-compute / etc');
}
