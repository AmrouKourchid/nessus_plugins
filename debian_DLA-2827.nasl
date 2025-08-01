#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2827. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155712);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2019-8921", "CVE-2019-8922", "CVE-2021-41229");

  script_name(english:"Debian DLA-2827-1 : bluez - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2827 advisory.

    Several vulnerabilities were discovered in BlueZ, the Linux Bluetooth protocol stack. An attacker could
    cause a denial-of-service (DoS) or leak information. CVE-2019-8921 SDP infoleak; the vulnerability lies in
    the handling of a SVC_ATTR_REQ by the SDP implementation of BlueZ. By crafting a malicious CSTATE, it is
    possible to trick the server into returning more bytes than the buffer actually holds, resulting in
    leaking arbitrary heap data. CVE-2019-8922 SDP Heap Overflow; this vulnerability lies in the SDP protocol
    handling of attribute requests as well. By requesting a huge number of attributes at the same time, an
    attacker can overflow the static buffer provided to hold the response. CVE-2021-41229 sdp_cstate_alloc_buf
    allocates memory which will always be hung in the singly linked list of cstates and will not be freed.
    This will cause a memory leak over time. The data can be a very large object, which can be caused by an
    attacker continuously sending sdp packets and this may cause the service of the target device to crash.
    For Debian 9 stretch, these problems have been fixed in version 5.43-2+deb9u5. We recommend that you
    upgrade your bluez packages. For the detailed security status of bluez please refer to its security
    tracker page at: https://security-tracker.debian.org/tracker/bluez Further information about Debian LTS
    security advisories, how to apply these updates to your system and frequently asked questions can be found
    at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1000262");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/bluez");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2827");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-8921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-8922");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41229");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/bluez");
  script_set_attribute(attribute:"solution", value:
"Upgrade the bluez packages.

For Debian 9 stretch, these problems have been fixed in version 5.43-2+deb9u5.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8922");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-hcidump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-obexd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-test-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-test-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbluetooth-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbluetooth3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbluetooth3-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'bluetooth', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'bluez', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'bluez-cups', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'bluez-dbg', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'bluez-hcidump', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'bluez-obexd', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'bluez-test-scripts', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'bluez-test-tools', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'libbluetooth-dev', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'libbluetooth3', 'reference': '5.43-2+deb9u5'},
    {'release': '9.0', 'prefix': 'libbluetooth3-dbg', 'reference': '5.43-2+deb9u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bluetooth / bluez / bluez-cups / bluez-dbg / bluez-hcidump / etc');
}
