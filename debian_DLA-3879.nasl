#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3879. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206762);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/07");

  script_cve_id(
    "CVE-2021-3658",
    "CVE-2021-41229",
    "CVE-2021-43400",
    "CVE-2022-0204",
    "CVE-2022-39176",
    "CVE-2022-39177",
    "CVE-2023-27349",
    "CVE-2023-50229",
    "CVE-2023-50230"
  );

  script_name(english:"Debian dla-3879 : bluetooth - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3879 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3879-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    September 07, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : bluez
    Version        : 5.55-3.1+deb11u2
    CVE ID         : CVE-2021-3658 CVE-2021-41229 CVE-2021-43400 CVE-2022-0204
                     CVE-2022-39176 CVE-2022-39177 CVE-2023-27349 CVE-2023-50229
                     CVE-2023-50230
    Debian Bug     : 991596 998626 1000262 1003712

    Multiple vulnerabilities have been fixed in bluez library, tools and
    daemons for using Bluetooth devices.

    CVE-2021-3658

        adapter: Fix storing discoverable setting

    CVE-2021-41229

        Memory leak in the SDP protocol

    CVE-2021-43400

        Use-after-free on client disconnect

    CVE-2022-0204

        GATT heap overflow

    CVE-2022-39176

        Proximate attackers could obtain sensitive information

    CVE-2022-39177

        Proximate attackers could cause denial of service

    CVE-2023-27349

        AVRCP crash while handling unsupported events

    CVE-2023-50229

        Phone Book Access profile Heap-based Buffer Overflow

    CVE-2023-50230

        Phone Book Access profile Heap-based Buffer Overflow

    For Debian 11 bullseye, these problems have been fixed in version
    5.55-3.1+deb11u2.

    We recommend that you upgrade your bluez packages.

    For the detailed security status of bluez please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/bluez

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/bluez");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3658");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43400");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39176");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39177");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27349");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50230");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/bluez");
  script_set_attribute(attribute:"solution", value:
"Upgrade the bluetooth packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43400");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-hcidump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-meshd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-obexd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-test-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez-test-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbluetooth-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbluetooth3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'bluetooth', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'bluez', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'bluez-cups', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'bluez-hcidump', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'bluez-meshd', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'bluez-obexd', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'bluez-source', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'bluez-test-scripts', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'bluez-test-tools', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'libbluetooth-dev', 'reference': '5.55-3.1+deb11u2'},
    {'release': '11.0', 'prefix': 'libbluetooth3', 'reference': '5.55-3.1+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bluetooth / bluez / bluez-cups / bluez-hcidump / bluez-meshd / etc');
}
