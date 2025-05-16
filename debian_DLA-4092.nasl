#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4092. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(233360);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_cve_id("CVE-2023-2602", "CVE-2023-2603", "CVE-2025-1390");
  script_xref(name:"IAVA", value:"2025-A-0134");

  script_name(english:"Debian dla-4092 : libcap-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4092 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4092-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                           Chris Lamb
    March 26, 2025                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : libcap2
    Version        : 1:2.44-1+deb11u1
    CVE IDs        : CVE-2023-2602 CVE-2023-2603 CVE-2025-1390
    Debian Bugs    : 1036114 1098318

    It was discovered that there were three issues in libcap2, a library
    for managing kernel capabilities; that is, partitioning the
    powerful single root privilege into a set of distinct privileges,
    typically used to limit any damage if a process running as the root
    user is exploited. The three issues are as follows:

    * CVE-2023-2602: A vulnerability was found in the pthread_create()
      function. This issue could have allowed a malicious actor in order
      to exhaust the system's memory.

    * CVE-2023-2603: An issue was found in the _libcap_strdup function
      which could have led to an integer overflow if the input string was
      close to 4GiB.

    * CVE-2025-1390: The pam_cap.so PAM module supports group names
      starting with @ but during parsing, configurations not starting
      with @ were incorrectly recognised as group names. This
      user-group confusion may have resulted in unintended users being
      granted an inherited capability set, potentially leading to
      security risks. Attackers could have exploited this vulnerability
      to achieve local privilege escalation on systems where
      capability.conf was used to configure user inherited privileges by
      constructing specific usernames.

    For Debian 11 bullseye, these problems have been fixed in version
    1:2.44-1+deb11u1.

    We recommend that you upgrade your libcap2 packages.

    For the detailed security status of libcap2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libcap2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libcap2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2602");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2603");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-1390");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libcap2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libcap-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2603");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcap2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcap2-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-cap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'libcap-dev', 'reference': '1:2.44-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libcap2', 'reference': '1:2.44-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libcap2-bin', 'reference': '1:2.44-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libcap2-udeb', 'reference': '1:2.44-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libpam-cap', 'reference': '1:2.44-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcap-dev / libcap2 / libcap2-bin / libcap2-udeb / libpam-cap');
}
