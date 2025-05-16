#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2967. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159397);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2021-4181",
    "CVE-2021-4184",
    "CVE-2021-4185",
    "CVE-2021-22191",
    "CVE-2022-0581",
    "CVE-2022-0582",
    "CVE-2022-0583",
    "CVE-2022-0585",
    "CVE-2022-0586"
  );
  script_xref(name:"IAVB", value:"2021-B-0020-S");
  script_xref(name:"IAVB", value:"2022-B-0006-S");
  script_xref(name:"IAVB", value:"2021-B-0072-S");

  script_name(english:"Debian DLA-2967-1 : wireshark - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2967 advisory.

    Multiple security vulnerabilities have been discovered in Wireshark, a network traffic analyzer. An
    attacker could cause a denial of service (infinite loop or application crash) via packet injection or a
    crafted capture file. Improper URL handling in Wireshark could also allow remote code execution. A double-
    click will no longer automatically open the URL in pcap(ng) files and instead copy it to the clipboard
    where it can be inspected and pasted to the browser's address bar. For Debian 9 stretch, these problems
    have been fixed in version 2.6.20-0+deb9u3. We recommend that you upgrade your wireshark packages. For the
    detailed security status of wireshark please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/wireshark Further information about Debian LTS security advisories, how to
    apply these updates to your system and frequently asked questions can be found at:
    https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wireshark");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2967");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22191");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4185");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0582");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0583");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0585");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0586");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/wireshark");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wireshark packages.

For Debian 9 stretch, these problems have been fixed in version 2.6.20-0+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0582");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwscodecs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libwireshark-data', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwireshark-dev', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwireshark11', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwireshark8', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwiretap-dev', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwiretap6', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwiretap8', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwscodecs1', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwscodecs2', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwsutil-dev', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwsutil7', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'libwsutil9', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'tshark', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'wireshark', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'wireshark-common', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'wireshark-dev', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'wireshark-doc', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'wireshark-gtk', 'reference': '2.6.20-0+deb9u3'},
    {'release': '9.0', 'prefix': 'wireshark-qt', 'reference': '2.6.20-0+deb9u3'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwireshark-data / libwireshark-dev / libwireshark11 / libwireshark8 / etc');
}
