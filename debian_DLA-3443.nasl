#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3443. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176657);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id(
    "CVE-2023-2856",
    "CVE-2023-2858",
    "CVE-2023-2879",
    "CVE-2023-2952"
  );
  script_xref(name:"IAVB", value:"2023-B-0036-S");

  script_name(english:"Debian dla-3443 : libwireshark-data - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3443 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3443-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    June 03, 2023                                 https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : wireshark
    Version        : 2.6.20-0+deb10u7
    CVE ID         : CVE-2023-2856 CVE-2023-2858 CVE-2023-2879 CVE-2023-2952

    Several vulnerabilities were fixed in the network traffic analyzer Wireshark.

    CVE-2023-2856

        VMS TCPIPtrace file parser crash

    CVE-2023-2858

        NetScaler file parser crash

    CVE-2023-2879

        GDSDB infinite loop

    CVE-2023-2952

        XRA dissector infinite loop

    For Debian 10 buster, these problems have been fixed in version
    2.6.20-0+deb10u7.

    We recommend that you upgrade your wireshark packages.

    For the detailed security status of wireshark please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/wireshark

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wireshark");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2856");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2858");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2879");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2952");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/wireshark");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libwireshark-data packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2952");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2879");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwireshark11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwiretap8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwscodecs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwsutil9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'libwireshark-data', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'libwireshark-dev', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'libwireshark11', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'libwiretap-dev', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'libwiretap8', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'libwscodecs2', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'libwsutil-dev', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'libwsutil9', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'tshark', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'wireshark', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'wireshark-common', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'wireshark-dev', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'wireshark-doc', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'wireshark-gtk', 'reference': '2.6.20-0+deb10u7'},
    {'release': '10.0', 'prefix': 'wireshark-qt', 'reference': '2.6.20-0+deb10u7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwireshark-data / libwireshark-dev / libwireshark11 / libwiretap-dev / etc');
}
