#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3990. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(212178);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/09");

  script_cve_id(
    "CVE-2023-1981",
    "CVE-2023-38469",
    "CVE-2023-38470",
    "CVE-2023-38471",
    "CVE-2023-38472",
    "CVE-2023-38473"
  );

  script_name(english:"Debian dla-3990 : avahi-autoipd - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3990 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3990-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    December 09, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : avahi
    Version        : 0.8-5+deb11u3
    CVE ID         : CVE-2023-1981 CVE-2023-38469 CVE-2023-38470 CVE-2023-38471
                     CVE-2023-38472 CVE-2023-38473
    Debian Bug     : 1034594 1054876 1054877 1054878 1054879 1054880

    Multiple vulnerabilities have been fixed in the service discovery system Avahi.

    CVE-2023-1981

        avahi-daemon can be crashed via DBus

    CVE-2023-38469

        Reachable assertion in avahi_dns_packet_append_record

    CVE-2023-38470

        Reachable assertion in avahi_escape_label

    CVE-2023-38471

        Reachable assertion in dbus_set_host_name

    CVE-2023-38472

        Reachable assertion in avahi_rdata_parse

    CVE-2023-38473

        Reachable assertion in avahi_alternative_host_name

    For Debian 11 bullseye, these problems have been fixed in version
    0.8-5+deb11u3.

    We recommend that you upgrade your avahi packages.

    For the detailed security status of avahi please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/avahi

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/avahi");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38469");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38470");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38471");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38472");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38473");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/avahi");
  script_set_attribute(attribute:"solution", value:
"Upgrade the avahi-autoipd packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-discover");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-ui-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-avahi-0.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-common-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-compat-libdnssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-compat-libdnssd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-gobject-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-ui-gtk3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-ui-gtk3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-avahi");
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
    {'release': '11.0', 'prefix': 'avahi-autoipd', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'avahi-daemon', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'avahi-discover', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'avahi-dnsconfd', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'avahi-ui-utils', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'avahi-utils', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'gir1.2-avahi-0.6', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-client-dev', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-client3', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-common-data', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-common-dev', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-common3', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-compat-libdnssd-dev', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-compat-libdnssd1', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-core-dev', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-core7', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-glib-dev', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-glib1', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-gobject-dev', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-gobject0', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-ui-gtk3-0', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'libavahi-ui-gtk3-dev', 'reference': '0.8-5+deb11u3'},
    {'release': '11.0', 'prefix': 'python3-avahi', 'reference': '0.8-5+deb11u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'avahi-autoipd / avahi-daemon / avahi-discover / avahi-dnsconfd / etc');
}
