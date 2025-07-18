#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4059. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216526);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id("CVE-2024-3935", "CVE-2024-10525");

  script_name(english:"Debian dla-4059 : libmosquitto-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4059 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4059-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Abhijith PA
    February 20, 2025                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : mosquitto
    Version        : 2.0.11-1+deb11u2
    CVE ID         : CVE-2024-3935 CVE-2024-10525


    The following vulnerabilities have been discovered in the package
    mosquitto, MQTT message broker.

    CVE-2024-3935

        If a Mosquitto broker is configured to create an outgoing bridge
        connection, and that bridge connection has an incoming topic
        configured that makes use of topic remapping, then if the remote
        connection sends a crafted PUBLISH packet to the broker a double
        free will occur with a subsequent crash of the broker.


    CVE-2024-10525

        If a malicious broker sends a crafted SUBACK packet with no reason
        codes, a client using libmosquitto may make out of bounds memory
        access when acting in its on_subscribe callback. This affects the
        mosquitto_sub and mosquitto_rr clients.


    For Debian 11 bullseye, these problems have been fixed in version
    2.0.11-1+deb11u2.

    We recommend that you upgrade your mosquitto packages.

    For the detailed security status of mosquitto please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/mosquitto

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mosquitto");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-10525");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3935");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/mosquitto");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libmosquitto-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10525");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'release': '11.0', 'prefix': 'libmosquitto-dev', 'reference': '2.0.11-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libmosquitto1', 'reference': '2.0.11-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libmosquittopp-dev', 'reference': '2.0.11-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libmosquittopp1', 'reference': '2.0.11-1+deb11u2'},
    {'release': '11.0', 'prefix': 'mosquitto', 'reference': '2.0.11-1+deb11u2'},
    {'release': '11.0', 'prefix': 'mosquitto-clients', 'reference': '2.0.11-1+deb11u2'},
    {'release': '11.0', 'prefix': 'mosquitto-dev', 'reference': '2.0.11-1+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmosquitto-dev / libmosquitto1 / libmosquittopp-dev / etc');
}
