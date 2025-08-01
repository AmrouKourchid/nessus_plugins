#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3953. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211508);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id(
    "CVE-2021-32739",
    "CVE-2021-32743",
    "CVE-2021-37698",
    "CVE-2024-49369"
  );
  script_xref(name:"IAVB", value:"2024-B-0186");

  script_name(english:"Debian dla-3953 : icinga2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3953 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3953-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Daniel Leidert
    November 16, 2024                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : icinga2
    Version        : 2.12.3-1+deb11u1
    CVE ID         : CVE-2021-32739 CVE-2021-32743 CVE-2021-37698 CVE-2024-49369
    Debian Bug     : 991494 1087384

    Icinga 2 is a general-purpose monitoring application to fit the needs
    of any size of network.

    CVE-2021-32739

        From version 2.4.0 through version 2.12.4, a vulnerability exists that
        may allow privilege escalation for authenticated API users. With a
        read-only user's credentials, an attacker can view most attributes of
        all config objects including `ticket_salt` of `ApiListener`. This salt
        is enough to compute a ticket for every possible common name (CN). A
        ticket, the master node's certificate, and a self-signed certificate are
        enough to successfully request the desired certificate from Icinga. That
        certificate may in turn be used to steal an endpoint or API user's
        identity.

    CVE-2021-32743

        In versions prior to 2.11.10 and from version 2.12.0 through version
        2.12.4, some of the Icinga 2 features that require credentials for
        external services expose those credentials through the API to
        authenticated API users with read permissions for the corresponding
        object types. An attacker who obtains these credentials can impersonate
        Icinga to these services and add, modify and delete information there.

    CVE-2021-37698

        In versions 2.5.0 through 2.13.0, ElasticsearchWriter, GelfWriter,
        InfluxdbWriter and Influxdb2Writer do not verify the server's certificate
        despite a certificate authority being specified. Icinga 2 instances which
        connect to any of the mentioned time series databases (TSDBs) using TLS
        over a spoofable infrastructure should change the credentials (if any)
        used by the TSDB writer feature to authenticate against the TSDB.

    CVE-2024-49369

        The TLS certificate validation in all Icinga 2 versions starting from
        2.4.0 was flawed, allowing an attacker to impersonate both trusted
        cluster nodes as well as any API users that use TLS client certificates
        for authentication (ApiUser objects with the client_cn attribute set).

    For Debian 11 bullseye, these problems have been fixed in version
    2.12.3-1+deb11u1.

    We recommend that you upgrade your icinga2 packages.

    For the detailed security status of icinga2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/icinga2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/icinga2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32739");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32743");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37698");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49369");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/icinga2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the icinga2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32743");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-ido-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icinga2-ido-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-icinga2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'icinga2', 'reference': '2.12.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'icinga2-bin', 'reference': '2.12.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'icinga2-common', 'reference': '2.12.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'icinga2-doc', 'reference': '2.12.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'icinga2-ido-mysql', 'reference': '2.12.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'icinga2-ido-pgsql', 'reference': '2.12.3-1+deb11u1'},
    {'release': '11.0', 'prefix': 'vim-icinga2', 'reference': '2.12.3-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'icinga2 / icinga2-bin / icinga2-common / icinga2-doc / etc');
}
