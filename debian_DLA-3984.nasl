#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3984. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(212155);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-36464",
    "CVE-2024-42330",
    "CVE-2024-42331",
    "CVE-2024-42332",
    "CVE-2024-42333"
  );
  script_xref(name:"IAVA", value:"2024-A-0836-S");

  script_name(english:"Debian dla-3984 : zabbix-agent - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3984 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3984-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    December 07, 2024                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : zabbix
    Version        : 1:5.0.45+dfsg-1+deb11u1
    CVE ID         : CVE-2024-36464 CVE-2024-42330 CVE-2024-42331 CVE-2024-42332
                     CVE-2024-42333
    Debian Bug     : 1088689

    Several security vulnerabilities have been discovered in zabbix, a network
    monitoring solution, potentially among other effects allowing denial of
    service, information disclosure, use-after-free or remote code inclusion.


    CVE-2024-36464

        When exporting media types, the password is exported in the YAML in
        plain text. This appears to be a best practices type issue and may
        have no actual impact. The user would need to have permissions to
        access the media types and therefore would be expected to have
        access to these passwords.

    CVE-2024-42330

        The HttpRequest object allows to get the HTTP headers from the
        server's response after sending the request. The problem is that the
        returned strings are created directly from the data returned by the
        server and are not correctly encoded for JavaScript. This allows to
        create internal strings that can be used to access hidden properties
        of objects.

    CVE-2024-42331

        In the src/libs/zbxembed/browser.c file, the es_browser_ctor method
        retrieves a heap pointer from the Duktape JavaScript engine. This
        heap pointer is subsequently utilized by the browser_push_error
        method in the src/libs/zbxembed/browser_error.c file. A
        use-after-free bug can occur at this stage if the wd->browser heap
        pointer is freed by garbage collection.

    CVE-2024-42332

        The researcher is showing that due to the way the SNMP trap log is
        parsed, an attacker can craft an SNMP trap with additional lines of
        information and have forged data show in the Zabbix UI. This attack
        requires SNMP auth to be off and/or the attacker to know the
        community/auth details. The attack requires an SNMP item to be
        configured as text on the target host.

    CVE-2024-42333

        The researcher is showing that it is possible to leak a small amount
        of Zabbix Server memory using an out of bounds read in
        src/libs/zbxmedia/email.c

    For Debian 11 bullseye, these problems have been fixed in version
    1:5.0.45+dfsg-1+deb11u1.

    We recommend that you upgrade your zabbix packages.

    For the detailed security status of zabbix please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/zabbix

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/zabbix");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36464");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42330");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42331");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42332");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42333");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/zabbix");
  script_set_attribute(attribute:"solution", value:
"Upgrade the zabbix-agent packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42330");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-frontend-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-java-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-server-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'zabbix-agent', 'reference': '1:5.0.45+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-frontend-php', 'reference': '1:5.0.45+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-java-gateway', 'reference': '1:5.0.45+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-proxy-mysql', 'reference': '1:5.0.45+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-proxy-pgsql', 'reference': '1:5.0.45+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-proxy-sqlite3', 'reference': '1:5.0.45+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-server-mysql', 'reference': '1:5.0.45+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-server-pgsql', 'reference': '1:5.0.45+dfsg-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'zabbix-agent / zabbix-frontend-php / zabbix-java-gateway / etc');
}
