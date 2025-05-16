#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4064. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216663);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2017-9047",
    "CVE-2022-49043",
    "CVE-2023-39615",
    "CVE-2023-45322",
    "CVE-2024-25062",
    "CVE-2024-56171",
    "CVE-2025-24928",
    "CVE-2025-27113"
  );
  script_xref(name:"IAVA", value:"2024-A-0067-S");
  script_xref(name:"IAVA", value:"2025-A-0123-S");

  script_name(english:"Debian dla-4064 : libxml2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4064 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4064-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    February 22, 2025                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libxml2
    Version        : 2.9.10+dfsg-6.7+deb11u6
    CVE ID         : CVE-2022-49043 CVE-2023-39615 CVE-2023-45322 CVE-2024-25062
                     CVE-2024-56171 CVE-2025-24928 CVE-2025-27113
    Debian Bug     : 1051230 1053629 1063234 1094238 1098320 1098321 1098322

    Multiple vulnerabilities have been found in libxml2, a library providing
    support to read, modify and write XML and HTML files. These
    vulnerabilities could potentially lead to denial of servie or other
    unintended behaviors.

    CVE-2022-49043

        xmlXIncludeAddNode in xinclude.c in libxml2 before 2.11.0 has a
        use-after-free.

    CVE-2023-39615

        libxml2 v2.11.0 was discovered to contain an out-of-bounds read via
        the xmlSAX2StartElement() function at /libxml2/SAX2.c. This
        vulnerability allows attackers to cause a Denial of Service (DoS)
        via supplying a crafted XML file. NOTE: the vendor's position is
        that the product does not support the legacy SAX1 interface with
        custom callbacks; there is a crash even without crafted input.

    CVE-2023-45322

        libxml2 through 2.11.5 has a use-after-free that can only occur
        after a certain memory allocation fails. This occurs in
        xmlUnlinkNode in tree.c. NOTE: the vendor's position is I don't
        think these issues are critical enough to warrant a CVE ID ...
        because an attacker typically can't control when memory allocations
        fail.

    CVE-2024-25062

        An issue was discovered in libxml2 before 2.11.7 and 2.12.x before
        2.12.5. When using the XML Reader interface with DTD validation and
        XInclude expansion enabled, processing crafted XML documents can
        lead to an xmlValidatePopElement use-after-free.

    CVE-2024-56171

        libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a use-after-free
        in xmlSchemaIDCFillNodeTables and xmlSchemaBubbleIDCNodeTables in
        xmlschemas.c. To exploit this, a crafted XML document must be
        validated against an XML schema with certain identity constraints,
        or a crafted XML schema must be used.

    CVE-2025-24928

        libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a stack-based
        buffer overflow in xmlSnprintfElements in valid.c. To exploit this,
        DTD validation must occur for an untrusted document or untrusted
        DTD. NOTE: this is similar to CVE-2017-9047.

    CVE-2025-27113

        libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a NULL pointer
        dereference in xmlPatMatch in pattern.c.

    For Debian 11 bullseye, these problems have been fixed in version
    2.9.10+dfsg-6.7+deb11u6.

    We recommend that you upgrade your libxml2 packages.

    For the detailed security status of libxml2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libxml2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libxml2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-9047");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-49043");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39615");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45322");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25062");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56171");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-24928");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-27113");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libxml2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libxml2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9047");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-27113");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'libxml2', 'reference': '2.9.10+dfsg-6.7+deb11u6'},
    {'release': '11.0', 'prefix': 'libxml2-dev', 'reference': '2.9.10+dfsg-6.7+deb11u6'},
    {'release': '11.0', 'prefix': 'libxml2-doc', 'reference': '2.9.10+dfsg-6.7+deb11u6'},
    {'release': '11.0', 'prefix': 'libxml2-utils', 'reference': '2.9.10+dfsg-6.7+deb11u6'},
    {'release': '11.0', 'prefix': 'python3-libxml2', 'reference': '2.9.10+dfsg-6.7+deb11u6'},
    {'release': '11.0', 'prefix': 'python3-libxml2-dbg', 'reference': '2.9.10+dfsg-6.7+deb11u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxml2 / libxml2-dev / libxml2-doc / libxml2-utils / python3-libxml2 / etc');
}
