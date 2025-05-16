#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3801. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(194482);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2024-30203", "CVE-2024-30204", "CVE-2024-30205");
  script_xref(name:"IAVA", value:"2024-A-0247-S");

  script_name(english:"Debian dla-3801 : emacs - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3801 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3801-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Sean Whitton
    April 29, 2024                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : emacs
    Version        : 1:26.1+1-3.2+deb10u5
    CVE ID         : CVE-2024-30203 CVE-2024-30204 CVE-2024-30205
    Debian Bug     : 1067630

    Multiple problems were discovered in GNU Emacs, the extensible,
    customisable, self-documenting display editor.

    CVE-2024-30203 & CVE-2024-30204

        In Emacs before 29.3, LaTeX preview is enabled by default for e-mail
        attachments in some Emacs MUAs.  This can lead to denial of service.

        (A request has been submitted to MITRE to merge these CVE numbers.)

    CVE-2024-30205

        In Emacs before 29.3, Org mode considers the contents of remote
        files to be trusted.  This affects Org Mode before 9.6.23.

    For Debian 10 buster, these problems have been fixed in version
    1:26.1+1-3.2+deb10u5.

    We recommend that you upgrade your emacs packages.

    For the detailed security status of emacs please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/emacs

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/emacs");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-30203");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-30204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-30205");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/emacs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the emacs packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30205");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs21-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs22-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs22-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs23-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs23-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs24-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs24-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs25-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs25-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'emacs', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs-bin-common', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs-common', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs-el', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs-gtk', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs-lucid', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs-nox', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs21', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs21-nox', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs22', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs22-gtk', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs22-nox', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs23', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs23-lucid', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs23-nox', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs24', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs24-lucid', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs24-nox', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs25', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs25-lucid', 'reference': '1:26.1+1-3.2+deb10u5'},
    {'release': '10.0', 'prefix': 'emacs25-nox', 'reference': '1:26.1+1-3.2+deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'emacs / emacs-bin-common / emacs-common / emacs-el / emacs-gtk / etc');
}
