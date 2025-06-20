#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4069. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216874);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2023-28617", "CVE-2024-53920", "CVE-2025-1244");

  script_name(english:"Debian dla-4069 : emacs - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4069 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4069-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Sean Whitton
    February 27, 2025                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : emacs
    Version        : 1:27.1+1-3.1+deb11u6
    CVE ID         : CVE-2023-28617 CVE-2024-53920 CVE-2025-1244
    Debian Bug     : 1033342 1088690 1098255

    Multiple vulnerabilities were discovered in GNU Emacs, the extensible,
    customisable, self-documenting, real-time display editor.

    CVE-2023-28617

        Improper handling of file or directory names containing shell
        metacharacters in the ob-latex Lisp library could allow the
        execution of attacker-controlled code.

    CVE-2024-53920

        Several ways to trigger arbitrary code execution were discovered in
        Emacs's support for editing files in its own dialect of Lisp.
        These include arbitrary code execution upon opening an otherwise
        innocent-looking file, with any (or no) file extension, for editing.

    CVE-2025-1244

        Improper handling of custom 'man' URI schemes could allow an
        attacker to execute arbitrary shell commands by tricking users into
        visiting a specially crafted website, or an HTTP URL with a
        redirect.

    For Debian 11 bullseye, these problems have been fixed in version
    1:27.1+1-3.1+deb11u6.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-53920");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-1244");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/emacs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the emacs packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs-nox");
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
    {'release': '11.0', 'prefix': 'emacs', 'reference': '1:27.1+1-3.1+deb11u6'},
    {'release': '11.0', 'prefix': 'emacs-bin-common', 'reference': '1:27.1+1-3.1+deb11u6'},
    {'release': '11.0', 'prefix': 'emacs-common', 'reference': '1:27.1+1-3.1+deb11u6'},
    {'release': '11.0', 'prefix': 'emacs-el', 'reference': '1:27.1+1-3.1+deb11u6'},
    {'release': '11.0', 'prefix': 'emacs-gtk', 'reference': '1:27.1+1-3.1+deb11u6'},
    {'release': '11.0', 'prefix': 'emacs-lucid', 'reference': '1:27.1+1-3.1+deb11u6'},
    {'release': '11.0', 'prefix': 'emacs-nox', 'reference': '1:27.1+1-3.1+deb11u6'}
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
