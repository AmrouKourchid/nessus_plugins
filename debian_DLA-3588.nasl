#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3588. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(182369);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-4752", "CVE-2023-4781");
  script_xref(name:"IAVB", value:"2023-B-0066-S");

  script_name(english:"Debian dla-3588 : vim - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3588 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3588-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    September 29, 2023                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : vim
    Version        : 2:8.1.0875-5+deb10u6
    CVE ID         : CVE-2023-4752 CVE-2023-4781

    Multiple vulnerabilities were found in vim a text editor.

    CVE-2023-4752

        A heap use after free was found in ins_compl_get_exp()

    CVE-2023-4781

        A heap-buffer-overflow was found in vim_regsub_both()

    For Debian 10 buster, these problems have been fixed in version
    2:8.1.0875-5+deb10u6.

    We recommend that you upgrade your vim packages.

    For the detailed security status of vim please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/vim

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/vim");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4781");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/vim");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4781");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xxd");
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
    {'release': '10.0', 'prefix': 'vim', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-athena', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-common', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-doc', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-gtk', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-gtk3', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-gui-common', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-nox', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-runtime', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'vim-tiny', 'reference': '2:8.1.0875-5+deb10u6'},
    {'release': '10.0', 'prefix': 'xxd', 'reference': '2:8.1.0875-5+deb10u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-common / vim-doc / vim-gtk / vim-gtk3 / etc');
}
