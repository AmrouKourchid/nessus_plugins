#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-e142be4915
#

include('compat.inc');

if (description)
{
  script_id(205287);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/09");
  script_xref(name:"FEDORA", value:"2024-e142be4915");

  script_name(english:"Fedora 40 : xrdp (2024-e142be4915)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2024-e142be4915 advisory.

    Release notes for xrdp v0.10.1 (2024/07/31)

    General announcements

    A clipboard bugfix included in this release is sponsored by Krmer Pferdesport GmbH & Co KG. We very much
    appreciate the sponsorship.

    Please consider sponsoring or making a donation to the project if you like xrdp. We accept financial
    contributions via Open Collective. Direct donations to each developer via GitHub Sponsors are also
    welcomed.
    Security fixes

     - Unauthenticated RDP security scan finding / partial auth bypass (no CVE). Thanks to @txtdawg for
    reporting this.

    New features

     - GFX-RFX lossy compression levels are now selectable depending on connection type on the client (#3183,
    backport of #2973)

    Bug fixes

     - A regression in the code for creating the chansrv FUSE directory has been fixed (#3088, backport of
    #3082)
     - Fix a systemd dependency (network-online.target) (#3088, backport of #3086)
     - A problem in session list processing which could result in incorrect display assignments has been fixed
    (#3088, backport of #3103)
     - A problem in GFX resizing which could lead to a SEGV in xrdp has been fixed (#3088, backport of #3107)
     - A problem with the US Dvorak keyboard layout has been resolved (#3088, backport of #3112)
     - A regression bug when pasting image to LibreOffice has been fixed [Sponsored by Krmer Pferdesport
    GmbH & Co KG] (#3102 #3120)
     - Fix a regression when the server tries to negotiate GFX when max_bpp is not high enough (#3118 #3122)
     - Fix a GFX multi-monitor screen placing issue on minimise/maximize (#3075 #3127)
     - Fix an issue some files are not included properly in release tarball (#3149 #3150)
     - Using 'I' in the session selection policy now works correctly (#3167 #3171)
     - A potential name buffer overflow in the redirector has been fixed [no security implications] (#3175)
     - Screens wider than 4096 pixels should now be supported (#3083)
     - An unnecessary licensing exchange during connection setup has been removed. This was causing problems
    for FIPS-compliant clients (#3132 backport of #3143)

    Internal changes

     - FreeBSD CI bumped to 13.3 (#3088, backport of #3104)

    Changes for users

     - None since v0.10.0.
     - If moving from v0.9.x, read the v0.10.0 release note.

    Changes for packagers or developers

     - None since v0.10.0.
     - If moving from v0.9.x, read the v0.10.0 release note.

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e142be4915");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:xrdp package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xrdp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'xrdp-0.10.1-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xrdp');
}
