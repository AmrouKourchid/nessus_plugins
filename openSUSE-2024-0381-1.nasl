#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0381-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212495);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_name(english:"openSUSE 15 Security Update : seamonkey (openSUSE-SU-2024:0381-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2024:0381-1 advisory.

    Update to SeaMonkey 2.53.19:

      * Cancel button in SeaMonkey bookmarking star ui not working bug
        1872623.
      * Remove OfflineAppCacheHelper.jsm copy from SeaMonkey and use the
        one in toolkit bug 1896292.
      * Remove obsolete registerFactoryLocation calls from cZ bug 1870930.
      * Remove needless implements='nsIDOMEventListener' and QI bug
        1611010.
      * Replace use of nsIStandardURL::Init bug 1864355.
      * Switch SeaMonkey website from hg.mozilla.org to heptapod. bug
        1870934.
      * Allow view-image to open a data: URI by setting a flag on the
        loadinfo bug 1877001.
      * Save-link-as feature should use the loading principal and context
        menu using nsIContentPolicy.TYPE_SAVE_AS_DOWNLOAD bug 1879726.
      * Use punycode in SeaMonkey JS bug 1864287.
      * Font lists in preferences are no longer grouped by font type, port
        asynchronous handling like Bug 1399206 bug 1437393.
      * SeaMonkey broken tab after undo closed tab with invalid protocol
        bug 1885748.
      * SeaMonkey session restore is missing the checkboxes in the Classic
        theme bug 1896174.
      * Implement about:credits on seamonkey-project.org website bug
        1898467.
      * Fix for the 0.0.0.0 day vulnerability oligo summary.
      * Link in update notification does not open Browser bug 1888364.
      * Update ReadExtensionPrefs in Preferences.cpp bug 1890196.
      * Add about:seamonkey page to SeaMonkey bug 1897801.
      * SeaMonkey 2.53.19 uses the same backend as Firefox and contains
        the relevant Firefox 60.8 security fixes.
      * SeaMonkey 2.53.19 shares most parts of the mail and news code with
        Thunderbird. Please read the Thunderbird 60.8.0 release notes for
        specific security fixes in this release.
      * Additional important security fixes up to Current Firefox 115.14
        and Thunderbird 115.14 ESR plus many enhancements have been
        backported. We will continue to enhance SeaMonkey security in
        subsequent 2.53.x beta and release versions as fast as we are able
        to.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230257");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZCBM65JXGQLO4VAA4PM3Q466RSC2IZRV/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83b72c69");
  script_set_attribute(attribute:"solution", value:
"Update the affected seamonkey, seamonkey-dom-inspector and / or seamonkey-irc packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'seamonkey-2.53.19-bp155.2.23.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'seamonkey-dom-inspector-2.53.19-bp155.2.23.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'seamonkey-irc-2.53.19-bp155.2.23.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'seamonkey / seamonkey-dom-inspector / seamonkey-irc');
}
