#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0111-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(233751);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id("CVE-2025-2783");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/17");

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2025:0111-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by a vulnerability as referenced in the openSUSE-
SU-2025:0111-1 advisory.

    - Update to 117.0.5408.163
      * DNA-120683 [Issue back] Sometimes onboarding is blank
        and useless
      * DNA-121682 Backport fix for CVE-2025-2783 to O132, O133,
        GX132 and Air132
    - Changes in 117.0.5408.154
      * DNA-121210 After enabling tab scrolling, the tab bar narrows
        on both the left and right sides
      * DNA-121560 Extension updates which requires manual
        confirmation do not work
    - Changes in 117.0.5408.142
      * DNA-121314 Use the extra palette color to paint the frame
      * DNA-121321 Refactor ColorSet struct
      * DNA-121444 Crash at opera::VibesServiceImpl::VibesServiceImpl
      * DNA-121477 Add unit tests for ColorSet
      * DNA-121488 [ASAN] ColorSetTest.DefaultConstructor fails
    - Changes in 117.0.5408.93
      * DNA-118548 After pressing Ctrl+F / Cmd+F on the Start Page
        (SP), the focus should be on the search bar
      * DNA-121183 Add 'transparent UI' parameter to Vibe logic
      * DNA-121184 Allow to specify extra palette for window
        background in Vibe logic
      * DNA-121232 Enable Slack, Discord and Bluesky flag on
        all streams
      * DNA-121237 Crash at opera::SidebarExpandViewEmbedder::Position
      * DNA-121322 [Opera Translate] [Redesign] Expired #translator
        flag
      * DNA-121385 Remove 'passkey' string

    - Update to 117.0.5408.53
      * DNA-120848 Add 'x' button to close/dismiss translate popup
      * DNA-120849 Dismissing popup adds language to never translate
        from list
      * DNA-120951 Optimize MFSVE output handling
      * DNA-120972 Crash at TabDesktopMediaList::Refresh
      * CHR-9964 Update Chromium on desktop-stable-132-5408 to
        132.0.6834.210
    Changes in 117.0.5408.47
      * CHR-9961 Update Chromium on desktop-stable-132-5408 to
        132.0.6834.209

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SJEX6ZT5W5GYLZEQIA7L2J32HG4KGMAX/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4573f70");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-2783");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2783");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'opera-117.0.5408.163-lp156.2.32.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opera');
}
