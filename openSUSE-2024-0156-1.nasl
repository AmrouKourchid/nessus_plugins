#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0156-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(200299);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2024-3832",
    "CVE-2024-3833",
    "CVE-2024-3834",
    "CVE-2024-3837",
    "CVE-2024-3838",
    "CVE-2024-3839",
    "CVE-2024-3840",
    "CVE-2024-3841",
    "CVE-2024-3843",
    "CVE-2024-3844",
    "CVE-2024-3845",
    "CVE-2024-3846",
    "CVE-2024-3847",
    "CVE-2024-3914",
    "CVE-2024-4671",
    "CVE-2024-5274"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/18");

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2024:0156-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0156-1 advisory.

    Update to 110.0.5130.64

      * CHR-9748 Update Chromium on desktop-stable-124-5130
        to 124.0.6367.243
      * DNA-116317 Create outline or shadow around emojis on tab strip
      * DNA-116320 Create animation for emoji disappearing from
        tab strip
      * DNA-116564 Assign custom emoji from emoji picker
      * DNA-116690 Make chrome://emoji-picker attachable by webdriver
      * DNA-116732 Introduce stat event for setting / unsetting emoji
        on a tab
      * DNA-116753 Emoji picker does not follow browser theme
      * DNA-116755 Record tab emojis added / removed
      * DNA-116777 Enable #tab-art on all streams

    Update to 110.0.5130.49

      * CHR-9416 Updating Chromium on desktop-stable-* branches
      * DNA-116706 [gpu-crash] Crash at SkGpuShaderImageFilter::
        onFilterImage(skif::Context const&)

    Update to 110.0.5130.39

      * DNA-115603 [Rich Hints] Pass trigger source to the Rich Hint
      * DNA-116680 Import 0-day fix for CVE-2024-5274

    Update to 110.0.5130.35

      * CHR-9721 Update Chromium on desktop-stable-124-5130 to
        124.0.6367.202
      * DNA-114787 Crash at views::View::DoRemoveChildView(views::
        View*, bool, bool, views::View*)
      * DNA-115640 Tab island is not properly displayed after
        drag&drop in light theme
      * DNA-116191 Fix link in RTV Euro CoS
      * DNA-116218 Crash at SkGpuShaderImageFilter::onFilterImage
        (skif::Context const&)
      * DNA-116241 Update affiliation link for media expert
        'Continue On'
      * DNA-116256 Crash at TabHoverCardController::UpdateHoverCard
        (opera::TabDataView*, TabHoverCardController::UpdateType,
        bool)
      * DNA-116270 Show 'Suggestions' inside expanding Speed Dial
        field
      * DNA-116474 Implement the no dynamic hover approach
      * DNA-116493 Make sure that additional elements like
        (Sync your browser) etc. doesnt shift content down on page
      * DNA-116515 Import 0-day fix from Chromium '[wasm-gc] Only
        normalize JSObject targets in SetOrCopyDataProperties'
      * DNA-116543 Twitter migrate to x.com
      * DNA-116552 Change max width of the banner
      * DNA-116569 Twitter in Panel loading for the first time opens
        two Tabs automatically
      * DNA-116587 Translate settings strings for every language

    The update to chromium 124.0.6367.202 fixes following issues:
      CVE-2024-4671

    Update to 110.0.5130.23

      * CHR-9706 Update Chromium on desktop-stable-124-5130 to
        124.0.6367.62
      * DNA-116450 Promote 110 to stable

    - Complete Opera 110 changelog at:
      https://blogs.opera.com/desktop/changelog-for-110/

    - The update to chromium 124.0.6367.62 fixes following issues:
      CVE-2024-3832, CVE-2024-3833, CVE-2024-3914, CVE-2024-3834,
      CVE-2024-3837, CVE-2024-3838, CVE-2024-3839, CVE-2024-3840,
      CVE-2024-3841, CVE-2024-3843, CVE-2024-3844, CVE-2024-3845,
      CVE-2024-3846, CVE-2024-3847

    - Update to 109.0.5097.80

      * DNA-115738 Crash at extensions::ExtensionRegistry::
        GetExtensionById(std::__Cr::basic_string const&, int)
      * DNA-115797 [Flow] Never ending loading while connecting to flow
      * DNA-116315 Chat GPT in Sidebar Panel doesnt work

    - Update to 109.0.5097.59

      * CHR-9416 Updating Chromium on desktop-stable-* branches
      * DNA-115810 Enable #drag-multiple-tabs on all streams

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PYKI7FIDICKYHO5TLIGQUUCUF2ATFWPR/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f019509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-4671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5274");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5274");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
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
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'opera-110.0.5130.64-lp156.2.6.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opera');
}
