#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0012-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214241);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/16");

  script_cve_id("CVE-2024-11395");

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2025:0012-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by a vulnerability as referenced in the openSUSE-
SU-2025:0012-1 advisory.

    - Update to 116.0.5366.21
      * CHR-9904 Update Chromium on desktop-stable-131-5366 to
        131.0.6778.86
      * DNA-119581 Crash at views::View::ConvertPointToTarget
      * DNA-119847 Missing Opera warning color and some margins
        in Settings
      * DNA-119853 Eula dialog is wrong displayed and can not run
        installation with system scale 125%
      * DNA-119883 Dark mode: side bar player icons have
        no background
        * DNA-120054 Double icon effect in adress bar
      * DNA-120117 [Player] Crash when trying to Inspect Element
        on player's web page in panel
      * DNA-120155 Crash on opera:extensions with color-themes
        flag disabled
      * DNA-120195 Scroll in Theme Gallery view changes to dark
        color in Dark Mode
      * DNA-120211 Crash at extensions::
        TabsPrivateGetAllInWindowFunction::Run
      * DNA-120230 Start page button is blurry
      * DNA-120240 Dropdown display lacks expected overlay effect
      * DNA-120242 Translations for Opera 116
      * DNA-120317 Crash at opera::BrowserWindowImpl::
        SetBrowserUIVisible
      * DNA-120458 Crash at opera::BrowserWindowImpl::
        AddWidgetToTracked
      * DNA-120512 Promote 116.0 to stable
    - Complete Opera 116 changelog at:
      https://blogs.opera.com/desktop/changelog-for-116
    - The update to chromium 131.0.6778.86 fixes following issues:
      CVE-2024-11395


    - Update to 115.0.5322.119
      * CHR-9416 Updating Chromium on desktop-stable-* branches
      * DNA-120117 [Player] Crash when trying to Inspect Element on
        player's web page in panel
      * DNA-120211 Crash at extensions::
        TabsPrivateGetAllInWindowFunction::Run

    - Update to 115.0.5322.109
      * CHR-9416 Updating Chromium on desktop-stable-* branches
      * DNA-118730 Crash at opera::content_filter::
        AdBlockerWhitelistHandler::SetSiteBlocked
      * DNA-119320 [Mac] Web view corners not rounded
      * DNA-119421 [Easy setup] Dropdown for theme editing do not
        close after opening other dropdowns
      * DNA-119519 Implement stop mechanism for video as wallpaper
      * DNA-119550 Collect common shader rendering code in
        Rich Wallpaper
      * DNA-119551 Convert Midsommar to new shader-based dynamic
        theme format
      * DNA-119552 Convert Aurora to new shader-based dynamic
        theme format
      * DNA-119553 Pass configuration data to shader-based
        dynamic themes
      * DNA-119554 Logic for pause / resume animations in rich
        wallpaper page
      * DNA-119645 Install theme from the server
      * DNA-119652 Show spinner while downloading & installing theme
      * DNA-119692 'start now' button not translated in hindi
      * DNA-119783 Toggles in Dark Mode unchecked state missed
        background color
      * DNA-119811 Show download icon on hover
      * DNA-119812 Implement downloading new theme by clicking
        download button
      * DNA-119813 Implement selecting new theme by clicking tile
      * DNA-119814 Implement canceling theme download API
      * DNA-119815 Implement canceling theme download UI
      * DNA-119816 Handle error callback from download/install
      * DNA-119817 Implement ability to see themes being downloaded
        when opening themes gallery
      * DNA-119834 Sometimes onboarding is blank and useless
      * DNA-119835 Crash at opera::VibesServiceImpl::OnVibeInstalled
      * DNA-119846 Animated wallpapers doesn't work in Classic theme
      * DNA-119848 Add tests for addonsPrivate.cancelInstallation and
        isThemeInstallationPending
      * DNA-119863 Create a configuration for preinstalled theme
      * DNA-119924 Relaunch button resets the toggle instead of
        relaunching browser
      * DNA-119979 Crash at opera::VibesDataReaderImpl::
        LoadDefaultColorsForVibe
      * DNA-119983 DevTools reverts to Light Mode after restart
      * DNA-120018 Context menus not opening for some internal pages
      * DNA-120020 The light mode icon on the mixer page is nearly
        invisible
      * DNA-120210 Crash at base::internal::flat_tree::contains

    - Update to 115.0.5322.77
      * CHR-9896 Update Chromium on desktop-stable-130-5322 to
        130.0.6723.137
      * DNA-119410 Crash at opera::WebPanelView::ClosePanel
      * DNA-119466 Unable to open easy setup page when color-theme
        flag is disabled
      * DNA-119955 [My Flow] downloading a file never ends

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Q3PEGRWS7VSTXHREFS3ULWWCUPH6HWX2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3776498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-11395");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/16");

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
    {'reference':'opera-116.0.5366.21-lp156.2.26.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
