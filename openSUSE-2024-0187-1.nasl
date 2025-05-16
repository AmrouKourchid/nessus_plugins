#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0187-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(201941);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2024-5493",
    "CVE-2024-5494",
    "CVE-2024-5495",
    "CVE-2024-5496",
    "CVE-2024-5497",
    "CVE-2024-5498",
    "CVE-2024-5499"
  );

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2024:0187-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0187-1 advisory.

    - Update to 111.0.5168.43

      * DNA-115228 Adblocker is blocking ads when turned off
      * DNA-116605 Crash at opera::BrowserContentsView::
        NonClientHitTestPoint(gfx::Point const&)
      * DNA-116855 Cannot close tab islands tab when popup
        was hovered
      * DNA-116885 Add chrome.cookies api permission to Rich Hints
      * DNA-116948 [Linux] Theme toggle in settings is not working

    - Update to 111.0.5168.25

      * CHR-9754 Update Chromium on desktop-stable-125-5168 to
        125.0.6422.142
      * DNA-116089 [Win/Lin] Fullscreen view has rounded corners
      * DNA-116208 The red dot on the Arias icon is misaligned
      * DNA-116693 X (twitter) logo is not available on
        opera:about page
      * DNA-116737 [Bookmarks] Bookmarks bar favicon have light
        theme color in new window
      * DNA-116769 Extension popup  pin icon is replaced
      * DNA-116850 Fix full package installer link
      * DNA-116852 Promote 111 to stable
      * DNA-116491 Site info popup is cut with dropdown opened
      * DNA-116661 [opera:settings] IPFS/IPNS Gateway box has the
        wrong design
      * DNA-116789 Translations for O111
      * DNA-116813 [React emoji picker] Flag emojis are not load
        correctly
      * DNA-116893 Put 'Show emojis in tab tooltip' in Settings
      * DNA-116918 Translations for 'Show emojis in tab tooltip'
    - Complete Opera 111 changelog at:
      https://blogs.opera.com/desktop/changelog-for-111
    - The update to chromium 125.0.6422.142 fixes following issues:
      CVE-2024-5493, CVE-2024-5494, CVE-2024-5495, CVE-2024-5496,
      CVE-2024-5497, CVE-2024-5498, CVE-2024-5499

    - Update to 110.0.5130.64

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

    - Update to 110.0.5130.49

      * CHR-9416 Updating Chromium on desktop-stable-* branches
      * DNA-116706 [gpu-crash] Crash at SkGpuShaderImageFilter::
        onFilterImage(skif::Context const&)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6B5SLGYT6SKW4EUYZ5XLYQG66Y433XMH/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0262ee90");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5499");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5499");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
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
    {'reference':'opera-111.0.5168.43-lp155.3.51.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
