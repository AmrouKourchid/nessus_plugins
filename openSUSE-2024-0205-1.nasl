#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0205-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(202753);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2024-5830",
    "CVE-2024-5831",
    "CVE-2024-5832",
    "CVE-2024-5833",
    "CVE-2024-5834",
    "CVE-2024-5835",
    "CVE-2024-5836",
    "CVE-2024-5837",
    "CVE-2024-5838",
    "CVE-2024-5839",
    "CVE-2024-5840",
    "CVE-2024-5841",
    "CVE-2024-5842",
    "CVE-2024-5843",
    "CVE-2024-5844",
    "CVE-2024-5845",
    "CVE-2024-5846",
    "CVE-2024-5847",
    "CVE-2024-6290",
    "CVE-2024-6291",
    "CVE-2024-6292",
    "CVE-2024-6293"
  );

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2024:0205-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0205-1 advisory.

    - Update to 112.0.5197.25

      * CHR-9787 Update Chromium on desktop-stable-126-5197 to
        126.0.6478.127

    - The update to chromium 126.0.6478.127 fixes following issues:
      CVE-2024-6290, CVE-2024-6291, CVE-2024-6292, CVE-2024-6293

    - Update to 112.0.5197.24

      * CHR-9762 Update Chromium on desktop-stable-126-5197 to
        126.0.6478.62
      * DNA-117001 Crash at base::internal::check_is_test_impl
        (base::NotFatalUntil)
      * DNA-117050 [Settings][Sync] Synchronization options aren't
        visible
      * DNA-117076 [Player] Background of the icons has changed and
        the Tidal icon is now missing
      * DNA-117109 Browser freezes when trying to remove a tab
      * DNA-117181 Translations for O112
      * DNA-117202 Crash at syncer::SyncServiceImpl::NotifyObservers()
      * DNA-117295 Remove emoji names field in picker
      * DNA-117347 Start page is not rendered on first switch to
        workspace after its creation
      * DNA-117431 Promote 112 to stable

    - Complete Opera 112 changelog at:
      https://blogs.opera.com/desktop/changelog-for-112

    - The update to chromium >= 126.0.6478.54 fixes following issues:
      CVE-2024-5830, CVE-2024-5831, CVE-2024-5832, CVE-2024-5833,
      CVE-2024-5834, CVE-2024-5835, CVE-2024-5836, CVE-2024-5837,
      CVE-2024-5838, CVE-2024-5839, CVE-2024-5840, CVE-2024-5841,
      CVE-2024-5842, CVE-2024-5843, CVE-2024-5844, CVE-2024-5845,
      CVE-2024-5846, CVE-2024-5847

    - Update to 111.0.5168.55
      * DNA-116749 Unnecessary icons in the advanced sync settings
      * DNA-116961 Evaluate #vtvd-as-platform-sw-decoder in the field
      * DNA-117003 #vtvd-as-platform-sw-decoder is not registered in
        media unittests

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NHZIGJFBH37236FBCT6ZIM4Q4SHU345J/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46d8ba9b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6293");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6293");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/22");

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
    {'reference':'opera-112.0.5197.25-lp155.3.54.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
