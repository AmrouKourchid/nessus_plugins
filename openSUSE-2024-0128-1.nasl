#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0128-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197295);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

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
    "CVE-2024-3914"
  );

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2024:0128-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0128-1 advisory.

  - Object corruption in V8 in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to potentially
    exploit object corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3832)

  - Object corruption in WebAssembly in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to
    potentially exploit object corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3833)

  - Use after free in Downloads in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3834)

  - Use after free in QUIC in Google Chrome prior to 124.0.6367.60 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2024-3837)

  - Inappropriate implementation in Autofill in Google Chrome prior to 124.0.6367.60 allowed an attacker who
    convinced a user to install a malicious app to perform UI spoofing via a crafted app. (Chromium security
    severity: Medium) (CVE-2024-3838)

  - Out of bounds read in Fonts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2024-3839)

  - Insufficient policy enforcement in Site Isolation in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3840)

  - Insufficient data validation in Browser Switcher in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to inject scripts or HTML into a privileged page via a malicious file. (Chromium security
    severity: Medium) (CVE-2024-3841)

  - Insufficient data validation in Downloads in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3843)

  - Inappropriate implementation in Extensions in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to perform UI spoofing via a crafted Chrome Extension. (Chromium security severity: Low)
    (CVE-2024-3844)

  - Inappropriate implementation in Networks in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    to bypass mixed content policy via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-3845)

  - Inappropriate implementation in Prompts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2024-3846)

  - Insufficient policy enforcement in WebUI in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    to bypass content security policy via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2024-3847)

  - Use after free in V8 in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3914)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QVLMJIQMVDQI2D33EDKB65KEXN6OMIRX/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?030c9c19");
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
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3837");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/17");

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
    {'reference':'opera-110.0.5130.23-lp155.3.45.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
