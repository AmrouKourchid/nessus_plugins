#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0020-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(189103);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/17");

  script_cve_id(
    "CVE-2023-6508",
    "CVE-2023-6509",
    "CVE-2023-6510",
    "CVE-2023-6511",
    "CVE-2023-6512",
    "CVE-2023-6702",
    "CVE-2023-6703",
    "CVE-2023-6704",
    "CVE-2023-6705",
    "CVE-2023-6706",
    "CVE-2023-6707",
    "CVE-2023-7024",
    "CVE-2024-0222",
    "CVE-2024-0223",
    "CVE-2024-0224",
    "CVE-2024-0225",
    "CVE-2024-0333"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/01/23");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2024:0020-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0020-1 advisory.

  - Use after free in Media Stream in Google Chrome prior to 120.0.6099.62 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6508)

  - Use after free in Side Panel Search in Google Chrome prior to 120.0.6099.62 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    UI interaction. (Chromium security severity: High) (CVE-2023-6509)

  - Use after free in Media Capture in Google Chrome prior to 120.0.6099.62 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    UI interaction. (Chromium security severity: Medium) (CVE-2023-6510)

  - Inappropriate implementation in Autofill in Google Chrome prior to 120.0.6099.62 allowed a remote attacker
    to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-6511)

  - Inappropriate implementation in Web Browser UI in Google Chrome prior to 120.0.6099.62 allowed a remote
    attacker to potentially spoof the contents of an iframe dialog context menu via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2023-6512)

  - Type confusion in V8 in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-6702)

  - Use after free in Blink in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-6703)

  - Use after free in libavif in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to
    potentially exploit heap corruption via a crafted image file. (Chromium security severity: High)
    (CVE-2023-6704)

  - Use after free in WebRTC in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-6705)

  - Use after free in FedCM in Google Chrome prior to 120.0.6099.109 allowed a remote attacker who convinced a
    user to engage in specific UI interaction to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-6706)

  - Use after free in CSS in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-6707)

  - Heap buffer overflow in WebRTC in Google Chrome prior to 120.0.6099.129 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-7024)

  - Use after free in ANGLE in Google Chrome prior to 120.0.6099.199 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2024-0222)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 120.0.6099.199 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0223)

  - Use after free in WebAudio in Google Chrome prior to 120.0.6099.199 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0224)

  - Use after free in WebGPU in Google Chrome prior to 120.0.6099.199 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-0225)

  - Insufficient data validation in Extensions in Google Chrome prior to 120.0.6099.216 allowed an attacker in
    a privileged network position to install a malicious extension via a crafted HTML page. (Chromium security
    severity: High) (CVE-2024-0333)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218719");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2KWUFI7NWEEY53YIAANSM3OSYVP7LTDM/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?964a3ce9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6511");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6512");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0223");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0225");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0333");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0225");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
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
    {'reference':'chromedriver-120.0.6099.216-bp155.2.64.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-120.0.6099.216-bp155.2.64.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-120.0.6099.216-bp155.2.64.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-120.0.6099.216-bp155.2.64.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}
