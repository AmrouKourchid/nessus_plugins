#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3761-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181674);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/20");

  script_cve_id(
    "CVE-2021-41411",
    "CVE-2021-42740",
    "CVE-2021-43138",
    "CVE-2022-0860",
    "CVE-2022-31129"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3761-1");

  script_name(english:"SUSE SLES15 Security Update : release-notes-susemanager, release-notes-susemanager-proxy (SUSE-SU-2022:3761-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3761-1 advisory.

  - drools <=7.59.x is affected by an XML External Entity (XXE) vulnerability in KieModuleMarshaller.java. The
    Validator class is not used correctly, resulting in the XXE injection vulnerability. (CVE-2021-41411)

  - The shell-quote package before 1.7.3 for Node.js allows command injection. An attacker can inject
    unescaped shell metacharacters through a regex designed to support Windows drive letters. If the output of
    this package is passed to a real shell as a quoted argument to a command with exec(), an attacker can
    inject arbitrary commands. This is because the Windows drive letter regex character class is {A-z] instead
    of the correct {A-Za-z]. Several shell metacharacters exist in the space between capital letter Z and
    lower case letter a, such as the backtick character. (CVE-2021-42740)

  - In Async before 2.6.4 and 3.x before 3.2.2, a malicious user can obtain privileges via the mapValues()
    method, aka lib/internal/iterator.js createObjectIterator prototype pollution. (CVE-2021-43138)

  - Improper Authorization in GitHub repository cobbler/cobbler prior to 3.3.2. (CVE-2022-0860)

  - moment is a JavaScript date library for parsing, validating, manipulating, and formatting dates. Affected
    versions of moment were found to use an inefficient parsing algorithm. Specifically using string-to-date
    parsing in moment (more specifically rfc2822 parsing, which is tried by default) has quadratic (N^2)
    complexity on specific inputs. Users may notice a noticeable slowdown is observed with inputs above 10k
    characters. Users who pass user-provided strings without sanity length checks to moment constructor are
    vulnerable to (Re)DoS attacks. The problem is patched in 2.29.4, the patch can be applied to all affected
    versions with minimal tweaking. Users are advised to upgrade. Users unable to upgrade should consider
    limiting date lengths accepted from user input. (CVE-2022-31129)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203611");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-October/012707.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db7bd395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41411");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31129");
  script_set_attribute(attribute:"solution", value:
"Update the affected release-notes-susemanager and / or release-notes-susemanager-proxy packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42740");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:release-notes-susemanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:release-notes-susemanager-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'release-notes-susemanager-proxy-4.3.2-150400.3.9.3', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'suse-manager-server-release-4.3']},
    {'reference':'release-notes-susemanager-4.3.2-150400.3.15.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'release-notes-susemanager / release-notes-susemanager-proxy');
}
