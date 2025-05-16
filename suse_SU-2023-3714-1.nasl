#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3714-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181743);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id(
    "CVE-2022-23517",
    "CVE-2022-23518",
    "CVE-2022-23519",
    "CVE-2022-23520"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3714-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : rubygem-rails-html-sanitizer (SUSE-SU-2023:3714-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:3714-1 advisory.

  - rails-html-sanitizer is responsible for sanitizing HTML fragments in Rails applications. Certain
    configurations of rails-html-sanitizer < 1.4.4 use an inefficient regular expression that is susceptible
    to excessive backtracking when attempting to sanitize certain SVG attributes. This may lead to a denial of
    service through CPU resource consumption. This issue has been patched in version 1.4.4. (CVE-2022-23517)

  - rails-html-sanitizer is responsible for sanitizing HTML fragments in Rails applications. Versions >=
    1.0.3, < 1.4.4 are vulnerable to cross-site scripting via data URIs when used in combination with Loofah
    >= 2.1.0. This issue is patched in version 1.4.4. (CVE-2022-23518)

  - rails-html-sanitizer is responsible for sanitizing HTML fragments in Rails applications. Prior to version
    1.4.4, a possible XSS vulnerability with certain configurations of Rails::Html::Sanitizer may allow an
    attacker to inject content if the application developer has overridden the sanitizer's allowed tags in
    either of the following ways: allow both math and style elements, or allow both svg and style
    elements. Code is only impacted if allowed tags are being overridden. . This issue is fixed in version
    1.4.4. All users overriding the allowed tags to include math or svg and style should either upgrade
    or use the following workaround immediately: Remove style from the overridden allowed tags, or remove
    math and svg from the overridden allowed tags. (CVE-2022-23519)

  - rails-html-sanitizer is responsible for sanitizing HTML fragments in Rails applications. Prior to version
    1.4.4, there is a possible XSS vulnerability with certain configurations of Rails::Html::Sanitizer due to
    an incomplete fix of CVE-2022-32209. Rails::Html::Sanitizer may allow an attacker to inject content if the
    application developer has overridden the sanitizer's allowed tags to allow both select and style
    elements. Code is only impacted if allowed tags are being overridden. This issue is patched in version
    1.4.4. All users overriding the allowed tags to include both select and style should either upgrade or
    use this workaround: Remove either select or style from the overridden allowed tags. NOTE: Code is
    _not_ impacted if allowed tags are overridden using either the :tags option to the Action View helper
    method sanitize or the :tags option to the instance method SafeListSanitizer#sanitize. (CVE-2022-23520)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206436");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-September/016255.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58138a6c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23520");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby2.5-rubygem-rails-html-sanitizer, ruby2.5-rubygem-rails-html-sanitizer-doc and / or
ruby2.5-rubygem-rails-html-sanitizer-testsuite packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23520");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-rubygem-rails-html-sanitizer");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1/2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-1.0.4-150000.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-doc-1.0.4-150000.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-testsuite-1.0.4-150000.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-1.0.4-150000.4.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-doc-1.0.4-150000.4.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-testsuite-1.0.4-150000.4.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-1.0.4-150000.4.6.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-1.0.4-150000.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-1.0.4-150000.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-1.0.4-150000.4.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'ruby2.5-rubygem-rails-html-sanitizer-1.0.4-150000.4.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby2.5-rubygem-rails-html-sanitizer / etc');
}
