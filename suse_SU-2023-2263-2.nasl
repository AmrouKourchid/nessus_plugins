#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2263-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(178692);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/16");

  script_cve_id("CVE-2023-30861");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2263-2");

  script_name(english:"openSUSE 15 Security Update : python-Flask (SUSE-SU-2023:2263-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2023:2263-2 advisory.

  - Flask is a lightweight WSGI web application framework. When all of the following conditions are met, a
    response containing data intended for one client may be cached and subsequently sent by the proxy to other
    clients. If the proxy also caches `Set-Cookie` headers, it may send one client's `session` cookie to other
    clients. The severity depends on the application's use of the session and the proxy's behavior regarding
    cookies. The risk depends on all these conditions being met. 1. The application must be hosted behind a
    caching proxy that does not strip cookies or ignore responses with cookies. 2. The application sets
    `session.permanent = True` 3. The application does not access or modify the session at any point during a
    request. 4. `SESSION_REFRESH_EACH_REQUEST` enabled (the default). 5. The application does not set a
    `Cache-Control` header to indicate that a page is private or should not be cached. This happens because
    vulnerable versions of Flask only set the `Vary: Cookie` header when the session is accessed or modified,
    not when it is refreshed (re-sent to update the expiration) without being accessed or modified. This issue
    has been fixed in versions 2.3.2 and 2.2.5. (CVE-2023-30861)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211246");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-July/030433.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30861");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-Flask and / or python3-Flask-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30861");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'python3-Flask-1.0.4-150400.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python3-Flask-doc-1.0.4-150400.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-Flask / python3-Flask-doc');
}
