#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3020-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153248);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id(
    "CVE-2021-32785",
    "CVE-2021-32786",
    "CVE-2021-32791",
    "CVE-2021-32792"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3020-1");

  script_name(english:"SUSE SLES15 Security Update : apache2-mod_auth_openidc (SUSE-SU-2021:3020-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3020-1 advisory.

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. When
    mod_auth_openidc versions prior to 2.4.9 are configured to use an unencrypted Redis cache
    (`OIDCCacheEncrypt off`, `OIDCSessionType server-cache`, `OIDCCacheType redis`), `mod_auth_openidc`
    wrongly performed argument interpolation before passing Redis requests to `hiredis`, which would perform
    it again and lead to an uncontrolled format string bug. Initial assessment shows that this bug does not
    appear to allow gaining arbitrary code execution, but can reliably provoke a denial of service by
    repeatedly crashing the Apache workers. This bug has been corrected in version 2.4.9 by performing
    argument interpolation only once, using the `hiredis` API. As a workaround, this vulnerability can be
    mitigated by setting `OIDCCacheEncrypt` to `on`, as cache keys are cryptographically hashed before use
    when this option is enabled. (CVE-2021-32785)

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. In versions
    prior to 2.4.9, `oidc_validate_redirect_url()` does not parse URLs the same way as most browsers do. As a
    result, this function can be bypassed and leads to an Open Redirect vulnerability in the logout
    functionality. This bug has been fixed in version 2.4.9 by replacing any backslash of the URL to redirect
    with slashes to address a particular breaking change between the different specifications (RFC2396 /
    RFC3986 and WHATWG). As a workaround, this vulnerability can be mitigated by configuring
    `mod_auth_openidc` to only allow redirection whose destination matches a given regular expression.
    (CVE-2021-32786)

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. In
    mod_auth_openidc before version 2.4.9, the AES GCM encryption in mod_auth_openidc uses a static IV and
    AAD. It is important to fix because this creates a static nonce and since aes-gcm is a stream cipher, this
    can lead to known cryptographic issues, since the same key is being reused. From 2.4.9 onwards this has
    been patched to use dynamic values through usage of cjose AES encryption routines. (CVE-2021-32791)

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. In
    mod_auth_openidc before version 2.4.9, there is an XSS vulnerability in when using `OIDCPreservePost On`.
    (CVE-2021-32792)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32792");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-September/009431.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd988498");
  script_set_attribute(attribute:"solution", value:
"Update the affected apache2-mod_auth_openidc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32786");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-32792");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_auth_openidc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'apache2-mod_auth_openidc-2.3.8-3.15.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-server-applications-release-15.2']},
    {'reference':'apache2-mod_auth_openidc-2.3.8-3.15.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-server-applications-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_auth_openidc');
}
