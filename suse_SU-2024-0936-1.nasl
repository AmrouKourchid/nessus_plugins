#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0936-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(192500);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/06");

  script_cve_id(
    "CVE-2023-45289",
    "CVE-2023-45290",
    "CVE-2024-24783",
    "CVE-2024-24784",
    "CVE-2024-24785"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0936-1");

  script_name(english:"SUSE SLES12 Security Update : go1.22 (SUSE-SU-2024:0936-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:0936-1 advisory.

  - When following an HTTP redirect to a domain which is not a subdomain match or exact match of the initial
    domain, an http.Client does not forward sensitive headers such as Authorization or Cookie. For
    example, a redirect from foo.com to www.foo.com will forward the Authorization header, but a redirect to
    bar.com will not. A maliciously crafted HTTP redirect could cause sensitive headers to be unexpectedly
    forwarded. (CVE-2023-45289)

  - When parsing a multipart form (either explicitly with Request.ParseMultipartForm or implicitly with
    Request.FormValue, Request.PostFormValue, or Request.FormFile), limits on the total size of the parsed
    form were not applied to the memory consumed while reading a single form line. This permits a maliciously
    crafted input containing very long lines to cause allocation of arbitrarily large amounts of memory,
    potentially leading to memory exhaustion. With fix, the ParseMultipartForm function now correctly limits
    the maximum size of form lines. (CVE-2023-45290)

  - Verifying a certificate chain which contains a certificate with an unknown public key algorithm will cause
    Certificate.Verify to panic. This affects all crypto/tls clients, and servers that set Config.ClientAuth
    to VerifyClientCertIfGiven or RequireAndVerifyClientCert. The default behavior is for TLS servers to not
    verify client certificates. (CVE-2024-24783)

  - The ParseAddressList function incorrectly handles comments (text within parentheses) within display names.
    Since this is a misalignment with conforming address parsers, it can result in different trust decisions
    being made by programs using different parsers. (CVE-2024-24784)

  - If errors returned from MarshalJSON methods contain user controlled data, they may be used to break the
    contextual auto-escaping behavior of the html/template package, allowing for subsequent actions to inject
    unexpected content into templates. (CVE-2024-24785)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221003");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-March/018201.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2cf12e2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24785");
  script_set_attribute(attribute:"solution", value:
"Update the affected go1.22 and / or go1.22-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-24784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.22-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'go1.22-1.22.1-1.3.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'go1.22-doc-1.22.1-1.3.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'go1.22-1.22.1-1.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'go1.22-doc-1.22.1-1.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'go1.22 / go1.22-doc');
}
