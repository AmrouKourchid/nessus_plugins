#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1504-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(235644);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2025-2784",
    "CVE-2025-32050",
    "CVE-2025-32051",
    "CVE-2025-32052",
    "CVE-2025-32053",
    "CVE-2025-32906",
    "CVE-2025-32907",
    "CVE-2025-32908",
    "CVE-2025-32909",
    "CVE-2025-32910",
    "CVE-2025-32911",
    "CVE-2025-32912",
    "CVE-2025-32913",
    "CVE-2025-32914",
    "CVE-2025-46420",
    "CVE-2025-46421"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1504-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : libsoup (SUSE-SU-2025:1504-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2025:1504-1 advisory.

    - CVE-2025-2784: Fixed heap buffer over-read in `skip_insignificant_space` when sniffing conten
    (bsc#1240750)
     - CVE-2025-32050: Fixed integer overflow in append_param_quoted (bsc#1240752)
     - CVE-2025-32051: Fixed segmentation fault when parsing malformed data URI (bsc#1240754)
     - CVE-2025-32052: Fixed heap buffer overflow in sniff_unknown() (bsc#1240756)
     - CVE-2025-32053: Fixed heap buffer overflows in sniff_feed_or_html() and skip_insignificant_space()
    (bsc#1240757)
     - CVE-2025-32906: Fixed out of bounds reads in soup_headers_parse_request() (bsc#1241263)
     - CVE-2025-32907: Fixed excessive memory consumption in server when client requests a large amount of
    overlapping ranges in a single HTTP request (bsc#1241222)
     - CVE-2025-32908: Fixed HTTP request may lead to server crash due to HTTP/2 server not fully validating
    the values of pseudo-headers (bsc#1241223)
     - CVE-2025-32909: Fixed NULL pointer dereference in the sniff_mp4 function in soup-content-sniffer.c
    (bsc#1241226)
     - CVE-2025-32910: Fixed NULL pointer deference on client when server omits the realm parameter in an
    Unauthorized response with Digest authentication (bsc#1241252)
     - CVE-2025-32911: Fixed double free on soup_message_headers_get_content_disposition() via 'params'
    (bsc#1241238)
     - CVE-2025-32912: Fixed NULL pointer dereference in SoupAuthDigest (bsc#1241214)
     - CVE-2025-32913: Fixed NULL pointer dereference in soup_message_headers_get_content_disposition
    (bsc#1241162)
     - CVE-2025-32914: Fixed out of bounds read in `soup_multipart_new_from_message()` (bsc#1241164)
     - CVE-2025-46420: Fixed memory leak on soup_header_parse_quality_list() via soup-headers.c (bsc#1241686)
     - CVE-2025-46421: Fixed HTTP Authorization Header leak via an HTTP redirect (bsc#1241688)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241688");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039149.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-2784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32050");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-32914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-46420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-46421");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32914");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoup-3_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoup-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoup-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Soup-3_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libsoup-3_0-0-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libsoup-3_0-0-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libsoup-devel-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libsoup-devel-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libsoup-lang-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libsoup-lang-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-Soup-3_0-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-Soup-3_0-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libsoup-3_0-0-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libsoup-3_0-0-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libsoup-devel-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libsoup-devel-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libsoup-lang-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libsoup-lang-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-Soup-3_0-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-Soup-3_0-3.4.4-150600.3.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libsoup-3_0-0-3.4.4-150600.3.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libsoup-3_0-0-32bit-3.4.4-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libsoup-devel-3.4.4-150600.3.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libsoup-devel-32bit-3.4.4-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libsoup-lang-3.4.4-150600.3.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-Soup-3_0-3.4.4-150600.3.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsoup-3_0-0 / libsoup-3_0-0-32bit / libsoup-devel / etc');
}
