#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2025-2755.
##

include('compat.inc');

if (description)
{
  script_id(216821);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id(
    "CVE-2024-57635",
    "CVE-2024-57636",
    "CVE-2024-57637",
    "CVE-2024-57638",
    "CVE-2024-57639",
    "CVE-2024-57640",
    "CVE-2024-57641",
    "CVE-2024-57642",
    "CVE-2024-57643",
    "CVE-2024-57644",
    "CVE-2024-57645",
    "CVE-2024-57646",
    "CVE-2024-57647",
    "CVE-2024-57648",
    "CVE-2024-57649",
    "CVE-2024-57650",
    "CVE-2024-57651",
    "CVE-2024-57652",
    "CVE-2024-57653",
    "CVE-2024-57654",
    "CVE-2024-57655",
    "CVE-2024-57656",
    "CVE-2024-57657",
    "CVE-2024-57658",
    "CVE-2024-57659",
    "CVE-2024-57660",
    "CVE-2024-57661",
    "CVE-2024-57662",
    "CVE-2024-57663",
    "CVE-2024-57664"
  );
  script_xref(name:"IAVA", value:"2025-A-0074");

  script_name(english:"Amazon Linux 2 : virtuoso-opensource (ALAS-2025-2755)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of virtuoso-opensource installed on the remote host is prior to 7.2.14-2. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2025-2755 advisory.

    An issue in the chash_array component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57635)

    An issue in the itc_sample_row_check component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57636)

    An issue in the dfe_unit_gb_dependant component of openlink virtuoso-opensource v7.2.11 allows attackers
    to cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57637)

    An issue in the dfe_body_copy component of openlink virtuoso-opensource v7.2.11 allows attackers to cause
    a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57638)

    An issue in the dc_elt_size component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57639)

    An issue in the dc_add_int component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57640)

    An issue in the sqlexp component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57641)

    An issue in the dfe_inx_op_col_def_table component of openlink virtuoso-opensource v7.2.11 allows
    attackers to cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57642)

    An issue in the box_deserialize_string component of openlink virtuoso-opensource v7.2.11 allows attackers
    to cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57643)

    An issue in the itc_hash_compare component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57644)

    An issue in the qi_inst_state_free component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57645)

    An issue in the psiginfo component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57646)

    An issue in the row_insert_cast component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57647)

    An issue in the itc_set_param_row component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57648)

    An issue in the qst_vec_set component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57649)

    An issue in the qi_inst_state_free component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57650)

    An issue in the jp_add component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57651)

    An issue in the numeric_to_dv component of openlink virtuoso-opensource v7.2.11 allows attackers to cause
    a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57652)

    An issue in the qst_vec_set_copy component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57653)

    An issue in the qst_vec_get_int64 component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57654)

    An issue in the dfe_n_in_order component of openlink virtuoso-opensource v7.2.11 allows attackers to cause
    a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57655)

    An issue in the sqlc_add_distinct_node component of openlink virtuoso-opensource v7.2.11 allows attackers
    to cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57656)

    An issue in the sqlg_vec_upd component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57657)

    An issue in the sql_tree_hash_1 component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57658)

    An issue in the sqlg_parallel_ts_seq component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57659)

    An issue in the sqlo_expand_jts component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57660)

    An issue in the sqlo_df component of openlink virtuoso-opensource v7.2.11 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57661)

    An issue in the sqlg_hash_source component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57662)

    An issue in the sqlg_place_dpipes component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57663)

    An issue in the sqlg_group_node component of openlink virtuoso-opensource v7.2.11 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2024-57664)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2025-2755.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57635.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57636.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57637.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57638.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57639.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57640.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57641.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57642.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57643.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57644.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57645.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57646.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57647.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57648.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57649.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57650.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57651.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57652.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57653.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57654.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57655.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57656.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57657.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57658.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57659.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57660.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57661.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57662.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57663.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-57664.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update virtuoso-opensource' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57664");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-57649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:virtuoso-opensource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:virtuoso-opensource-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'virtuoso-opensource-7.2.14-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-7.2.14-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-debuginfo-7.2.14-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-debuginfo-7.2.14-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "virtuoso-opensource / virtuoso-opensource-debuginfo");
}
