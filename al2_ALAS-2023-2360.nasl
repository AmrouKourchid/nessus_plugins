#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-2360.
##

include('compat.inc');

if (description)
{
  script_id(186555);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2023-31607",
    "CVE-2023-31609",
    "CVE-2023-31610",
    "CVE-2023-31611",
    "CVE-2023-31616",
    "CVE-2023-31617",
    "CVE-2023-31618",
    "CVE-2023-31619",
    "CVE-2023-31620",
    "CVE-2023-31621",
    "CVE-2023-31622",
    "CVE-2023-31623",
    "CVE-2023-31624",
    "CVE-2023-31625",
    "CVE-2023-31627",
    "CVE-2023-31628",
    "CVE-2023-31629",
    "CVE-2023-31630",
    "CVE-2023-31631"
  );

  script_name(english:"Amazon Linux 2 : virtuoso-opensource (ALAS-2023-2360)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of virtuoso-opensource installed on the remote host is prior to 7.2.11-1. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2023-2360 advisory.

    2024-03-13: CVE-2023-31618 was added to this advisory.

    2024-03-13: CVE-2023-31627 was added to this advisory.

    2024-03-13: CVE-2023-31609 was added to this advisory.

    2024-02-15: CVE-2023-31607 was added to this advisory.

    2024-02-15: CVE-2023-31621 was added to this advisory.

    2024-02-15: CVE-2023-31629 was added to this advisory.

    2024-02-01: CVE-2023-31622 was added to this advisory.

    2024-02-01: CVE-2023-31624 was added to this advisory.

    2024-02-01: CVE-2023-31617 was added to this advisory.

    2024-01-19: CVE-2023-31631 was added to this advisory.

    2024-01-19: CVE-2023-31623 was added to this advisory.

    2024-01-19: CVE-2023-31625 was added to this advisory.

    2024-01-19: CVE-2023-31611 was added to this advisory.

    2024-01-19: CVE-2023-31628 was added to this advisory.

    An issue in the __libc_malloc component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31607)

    An issue in the dfe_unit_col_loci component of openlink virtuoso-opensource v7.2.9 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31609)

    An issue in the _IO_default_xsputn component of openlink virtuoso-opensource v7.2.9 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31610)

    An issue in the __libc_longjmp component of openlink virtuoso-opensource v7.2.9 allows attackers to cause
    a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31611)

    An issue in the bif_mod component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31616)

    An issue in the dk_set_delete component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31617)

    An issue in the sqlc_union_dt_wrap component of openlink virtuoso-opensource v7.2.9 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31618)

    An issue in the sch_name_to_object component of openlink virtuoso-opensource v7.2.9 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31619)

    An issue in the dv_compare component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31620)

    An issue in the kc_var_col component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31621)

    An issue in the sqlc_make_policy_trig component of openlink virtuoso-opensource v7.2.9 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31622)

    An issue in the mp_box_copy component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31623)

    An issue in the sinv_check_exp component of openlink virtuoso-opensource v7.2.9 allows attackers to cause
    a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31624)

    An issue in the psiginfo component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31625)

    An issue in the strhash component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31627)

    An issue in the stricmp component of openlink virtuoso-opensource v7.2.9 allows attackers to cause a
    Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31628)

    An issue in the sqlo_union_scope component of openlink virtuoso-opensource v7.2.9 allows attackers to
    cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31629)

    An issue in the sqlo_query_spec component of openlink virtuoso-opensource v7.2.9 allows attackers to cause
    a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31630)

    An issue in the sqlo_preds_contradiction component of openlink virtuoso-opensource v7.2.9 allows attackers
    to cause a Denial of Service (DoS) via crafted SQL statements. (CVE-2023-31631)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-2360.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31607.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31609.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31610.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31611.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31616.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31617.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31618.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31619.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31620.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31621.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31622.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31624.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31625.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31627.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31628.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31629.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31630.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31631.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update virtuoso-opensource' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31631");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:virtuoso-opensource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:virtuoso-opensource-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'virtuoso-opensource-7.2.11-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-7.2.11-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-debuginfo-7.2.11-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-debuginfo-7.2.11-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
