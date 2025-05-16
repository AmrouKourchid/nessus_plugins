#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-527.
##

include('compat.inc');

if (description)
{
  script_id(190738);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2023-46045");

  script_name(english:"Amazon Linux 2023 : graphviz, graphviz-devel, graphviz-gd (ALAS2023-2024-527)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2023-2024-527 advisory.

    buffer overflow via a crafted config6a file

    NOTE: Crosses no security boundary, config files are under local controlNOTE:
    https://gitlab.com/graphviz/graphviz/-/issues/2441NOTE: Introduced by:
    https://gitlab.com/graphviz/graphviz/-/commit/cf95714837f06f684929b54659523c2c9b1fc19f (2.38.0)NOTE: Fixed
    by: https://gitlab.com/graphviz/graphviz/-/commit/361f274ca901c3c476697a6404662d95f4dd43cbNOTE: Fixed by:
    https://gitlab.com/graphviz/graphviz/-/commit/3f31704cafd7da3e86bb2861accf5e90c973e62aNOTE: Fixed by:
    https://gitlab.com/graphviz/graphviz/-/commit/a95f977f5d809915ec4b14836d2b5b7f5e74881e (CVE-2023-46045)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-527.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-46045.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update graphviz --releasever 2023.3.20240219' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46045");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-graphs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-ocaml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'graphviz-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-debugsource-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-debugsource-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-devel-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-devel-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-doc-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-doc-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-gd-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-gd-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-gd-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-gd-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-graphs-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-graphs-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-java-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-java-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-java-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-java-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-lua-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-lua-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-lua-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-lua-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-ocaml-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-ocaml-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-ocaml-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-ocaml-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-perl-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-perl-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-perl-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-perl-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-tcl-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-tcl-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-tcl-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'graphviz-tcl-debuginfo-2.44.0-25.amzn2023.0.7', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz / graphviz-debuginfo / graphviz-debugsource / etc");
}
