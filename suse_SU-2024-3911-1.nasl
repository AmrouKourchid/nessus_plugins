#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3911-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(210390);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/11");

  script_cve_id(
    "CVE-2022-45157",
    "CVE-2023-22644",
    "CVE-2023-32197",
    "CVE-2024-7558",
    "CVE-2024-7594",
    "CVE-2024-8037",
    "CVE-2024-8038",
    "CVE-2024-8901",
    "CVE-2024-8975",
    "CVE-2024-8996",
    "CVE-2024-9180",
    "CVE-2024-9264",
    "CVE-2024-9312",
    "CVE-2024-9313",
    "CVE-2024-9341",
    "CVE-2024-9355",
    "CVE-2024-9407",
    "CVE-2024-9486",
    "CVE-2024-9594",
    "CVE-2024-9675",
    "CVE-2024-10214",
    "CVE-2024-10241",
    "CVE-2024-22030",
    "CVE-2024-22036",
    "CVE-2024-33662",
    "CVE-2024-36814",
    "CVE-2024-38365",
    "CVE-2024-39223",
    "CVE-2024-47003",
    "CVE-2024-47067",
    "CVE-2024-47182",
    "CVE-2024-47534",
    "CVE-2024-47616",
    "CVE-2024-47825",
    "CVE-2024-47827",
    "CVE-2024-47832",
    "CVE-2024-47877",
    "CVE-2024-48909",
    "CVE-2024-48921",
    "CVE-2024-49380",
    "CVE-2024-49381",
    "CVE-2024-49753",
    "CVE-2024-49757",
    "CVE-2024-50312"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3911-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : govulncheck-vulndb (SUSE-SU-2024:3911-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:3911-1 advisory.

    Update to version 0.0.20241030T212825 2024-10-30T21:28:25Z ( jsc#PED-11136 )

    - Go CVE Numbering Authority IDs added or updated with aliases:

      * GO-2024-3230 CVE-2024-48921 GHSA-qjvc-p88j-j9rm
      * GO-2024-3232 CVE-2024-10241 GHSA-6mvp-gh77-7vwh

    - Go CVE Numbering Authority IDs added or updated with aliases:

      * GO-2024-3226 CVE-2024-47827 GHSA-ghjw-32xw-ffwr
      * GO-2024-3227 CVE-2024-10214 GHSA-hm57-h27x-599c
      * GO-2024-3228 GHSA-wcx9-ccpj-hx3c

    - Go CVE Numbering Authority IDs added or updated with aliases:

      * GO-2024-3207 GHSA-p5wf-cmr4-xrwr
      * GO-2024-3208 CVE-2024-47825 GHSA-3wwx-63fv-pfq6
      * GO-2024-3210 CVE-2024-8901
      * GO-2024-3211 CVE-2024-50312
      * GO-2024-3212 GHSA-rjfv-pjvx-mjgv
      * GO-2024-3213 CVE-2024-49380
      * GO-2024-3214 CVE-2024-49381
      * GO-2024-3215 CVE-2024-9264 GHSA-q99m-qcv4-fpm7
      * GO-2024-3216 CVE-2024-49753 GHSA-6cf5-w9h3-4rqv
      * GO-2024-3217 CVE-2024-49757 GHSA-3rmw-76m6-4gjc
      * GO-2024-3219 GHSA-7h65-4p22-39j6
      * GO-2024-3220 CVE-2023-32197 GHSA-7h8m-pvw3-5gh4
      * GO-2024-3221 CVE-2024-22036 GHSA-h99m-6755-rgwc
      * GO-2024-3222 GHSA-x7xj-jvwp-97rv
      * GO-2024-3223 CVE-2022-45157 GHSA-xj7w-r753-vj8v
      * GO-2024-3224 CVE-2024-39223 GHSA-8wxx-35qc-vp6r

    - Go CVE Numbering Authority IDs added or updated with aliases:

      * GO-2024-3189 CVE-2024-38365 GHSA-27vh-h6mc-q6g8
      * GO-2024-3203 CVE-2024-9486
      * GO-2024-3204 CVE-2024-9594

    - Go CVE Numbering Authority IDs added or updated with aliases:

      * GO-2024-3189 CVE-2024-38365 GHSA-27vh-h6mc-q6g8
      * GO-2024-3196 CVE-2024-47877 GHSA-8rm2-93mq-jqhc
      * GO-2024-3199 GHSA-vv6c-69r6-chg9
      * GO-2024-3200 CVE-2024-48909 GHSA-3c32-4hq9-6wgj
      * GO-2024-3201 CVE-2023-22644
    - Go CVE Numbering Authority IDs added or updated with aliases:

      * GO-2024-3166 CVE-2024-47534 GHSA-4f8r-qqr9-fq8j
      * GO-2024-3171 CVE-2024-9341 GHSA-mc76-5925-c5p6

    - Go CVE Numbering Authority IDs added or updated with aliases:

      * GO-2024-3161 CVE-2024-22030 GHSA-h4h5-9833-v2p4
      * GO-2024-3162 CVE-2024-7594 GHSA-jg74-mwgw-v6x3
      * GO-2024-3163 CVE-2024-47182
      * GO-2024-3164 CVE-2024-47003 GHSA-59hf-mpf8-pqjh
      * GO-2024-3166 CVE-2024-47534 GHSA-4f8r-qqr9-fq8j
      * GO-2024-3167 CVE-2024-9355 GHSA-3h3x-2hwv-hr52
      * GO-2024-3168 CVE-2024-8975 GHSA-chqx-36rm-rf8h
      * GO-2024-3169 CVE-2024-9407 GHSA-fhqq-8f65-5xfc
      * GO-2024-3170 CVE-2024-8996 GHSA-m5gv-m5f9-wgv4
      * GO-2024-3172 CVE-2024-33662 GHSA-9mjw-79r6-c9m8
      * GO-2024-3173 CVE-2024-7558 GHSA-mh98-763h-m9v4
      * GO-2024-3174 CVE-2024-8037 GHSA-8v4w-f4r9-7h6x
      * GO-2024-3175 CVE-2024-8038 GHSA-xwgj-vpm9-q2rq
      * GO-2024-3179 CVE-2024-47616 GHSA-r7rh-jww5-5fjr
      * GO-2024-3181 CVE-2024-9313 GHSA-x5q3-c8rm-w787
      * GO-2024-3182 GHSA-wpr2-j6gr-pjw9
      * GO-2024-3184 CVE-2024-36814 GHSA-9cp9-8gw2-8v7m
      * GO-2024-3185 CVE-2024-47832
      * GO-2024-3186 CVE-2024-9675 GHSA-586p-749j-fhwp
      * GO-2024-3188 CVE-2024-9312 GHSA-4gfw-wf7c-w6g2
      * GO-2024-3190 CVE-2024-47067 GHSA-8pph-gfhp-w226
      * GO-2024-3191 CVE-2024-9180 GHSA-rr8j-7w34-xp5j

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019776.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28e421c1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-33662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38365");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39223");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49380");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9355");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9407");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9675");
  script_set_attribute(attribute:"solution", value:
"Update the affected govulncheck-vulndb package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9486");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:govulncheck-vulndb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'govulncheck-vulndb-0.0.20241030T212825-150000.1.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'govulncheck-vulndb-0.0.20241030T212825-150000.1.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'govulncheck-vulndb-0.0.20241030T212825-150000.1.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'govulncheck-vulndb-0.0.20241030T212825-150000.1.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'govulncheck-vulndb');
}
