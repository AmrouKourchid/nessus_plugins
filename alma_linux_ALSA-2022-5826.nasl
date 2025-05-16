##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:5826.
##

include('compat.inc');

if (description)
{
  script_id(163903);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id(
    "CVE-2021-46659",
    "CVE-2021-46661",
    "CVE-2021-46663",
    "CVE-2021-46664",
    "CVE-2021-46665",
    "CVE-2021-46668",
    "CVE-2021-46669",
    "CVE-2022-24048",
    "CVE-2022-24050",
    "CVE-2022-24051",
    "CVE-2022-24052",
    "CVE-2022-27376",
    "CVE-2022-27377",
    "CVE-2022-27378",
    "CVE-2022-27379",
    "CVE-2022-27380",
    "CVE-2022-27381",
    "CVE-2022-27382",
    "CVE-2022-27383",
    "CVE-2022-27384",
    "CVE-2022-27386",
    "CVE-2022-27387",
    "CVE-2022-27444",
    "CVE-2022-27445",
    "CVE-2022-27446",
    "CVE-2022-27447",
    "CVE-2022-27448",
    "CVE-2022-27449",
    "CVE-2022-27451",
    "CVE-2022-27452",
    "CVE-2022-27455",
    "CVE-2022-27456",
    "CVE-2022-27457",
    "CVE-2022-27458",
    "CVE-2022-31622",
    "CVE-2022-31623"
  );
  script_xref(name:"ALSA", value:"2022:5826");

  script_name(english:"AlmaLinux 8 : mariadb:10.5 (5826) (ALSA-2022:5826)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:5826 advisory.

    * mariadb: MariaDB through 10.5.9 allows attackers to trigger a convert_const_to_int use-after-free when
    the BIGINT data type is used (CVE-2021-46669)
    * mariadb: lack of proper validation of the length of user-supplied data prior to copying it to a fixed-
    length stack-based buffer (CVE-2022-24048)
    * mariadb: lack of validating the existence of an object prior to performing operations on the object
    (CVE-2022-24050)
    * mariadb: lack of proper validation of a user-supplied string before using it as a format specifier
    (CVE-2022-24051)
    * mariadb: CONNECT Storage Engine Heap-based Buffer Overflow Privilege Escalation Vulnerability
    (CVE-2022-24052)
    * mariadb: assertion failure in Item_args::walk_arg (CVE-2022-27376)
    * mariadb: use-after-poison when complex conversion is involved in blob (CVE-2022-27377)
    * mariadb: crash in create_tmp_table::finalize (CVE-2022-27378)
    * mariadb: crash in component arg_comparator::compare_real_fixed (CVE-2022-27379)
    * mariadb: crash at my_decimal::operator= (CVE-2022-27380)
    * mariadb: crash at Field::set_default via specially crafted SQL statements (CVE-2022-27381)
    * mariadb: assertion failure via component Item_field::used_tables/update_depend_map_for_order
    (CVE-2022-27382)
    * mariadb: use-after-poison in my_strcasecmp_8bit() of ctype-simple.c (CVE-2022-27383)
    * mariadb: via component Item_subselect::init_expr_cache_tracker (CVE-2022-27384)
    * mariadb: crash in query_arena::set_query_arena upon SELECT from view (CVE-2022-27386)
    * mariadb: assertion failures in decimal_bin_size (CVE-2022-27387)
    * mariadb: crash when using HAVING with NOT EXIST predicate in an equality (CVE-2022-27444)
    * mariadb: assertion failure in compare_order_elements (CVE-2022-27445)
    * mariadb: crash when using HAVING with IS NULL predicate in an equality (CVE-2022-27446)
    * mariadb: use-after-poison in Binary_string::free_buffer (CVE-2022-27447)
    * mariadb: crash in multi-update and implicit grouping (CVE-2022-27448)
    * mariadb: assertion failure in sql/item_func.cc (CVE-2022-27449)
    * mariadb: crash via window function in expression in ORDER BY (CVE-2022-27451)
    * mariadb: assertion failure in sql/item_cmpfunc.cc (CVE-2022-27452)
    * mariadb: use-after-free when WHERE has subquery with an outer reference in HAVING (CVE-2022-27455)
    * mariadb: assertion failure in VDec::VDec at /sql/sql_type.cc (CVE-2022-27456)
    * mariadb: incorrect key in dup value error after long unique (CVE-2022-27457)
    * mariadb: use-after-poison in Binary_string::free_buffer (CVE-2022-27458)
    * mariadb: improper locking due to the unreleased lock in extra/mariabackup/ds_compress.cc
    (CVE-2022-31622)
    * mariadb: improper locking due to the unreleased lock in extra/mariabackup/ds_compress.cc
    (CVE-2022-31623)
    * mariadb: Crash executing query with VIEW, aggregate and subquery (CVE-2021-46659)
    * mariadb: MariaDB allows an application crash in find_field_in_tables and find_order_in_list via an
    unused common table expression (CTE) (CVE-2021-46661)
    * mariadb: MariaDB through 10.5.13 allows a ha_maria::extra application crash via certain SELECT
    statements (CVE-2021-46663)
    * mariadb: crash in sub_select_postjoin_aggr for a NULL value of aggr (CVE-2021-46664)
    * mariadb: crash because of incorrect used_tables expectations (CVE-2021-46665)
    * mariadb: crash via certain long SELECT DISTINCT statements (CVE-2021-46668)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-5826.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24052");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:Judy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/mariadb');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb:10.5');
if ('10.5' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mariadb:' + module_ver);

var appstreams = {
    'mariadb:10.5': [
      {'reference':'galera-26.4.11-1.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-1.0.5-18.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mariadb-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-backup-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-common-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-devel-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-pam-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-test-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'galera-26.4.11-1.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-1.0.5-18.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mariadb-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-backup-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-common-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-devel-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-pam-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-test-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'galera-26.4.11-1.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-1.0.5-18.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mariadb-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-backup-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-common-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-devel-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-pam-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-test-10.5.16-2.module_el8.6.0+3072+3c630e87', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
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
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb:10.5');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Judy / galera / mariadb / mariadb-backup / mariadb-common / etc');
}
