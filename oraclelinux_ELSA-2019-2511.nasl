#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2511 and 
# Oracle Linux Security Advisory ELSA-2019-2511 respectively.
#

include('compat.inc');

if (description)
{
  script_id(127983);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2019-2420",
    "CVE-2019-2434",
    "CVE-2019-2436",
    "CVE-2019-2455",
    "CVE-2019-2481",
    "CVE-2019-2482",
    "CVE-2019-2486",
    "CVE-2019-2494",
    "CVE-2019-2495",
    "CVE-2019-2502",
    "CVE-2019-2503",
    "CVE-2019-2507",
    "CVE-2019-2510",
    "CVE-2019-2528",
    "CVE-2019-2529",
    "CVE-2019-2530",
    "CVE-2019-2531",
    "CVE-2019-2532",
    "CVE-2019-2533",
    "CVE-2019-2534",
    "CVE-2019-2535",
    "CVE-2019-2536",
    "CVE-2019-2537",
    "CVE-2019-2539",
    "CVE-2019-2580",
    "CVE-2019-2581",
    "CVE-2019-2584",
    "CVE-2019-2585",
    "CVE-2019-2587",
    "CVE-2019-2589",
    "CVE-2019-2592",
    "CVE-2019-2593",
    "CVE-2019-2596",
    "CVE-2019-2606",
    "CVE-2019-2607",
    "CVE-2019-2614",
    "CVE-2019-2617",
    "CVE-2019-2620",
    "CVE-2019-2623",
    "CVE-2019-2624",
    "CVE-2019-2625",
    "CVE-2019-2626",
    "CVE-2019-2627",
    "CVE-2019-2628",
    "CVE-2019-2630",
    "CVE-2019-2631",
    "CVE-2019-2634",
    "CVE-2019-2635",
    "CVE-2019-2636",
    "CVE-2019-2644",
    "CVE-2019-2681",
    "CVE-2019-2683",
    "CVE-2019-2685",
    "CVE-2019-2686",
    "CVE-2019-2687",
    "CVE-2019-2688",
    "CVE-2019-2689",
    "CVE-2019-2691",
    "CVE-2019-2693",
    "CVE-2019-2694",
    "CVE-2019-2695",
    "CVE-2019-2737",
    "CVE-2019-2738",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2752",
    "CVE-2019-2755",
    "CVE-2019-2757",
    "CVE-2019-2758",
    "CVE-2019-2774",
    "CVE-2019-2778",
    "CVE-2019-2780",
    "CVE-2019-2784",
    "CVE-2019-2785",
    "CVE-2019-2789",
    "CVE-2019-2795",
    "CVE-2019-2796",
    "CVE-2019-2797",
    "CVE-2019-2798",
    "CVE-2019-2800",
    "CVE-2019-2801",
    "CVE-2019-2802",
    "CVE-2019-2803",
    "CVE-2019-2805",
    "CVE-2019-2808",
    "CVE-2019-2810",
    "CVE-2019-2811",
    "CVE-2019-2812",
    "CVE-2019-2814",
    "CVE-2019-2815",
    "CVE-2019-2819",
    "CVE-2019-2826",
    "CVE-2019-2830",
    "CVE-2019-2834",
    "CVE-2019-2879"
  );
  script_xref(name:"RHSA", value:"2019:2511");

  script_name(english:"Oracle Linux 8 : mysql:8.0 (ELSA-2019-2511)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-2511 advisory.

    mecab
    [0.996-1.9]
    - Release bump for rebuilding on new arches
      Related: #1518842

    [0.996-1.8]
    - skip %verify of /etc/opt/rh/rh-mysql57/mecabrc
      Resolves: #1382315

    [0.996-1.7]
    - Prefix library major number with SCL name in soname

    [0.996-1.6]
    - Require runtime package from the scl

    [0.996-1.5]
    - Convert to SCL package

    [0.996-1.4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

    [0.996-1.3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

    [0.996-1.2]
    - Rebuilt for GCC 5 C++11 ABI change

    [0.996-1.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

    [0.996-1.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

    mecab-ipadic
    [2.7.0.20070801-16.0.1]
    - Rename the LICENSE.Fedora to LICENSE.oracle

    [2.7.0.20070801-16]
    - Rename the LICENSE.fedora to LICENSE.rhel

    [2.7.0.20070801-15]
    - Release bump for rebuilding on new arches
      Related: #1518842

    [2.7.0.20070801-14.1]
    - Require runtime package from the scl

    [2.7.0.20070801-13.1]
    - Convert to SCL package

    [2.7.0.20070801-12.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

    [2.7.0.20070801-11.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

    [2.7.0.20070801-10.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

    [2.7.0.20070801-9.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

    [2.7.0.20070801-8.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

    [2.7.0.20070801-7.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

    [2.7.0.20070801-6.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

    [2.7.0.20070801-5.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

    [2.7.0.20070801-4.1]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

    * Wed Jan 13 2010 Mamoru Tasaka <mtasaka@ioa.s.u-tokyo.ac.jp>
    - Fix URL for Source2

    [2.7.0.20070801-3]
    - F-12: Mass rebuild

    [2.7.0.20070801-2]
    - F-11: Mass rebuild

    [2.7.0.20070801.dist.1]
    - License update

    [2.7.0.20070801]
    - New release 2.7.0-20070801

    [2.7.0.20070610]
    - New release 2.7.0-20070610

    [2.7.0.20060707-2]
    - Fix typo

    [2.7.0.20060707-1]
    - Initial packaging, based on mecab-jumandic spec file

    mysql
    [8.0.17-3]
    - Use RELRO hardening on all binaries
    - Resolves: #1734420

    [8.0.17-2]
    - Use RELRO hardening on all binaries
    - Resolves: #1734420

    [8.0.17-1]
    - Rebase to 8.0.17
    - Resolves: #1732042
    - CVEs fixed:
      CVE-2019-2737 CVE-2019-2738 CVE-2019-2739 CVE-2019-2740 CVE-2019-2741
      CVE-2019-2743 CVE-2019-2746 CVE-2019-2747 CVE-2019-2752 CVE-2019-2755
      CVE-2019-2757 CVE-2019-2758 CVE-2019-2774 CVE-2019-2778 CVE-2019-2780
      CVE-2019-2784 CVE-2019-2785 CVE-2019-2789 CVE-2019-2791 CVE-2019-2795
      CVE-2019-2796 CVE-2019-2797 CVE-2019-2798 CVE-2019-2800 CVE-2019-2801
      CVE-2019-2802 CVE-2019-2803 CVE-2019-2805 CVE-2019-2808 CVE-2019-2810
      CVE-2019-2811 CVE-2019-2812 CVE-2019-2814 CVE-2019-2815 CVE-2019-2819
      CVE-2019-2822 CVE-2019-2826 CVE-2019-2830 CVE-2019-2834 CVE-2019-2879

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-2511.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2819");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/mysql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mysql:' + module_ver);

var appstreams = {
    'mysql:8.0': [
      {'reference':'mecab-0.996-1.module+el8.0.0+5253+1dce7bb2.9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-0.996-1.module+el8.0.0+5253+1dce7bb2.9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.0.1.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.17-3.module+el8.0.0+5253+1dce7bb2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
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
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-ipadic / mecab-ipadic-EUCJP / etc');
}
