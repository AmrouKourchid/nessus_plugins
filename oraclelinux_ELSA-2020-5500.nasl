##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5500.
##

include('compat.inc');

if (description)
{
  script_id(144375);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2019-2938",
    "CVE-2019-2974",
    "CVE-2020-2574",
    "CVE-2020-2752",
    "CVE-2020-2760",
    "CVE-2020-2780",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-13249",
    "CVE-2020-14765",
    "CVE-2020-14776",
    "CVE-2020-14789",
    "CVE-2020-14812",
    "CVE-2020-15180"
  );

  script_name(english:"Oracle Linux 8 : mariadb:10.3 (ELSA-2020-5500)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-5500 advisory.

    asio
    [1.10.8-7]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

    [1.10.8-6]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

    [1.10.8-5]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

    [1.10.8-4]
    - Rebuilt for Boost 1.64

    [1.10.8-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

    [1.10.8-2]
    - Rebuilt for Boost 1.63

    [1.10.8-1]
    - Update to 1.10.8

    [1.10.7-1]
    - Update to 1.10.7

    [1.10.6-7]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

    [1.10.6-6]
    - Rebuilt for Boost 1.60

    [1.10.6-5]
    - Remove useless pieces of the spec
    - Conform to more recent SPEC style
    - Fix date in changelog that was giving warnings

    [1.10.6-4]
    - Move from define to global

    [1.10.6-3]
    - Rebuilt for Boost 1.59

    [1.10.6-2]
    - Rebuilt for https://fedoraproject.org/wiki/Changes/F23Boost159

    [-1.10.6-1]
    - Update to 1.10.6 version

    [1.10.4-5]
    - rebuild for Boost 1.58

    [1.10.4-4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

    [1.10.4-3]
    - Rebuild for boost 1.57.0

    [1.10.4-2]
    - Forgot to update the commit id

    [1.10.4-1]
    - Update to 1.10.4 version

    [1.10.3-1]
    - Update to 1.10.3 version

    [1.4.8-9]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

    [1.4.8-8]
    - Rebuild for boost 1.55.0

    [1.4.8-7]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

    [1.4.8-6]
    - Rebuild for boost 1.54.0

    [1.4.8-5]
    - Rebuild for Boost-1.53.0

    [1.4.8-4]
    - Rebuild for Boost-1.53.0

    [1.4.8-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

    [1.4.8-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

    [1.4.8-1]
    - Update to 1.4.8 bugfix release

    [1.4.1-4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

    [1.4.1-3]
    - fix FTBFS #538893 and #599857 (patch by Petr Machata)

    [1.4.1-2]
    - The tarball is now a gzip archive

    [1.4.1-1]
    - New upstream release

    [1.2.0-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

    [1.2.0-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    [1.2.0-1]
    - New upstream release

    galera
    [25.3.31-1]
    - Rebase to 25.3.31
      Resolves: #1731289, #1856812

    Judy
    mariadb
    [3:10.3.27-3]
    - Remove mariadb_rpl.h from includedir
      This file is shipped in mariadb-connector-c package
    - Require matching version of mariadb-connector-c package

    [3:10.3.27-2]
    - Disable building of the ed25519 client plugin.
      From now on it will be shipped by 'mariadb-connector-c' package

    [3:10.3.27-1]
    - Rebase to 10.3.27
    - mariadb-debug_build.patch is no more needed, upstream did the changes:
      https://github.com/MariaDB/server/commit/31eaa2029f3c2a4f8e5609ce8b87682286238d9a#diff-
    32766783af7cac683980224d63c59929
      https://github.com/MariaDB/server/commit/23c6fb3e6231b8939331e2d9f157092f24ed8f4f#diff-
    78f3162f137407db5240950beb2bcd7c

    [3:10.3.23-1]
    - Rebase to 10.3.23
    - Make conflicts between corresponding mariadb and mysql packages explicit
    - Get rid of the Conflicts macro, it was intended to mark conflicts with
      *upstream* packages
      Resolves: #1853159

    [3:10.3.22-1]
    - Rebase to 10.3.22

    [3:10.3.21-1]
    - Rebase to 10.3.21

    [3:10.3.20-2]
    - Change path of groonga's packaged files
    - Fix bz#1763287

    [3:10.3.20-1]
    - Rebase to 10.3.20
    - NOTE: 10.3.19 was deleted by upstream

    [3:10.3.18-1]
    - Rebase to 10.3.18

    [3:10.3.17-2]
    - Fix the debug build

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5500.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:Judy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:Judy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:asio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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

var appstreams = {
    'mariadb-devel:10.3': [
      {'reference':'Judy-devel-1.0.5-18.module+el8.1.0+5402+691bd77e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'asio-devel-1.10.8-7.module+el8.1.0+5402+691bd77e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-devel-1.0.5-18.module+el8.1.0+5402+691bd77e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'asio-devel-1.10.8-7.module+el8.1.0+5402+691bd77e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Judy-devel-1.0.5-18.module+el8.1.0+5402+691bd77e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'asio-devel-1.10.8-7.module+el8.1.0+5402+691bd77e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ],
    'mariadb:10.3': [
      {'reference':'Judy-1.0.5-18.module+el8.1.0+5402+691bd77e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'galera-25.3.31-1.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mariadb-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-common-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-test-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'Judy-1.0.5-18.module+el8.1.0+5402+691bd77e', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'galera-25.3.31-1.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mariadb-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-common-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-test-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'Judy-1.0.5-18.module+el8.1.0+5402+691bd77e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'galera-25.3.31-1.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mariadb-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-backup-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-common-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-devel-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-embedded-devel-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-errmsg-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-gssapi-server-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-oqgraph-engine-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-galera-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-server-utils-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'mariadb-test-10.3.27-3.module+el8.3.0+7885+7a81225f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb-devel:10.3 / mariadb:10.3');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Judy / Judy-devel / asio-devel / etc');
}
