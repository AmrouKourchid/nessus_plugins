#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-7139.
##

include('compat.inc');

if (description)
{
  script_id(186100);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2022-2127",
    "CVE-2023-34966",
    "CVE-2023-34967",
    "CVE-2023-34968"
  );

  script_name(english:"Oracle Linux 8 : samba (ELSA-2023-7139)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-7139 advisory.

    - resolves: rhbz#2222894 - Fix CVE-2022-2127 CVE-2023-3347 CVE-2023-34966 CVE-2023-34967 CVE-2023-34968
    - resolves: rhbz#2154370 - Fix CVE-2022-38023
    - resolves: rhbz#2126174 - Fix CVE-2022-1615
    - resolves: rhbz#2108331 - Fix CVE-2022-32742
    - resolves: rhbz#2046127 - Fix CVE-2021-44141
    - resolves: rhbz#2046153 - Fix CVE-2021-44142
    - resolves: rhbz#2039153 - Fix CVE-2021-20316
    - resolves: rhbz#2039157 - Fix CVE-2021-43566
    - related: rbhz#2019674 - Fix CVE-2020-25717
    - related: rbhz#2019674 - Fix CVE-2020-25717
    - resolves: rhbz#2019662 - Fix CVE-2016-2124
    - resolves: rhbz#2019668 - Fix CVE-2021-23192
    - resolves: rbhz#2019674 - Fix CVE-2020-25717
    - resolves: rhbz#1949445 - Fix CVE-2021-20254
    - resolves: #1891688 - Fix CVE-2020-14323
    - resolves: #1892633 - Fix CVE-2020-14318
    - resolves: #1892639 - Fix CVE-2020-14383
    - resolves: #1879835 - Fix CVE-2020-1472
    - resolves: #1791209 - Fix CVE-2019-14907
    - resolves: #1764469 - Fix CVE-2019-10218
    - resolves: #1746241 - Fix CVE-2019-10197
    - resolves: #1696525 - Fix CVE-2019-3880
    - resolves: #1554753 - Fix CVE-2018-1050
    - resolves: #1617912 - Fix CVE-2018-10858
    - resolves: #1617913 - Fix CVE-2018-10918
    - resolves: #1617914 - Fix CVE-2018-10919
    - resolves: #1617915 - Fix CVE-2018-1139
    - resolves: #1554754, #1554756 - Security fixes for CVE-2018-1050 CVE-2018-1057
    - resolves: #1515692 - Security fix for CVE-2017-14746 and CVE-2017-15275
    - resolves: #1493441 - Security fix for CVE-2017-12150 CVE-2017-12151 CVE-2017-12163
    - resolves: #1455050 - Security fix for CVE-2017-7494
    - related: #1435156 - Security fix for CVE-2017-2619
    - resolves: #1435156 - Security fix for CVE-2017-2619
    - resolves: #1405984 - CVE-2016-2123,CVE-2016-2125 and CVE-2016-2126
    - resolves: #1353504 - CVE-2016-2119
    - resolves: #1326453 - CVE-2015-5370
    - resolves: #1326453 - CVE-2016-2110
    - resolves: #1326453 - CVE-2016-2111
    - resolves: #1326453 - CVE-2016-2112
    - resolves: #1326453 - CVE-2016-2113
    - resolves: #1326453 - CVE-2016-2114
    - resolves: #1326453 - CVE-2016-2115
    - resolves: #1326453 - CVE-2016-2118
    - resolves: #1315942 - CVE-2015-7560 Incorrect ACL get/set allowed on symlink path
    - CVE-2015-3223 Remote DoS in Samba (AD) LDAP server
    - CVE-2015-5252 Insufficient symlink verification in smbd
    - CVE-2015-5296 Samba client requesting encryption vulnerable to
                    downgrade attack
    - CVE-2015-5299 Missing access control check in shadow copy code
    - CVE-2015-7540 DoS to AD-DC due to insufficient checking of asn1
                    memory allocation
    - resolves: #1126015 - Fix CVE-2014-3560
    - resolves: #1112251 - Fix CVE-2014-0244 and CVE-2014-3493.
    - resolves: #1102528 - CVE-2014-0178.
    - Fix CVE-2013-4496 and CVE-2013-6442.
    - resolves: #1039454 - CVE-2013-4408.
    - resolves: #1039500 - CVE-2012-6150.
    - resolves: #1024544 - Fix CVE-2013-4475.
    - Fixes CVE-2013-0213.
    - Fixes CVE-2013-0214.
    - Fixes CVE-2013-0172.
    - Security Release, fixes CVE-2012-2111
    - Fixes CVE-2012-1182
    - Fixes CVE-2012-0817
    - Fixes CVE-2010-0728
    - Security Release, fixes CVE-2009-2813, CVE-2009-2948 and CVE-2009-2906
    - Security Release, fixes CVE-2008-4314
    - Security fix for CVE-2008-3789
    - Add fix for CVE-2008-1105
    - includes security fixes for CVE-2007-2444,CVE-2007-2446,CVE-2007-2447

    * Mon Apr 30 2007 Gunther Deschner <gdeschner@redhat.com>

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-7139.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected evolution-mapi, evolution-mapi-langpacks and / or openchange packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8:9:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::distro_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-mapi-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openchange");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var pkgs = [
    {'reference':'evolution-mapi-3.28.3-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evolution-mapi-langpacks-3.28.3-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openchange-2.3-32.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openchange-2.3-32.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evolution-mapi-3.28.3-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evolution-mapi-langpacks-3.28.3-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openchange-2.3-32.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'evolution-mapi / evolution-mapi-langpacks / openchange');
}
