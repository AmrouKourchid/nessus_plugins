#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3242 and 
# Oracle Linux Security Advisory ELSA-2018-3242 respectively.
#

include('compat.inc');

if (description)
{
  script_id(118779);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2018-10911");
  script_xref(name:"RHSA", value:"2018:3242");

  script_name(english:"Oracle Linux 7 : glusterfs (ELSA-2018-3242)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2018-3242 advisory.

    [3.12.2-18]
    - fixes bugs bz#1524336 bz#1622029 bz#1622452

    [3.12.2-17]
    - fixes bugs bz#1615578 bz#1619416 bz#1619538 bz#1620469 bz#1620765

    [3.12.2-16]
    - fixes bugs bz#1569657 bz#1608352 bz#1609163 bz#1609724 bz#1610825
      bz#1611151 bz#1612098 bz#1615338 bz#1615440

    [3.12.2-15]
    - fixes bugs bz#1589279 bz#1598384 bz#1599362 bz#1599998 bz#1600790
      bz#1601331 bz#1603103

    [3.12.2-14]
    - fixes bugs bz#1547903 bz#1566336 bz#1568896 bz#1578716 bz#1581047
      bz#1581231 bz#1582066 bz#1593865 bz#1597506 bz#1597511 bz#1597654 bz#1597768
      bz#1598105 bz#1598356 bz#1599037 bz#1599823 bz#1600057 bz#1601314

    [3.12.2-13]
    - fixes bugs bz#1493085 bz#1518710 bz#1554255 bz#1558948 bz#1558989
      bz#1559452 bz#1567001 bz#1569312 bz#1569951 bz#1575539 bz#1575557 bz#1577051
      bz#1580120 bz#1581184 bz#1581553 bz#1581647 bz#1582119 bz#1582129 bz#1582417
      bz#1583047 bz#1588408 bz#1592666 bz#1594658

    [3.12.2-12]
    - fixes bugs bz#1558989 bz#1580344 bz#1581057 bz#1581219

    [3.12.2-11]
    - fixes bugs bz#1558989 bz#1575555 bz#1578647

    [3.12.2-10]
    - fixes bugs bz#1488120 bz#1565577 bz#1568297 bz#1570586 bz#1572043
      bz#1572075 bz#1575840 bz#1575877

    [3.12.2-9]
    - fixes bugs bz#1546717 bz#1557551 bz#1558948 bz#1561999 bz#1563804
      bz#1565015 bz#1565119 bz#1565399 bz#1565577 bz#1567100 bz#1567899 bz#1568374
      bz#1568969 bz#1569490 bz#1570514 bz#1570541 bz#1570582 bz#1571645 bz#1572087
      bz#1572585 bz#1575895

    [3.12.2-8]
    - fixes bugs bz#1466129 bz#1475779 bz#1523216 bz#1535281 bz#1546941
      bz#1550315 bz#1550991 bz#1553677 bz#1554291 bz#1559452 bz#1560955 bz#1562744
      bz#1563692 bz#1565962 bz#1567110 bz#1569457

    [3.12.2-7]
    - fixes bugs bz#958062 bz#1186664 bz#1226874 bz#1446046 bz#1529451 bz#1550315
      bz#1557365 bz#1559884 bz#1561733

    [3.12.2-6]
    - fixes bugs bz#1491785 bz#1518710 bz#1523599 bz#1528733 bz#1550474
      bz#1550982 bz#1551186 bz#1552360 bz#1552414 bz#1552425 bz#1554255 bz#1554905
      bz#1555261 bz#1556895 bz#1557297 bz#1559084 bz#1559788

    [3.12.2-5]
    - fixes bugs bz#1378371 bz#1384983 bz#1472445 bz#1493085 bz#1508999
      bz#1516638 bz#1518260 bz#1529072 bz#1530519 bz#1537357 bz#1540908 bz#1541122
      bz#1541932 bz#1543068 bz#1544382 bz#1544852 bz#1545570 bz#1546075 bz#1546945
      bz#1546960 bz#1547012 bz#1549497

    [3.12.2-4]
    - fixes bugs bz#1446125 bz#1467536 bz#1530146 bz#1540600 bz#1540664
      bz#1540961 bz#1541830 bz#1543296

    [3.12.2-3]
    - fixes bugs bz#1446125 bz#1463592 bz#1516249 bz#1517463 bz#1527309
      bz#1530325 bz#1531041 bz#1539699 bz#1540011

    [3.12.2-2]
    - fixes bugs bz#1264911 bz#1277924 bz#1286820 bz#1360331 bz#1401969
      bz#1410719 bz#1419438 bz#1426042 bz#1444820 bz#1459101 bz#1464150 bz#1464350
      bz#1466122 bz#1466129 bz#1467903 bz#1468972 bz#1476876 bz#1484446 bz#1492591
      bz#1498391 bz#1498730 bz#1499865 bz#1500704 bz#1501345 bz#1505570 bz#1507361
      bz#1507394 bz#1509102 bz#1509191 bz#1509810 bz#1509833 bz#1511766 bz#1512470
      bz#1512496 bz#1512963 bz#1515051 bz#1519076 bz#1519740 bz#1534253 bz#1534530

    [3.12.2-1]
    - rebase to upstream glusterfs at v3.12.2
    - fixes bugs bz#1442983 bz#1474745 bz#1503244 bz#1505363 bz#1509102

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-3242.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'glusterfs-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-api-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-api-devel-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-cli-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-client-xlators-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-devel-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-fuse-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-libs-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-rdma-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-gluster-3.12.2-18.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-api-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-api-devel-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-cli-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-client-xlators-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-devel-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-fuse-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-libs-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glusterfs-rdma-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-gluster-3.12.2-18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glusterfs / glusterfs-api / glusterfs-api-devel / etc');
}
