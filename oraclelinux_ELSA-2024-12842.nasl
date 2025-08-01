#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12842.
##

include('compat.inc');

if (description)
{
  script_id(211827);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2023-45236",
    "CVE-2023-45237",
    "CVE-2024-1298",
    "CVE-2024-25742"
  );

  script_name(english:"Oracle Linux 9 : edk2 (ELSA-2024-12842)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12842 advisory.

    - EDK2: EDK2 contains a vulnerability when S3 sleep is activated where an Attacker may cause a Division-
    By-Zero due to a UNIT32 overflow via local access [Orabug: 36990130] {CVE-2024-1298}
    - EDK2: In the Linux kernel before 6.9, an untrusted hypervisor can inject virtual interrupt 29 (#VC) at
    any point in time and can trigger its handler. [Orabug: 36990244] {CVE-2024-25742}
    - EDK2: EDK2's Network Package is susceptible to a predictable TCP Initial Sequence Number. [Orabug:
    36990198] {CVE-2023-45236}
    - EDK2: EDK2's Network Package is susceptible to a predictable TCP Initial Sequence Number. [Orabug:
    36990210] {CVE-2023-45237}

    * Tue Feb 27 2024 Aaron Young <aaron.young@oracle.com>
    - Create new 20240227 release for OL9 which includes the following fixed CVEs:
      {CVE-2023-45229} {CVE-2023-45230} {CVE-2023-45231} {CVE-2023-45232} {CVE-2023-45233} {CVE-2023-45234}
    {CVE-2023-45235} {CVE-2022-36763} {CVE-2022-36764} {CVE-2022-36765}
    - Update to OpenSSL 3.0.10 which includes the following fixed CVEs:
      {CVE-2023-2975} {CVE-2023-1255} {CVE-2023-0401} {CVE-2023-0217} {CVE-2023-0216} {CVE-2023-0215}
    {CVE-2022-4203} {CVE-2022-3996} {CVE-2022-3602} {CVE-2022-3786} {CVE-2022-3358} {CVE-2022-2274}
    {CVE-2022-1473} {CVE-2022-1434} {CVE-2022-1343} {CVE-2021-4044} {CVE-2021-23839}

    * Tue Aug 22 2023 Aaron Young <aaron.young@oracle.com>
    - Create new 20230821 release for OL9 which includes the following fixed CVEs:
      {CVE-2019-14560}
    - Update to OpenSSL 1.1.1v which includes the following fixed CVEs:
      {CVE-2023-3817} {CVE-2023-3446} {CVE-2023-2650} {CVE-2023-0465} {CVE-2023-0466} {CVE-2023-0464}
    {CVE-2023-0286} {CVE-2023-0215} {CVE-2022-4450} {CVE-2022-4304} {CVE-2022-2097} {CVE-2022-2068}
    {CVE-2022-1292} {CVE-2022-0778} {CVE-2021-4160} {CVE-2021-3712} {CVE-2021-3711} {CVE-2021-3450}
    {CVE-2021-3449} {CVE-2021-23841} {CVE-2021-23840} {CVE-2020-1971} {CVE-2020-1967} {CVE-2019-1551}
    {CVE-2019-1563} {CVE-2019-1549} {CVE-2019-1547} {CVE-2019-1552} {CVE-2019-1543} {CVE-2018-0734}
    {CVE-2018-0735}

    * Tue Jun 13 2023 Aaron Young <aaron.young@oracle.com>

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12842.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected edk2-aarch64, edk2-ovmf and / or edk2-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45237");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::developer_kvm_utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::kvm_utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:edk2-ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:edk2-tools");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'edk2-aarch64-20240909-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'edk2-tools-20240909-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'edk2-ovmf-20240909-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'},
    {'reference':'edk2-tools-20240909-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'30'}
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
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, require_epoch_match:TRUE, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, require_epoch_match:TRUE, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'edk2-aarch64 / edk2-ovmf / edk2-tools');
}
