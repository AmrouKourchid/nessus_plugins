#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2024-0010.
##

include('compat.inc');

if (description)
{
  script_id(205210);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/08");

  script_cve_id(
    "CVE-2021-47495",
    "CVE-2022-24448",
    "CVE-2023-52528",
    "CVE-2023-52813",
    "CVE-2023-52880",
    "CVE-2024-25739",
    "CVE-2024-26642",
    "CVE-2024-27020",
    "CVE-2024-36934",
    "CVE-2024-36941",
    "CVE-2024-36946",
    "CVE-2024-41090",
    "CVE-2024-41091"
  );

  script_name(english:"OracleVM 3.4 : kernel-uek (OVMSA-2024-0010)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

    [4.1.12-124.88.3]- crypto: pcrypt - Fix hungtask for PADATA_RESET (Lu Jialin)  [Orabug: 36806710]
    {CVE-2023-52813}- usbnet: sanity check for maxpacket (Oliver Neukum)  [Orabug: 36806658]
    {CVE-2021-47495}- phonet: fix rtm_phonet_notify() skb allocation (Eric Dumazet)  [Orabug: 36683487]
    {CVE-2024-36946}- wifi: nl80211: don't free NULL coalescing rule (Johannes Berg)  [Orabug: 36683466]
    {CVE-2024-36941}- bna: ensure the copied buf is NUL terminated (Bui Quang Minh)  [Orabug: 36683433]
    {CVE-2024-36934}- bna: use memdup_user to copy userspace buffers (Ivan Vecera)  [Orabug: 36683433]
    {CVE-2024-36934}- new helper: memdup_user_nul() (Al Viro)  [Orabug: 36683433]  {CVE-2024-36934}-
    netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (Ziyang Xuan)  [Orabug: 36598047]
    {CVE-2024-27020}- netfilter: nf_tables: __nft_expr_type_get() selects specific family type (Pablo Neira
    Ayuso)  [Orabug: 36598047]  {CVE-2024-27020}- net/mlx5e: drop shorter ethernet frames (Manjunath Patil)
    [Orabug: 36879159]  {CVE-2024-41090} {CVE-2024-41091}[4.1.12-124.88.2]- net: usb: smsc75xx: Fix uninit-
    value access in __smsc75xx_read_reg (Shigeru Yoshida)  [Orabug: 36802310]  {CVE-2023-52528}-
    usbnet/smsc75xx: silence uninitialized variable warning (Dan Carpenter)   {CVE-2023-52528}- tty: n_gsm:
    require CAP_NET_ADMIN to attach N_GSM0710 ldisc (Thadeu Lima de Souza Cascardo)  [Orabug: 36685663]
    {CVE-2023-52880}- netfilter: nf_tables: disallow anonymous set with timeout flag (Pablo Neira Ayuso)
    [Orabug: 36530112]  {CVE-2024-26642}- ubi: Check for too small LEB size in VTBL code (Richard Weinberger)
    [Orabug: 36356637]  {CVE-2024-25739}[4.1.12-124.88.1]- NFS: LOOKUP_DIRECTORY is also ok with symlinks
    (Trond Myklebust)  [Orabug: 33958156]  {CVE-2022-24448}- NFSv4: Handle case where the lookup of a
    directory fails (Trond Myklebust)  [Orabug: 33958156]  {CVE-2022-24448}

Tenable has extracted the preceding description block directly from the OracleVM security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-47495.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2022-24448.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52528.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52813.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2023-52880.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-25739.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-26642.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-27020.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-36934.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-36941.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-36946.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-41090.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2024-41091.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2024-0010.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek / kernel-uek-firmware packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24448");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-27020");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.88.3.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for OVMSA-2024-0010');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.1';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.1.12-124.88.3.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.88.3.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  if (!empty_or_null(package_array['release'])) _release = 'OVS' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-firmware');
}
