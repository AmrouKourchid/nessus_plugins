#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.4-2024-059.
##

include('compat.inc');

if (description)
{
  script_id(190047);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id(
    "CVE-2023-6040",
    "CVE-2023-6546",
    "CVE-2023-6915",
    "CVE-2023-46838",
    "CVE-2023-52439",
    "CVE-2023-52448",
    "CVE-2023-52464",
    "CVE-2023-52469",
    "CVE-2023-52470",
    "CVE-2023-52612",
    "CVE-2023-52675",
    "CVE-2023-52679",
    "CVE-2023-52683",
    "CVE-2023-52691",
    "CVE-2023-52698",
    "CVE-2024-0565",
    "CVE-2024-0607",
    "CVE-2024-0646",
    "CVE-2024-23849",
    "CVE-2024-26633"
  );

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.4-2024-059)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.4.268-181.368. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.4-2024-059 advisory.

    2024-12-05: CVE-2023-52683 was added to this advisory.

    2024-12-05: CVE-2023-52679 was added to this advisory.

    2024-09-12: CVE-2023-52675 was added to this advisory.

    2024-09-12: CVE-2023-52691 was added to this advisory.

    2024-07-03: CVE-2023-52612 was added to this advisory.

    2024-07-03: CVE-2024-26633 was added to this advisory.

    2024-07-03: CVE-2023-52470 was added to this advisory.

    2024-06-06: CVE-2023-52698 was added to this advisory.

    2024-06-06: CVE-2023-52464 was added to this advisory.

    2024-04-25: CVE-2023-52448 was added to this advisory.

    2024-03-27: CVE-2023-52439 was added to this advisory.

    2024-03-13: CVE-2023-52469 was added to this advisory.

    2024-02-15: CVE-2023-6546 was added to this advisory.

    A flaw has been found in Xen. An unprivileged guest can cause Denial of Service (DoS) of the host by
    sending network packets to the backend, causing the backend to crash. (CVE-2023-46838)

    In the Linux kernel, the following vulnerability has been resolved:

    uio: Fix use-after-free in uio_open

    core-1                          core-2-------------------------------------------------------
    uio_unregister_device              uio_openidev = idr_find()device_unregister(&idev->dev)put_device(&idev-
    >dev)uio_device_releaseget_device(&idev->dev)kfree(idev)uio_free_minor(minor)uio_releaseput_device(&idev-
    >dev)kfree(idev)-------------------------------------------------------

    In the core-1 uio_unregister_device(), the device_unregister will kfreeidev when the idev->dev kobject ref
    is 1. But after core-1device_unregister, put_device and before doing kfree, the core-2 mayget_device.
    Then:1. After core-1 kfree idev, the core-2 will do use-after-free for idev.2. When core-2 do uio_release
    and put_device, the idev will be doublefreed.

    To address this issue, we can get idev atomic & inc idev reference withminor_lock. (CVE-2023-52439)

    In the Linux kernel, the following vulnerability has been resolved:

    gfs2: Fix kernel NULL pointer dereference in gfs2_rgrp_dump

    Syzkaller has reported a NULL pointer dereference when accessingrgd->rd_rgl in gfs2_rgrp_dump().  This can
    happen when creatingrgd->rd_gl fails in read_rindex_entry().  Add a NULL pointer check ingfs2_rgrp_dump()
    to prevent that. (CVE-2023-52448)

    In the Linux kernel, the following vulnerability has been resolved:

    EDAC/thunderx: Fix possible out-of-bounds string access

    Enabling -Wstringop-overflow globally exposes a warning for a common bugin the usage of strncat():

    drivers/edac/thunderx_edac.c: In function
    'thunderx_ocx_com_threaded_isr':drivers/edac/thunderx_edac.c:1136:17: error: 'strncat' specified bound
    1024 equals destination size [-Werror=stringop-overflow=]1136 |                 strncat(msg, other,
    OCX_MESSAGE_SIZE);|                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~...1145 |
    strncat(msg, other, OCX_MESSAGE_SIZE);...1150 |                                 strncat(msg, other,
    OCX_MESSAGE_SIZE);

    ...

    Apparently the author of this driver expected strncat() to behave theway that strlcat() does, which uses
    the size of the destination bufferas its third argument rather than the length of the source buffer.
    Theresult is that there is no check on the size of the allocated buffer.

    Change it to strlcat().

    [ bp: Trim compiler output, fixup commit message. ] (CVE-2023-52464)

    In the Linux kernel, the following vulnerability has been resolved:

    drivers/amd/pm: fix a use-after-free in kv_parse_power_table

    When ps allocated by kzalloc equals to NULL, kv_parse_power_tablefrees adev->pm.dpm.ps that allocated
    before. However, after the controlflow goes through the following call chains:

    kv_parse_power_table|-> kv_dpm_init|-> kv_dpm_sw_init|-> kv_dpm_fini

    The adev->pm.dpm.ps is used in the for loop of kv_dpm_fini after itsfirst free in kv_parse_power_table and
    causes a use-after-free bug. (CVE-2023-52469)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/radeon: check the alloc_workqueue return value in radeon_crtc_init()

    check the alloc_workqueue return value in radeon_crtc_init()to avoid null-ptr-deref. (CVE-2023-52470)

    In the Linux kernel, the following vulnerability has been resolved:

    crypto: scomp - fix req->dst buffer overflow (CVE-2023-52612)

    In the Linux kernel, the following vulnerability has been resolved:

    powerpc/imc-pmu: Add a null pointer check in update_events_in_group() (CVE-2023-52675)

    In the Linux kernel, the following vulnerability has been resolved:

    of: Fix double free in of_parse_phandle_with_args_map (CVE-2023-52679)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: LPIT: Avoid u32 multiplication overflow (CVE-2023-52683)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/amd/pm: fix a double-free in si_dpm_init (CVE-2023-52691)

    In the Linux kernel, the following vulnerability has been resolved:

    calipso: fix memory leak in netlbl_calipso_add_pass() (CVE-2023-52698)

    An out-of-bounds access vulnerability involving netfilter was reported and fixed as: f1082dd31fe4
    (netfilter: nf_tables: Reject tables of unsupported family); While creating a new netfilter table, lack of
    a safeguard against invalid nf_tables family (pf) values within `nf_tables_newtable` function enables an
    attacker to achieve out-of-bounds access. (CVE-2023-6040)

    A race condition was found in the GSM 0710 tty multiplexor in the Linux kernel. This issue occurs when two
    threads execute the GSMIOC_SETCONF ioctl on the same tty file descriptor with the gsm line discipline
    enabled, and can lead to a use-after-free problem on a struct gsm_dlci while restarting the gsm mux. This
    could allow a local unprivileged user to escalate their privileges on the system. (CVE-2023-6546)

    A Null pointer dereference problem was found in ida_free in lib/idr.c in the Linux Kernel. This issue may
    allow an attacker using this library to cause a denial of service problem due to a missing check at a
    function return. (CVE-2023-6915)

    An out-of-bounds memory read flaw was found in receive_encrypted_standard in fs/smb/client/smb2ops.c in
    the SMB Client sub-component in the Linux Kernel. This issue occurs due to integer underflow on the memcpy
    length, leading to a denial of service. (CVE-2024-0565)

    netfilter: nf_tables: fix pointer math issue in nft_byteorder_eval() (CVE-2024-0607)

    An out-of-bounds memory write flaw was found in the Linux kernel's Transport Layer Security functionality
    in how a user calls a function splice with a ktls socket as the destination. This flaw allows a local user
    to crash or potentially escalate their privileges on the system. (CVE-2024-0646)

    In rds_recv_track_latency in net/rds/af_rds.c in the Linux kernel through 6.7.1, there is an off-by-one
    error for an RDS_MSG_RX_DGRAM_TRACE_MAX comparison, resulting in out-of-bounds access. (CVE-2024-23849)

    In the Linux kernel, the following vulnerability has been resolved:

    ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (CVE-2024-26633)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2024-059.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6040.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6546.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6915.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-46838.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52439.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52448.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52464.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52469.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52470.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52612.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52679.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52683.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52691.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52698.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0565.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0607.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0646.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23849.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26633.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0565");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-0646");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "kpatch.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");
include("hotfixes.inc");

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

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-6040", "CVE-2023-6546", "CVE-2023-6915", "CVE-2023-46838", "CVE-2023-52439", "CVE-2023-52448", "CVE-2023-52464", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52612", "CVE-2023-52675", "CVE-2023-52679", "CVE-2023-52683", "CVE-2023-52691", "CVE-2023-52698", "CVE-2024-0565", "CVE-2024-0607", "CVE-2024-0646", "CVE-2024-23849", "CVE-2024-26633");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.4-2024-059");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.4"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-aarch64-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-x86_64-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.268-181.368.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.268-181.368.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.268-181.368.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'}
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
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
