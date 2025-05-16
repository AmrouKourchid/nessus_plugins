#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-519.
##

include('compat.inc');

if (description)
{
  script_id(190728);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2023-46838",
    "CVE-2023-52439",
    "CVE-2023-52447",
    "CVE-2023-52458",
    "CVE-2023-52462",
    "CVE-2023-52463",
    "CVE-2023-52467",
    "CVE-2023-52610",
    "CVE-2023-52612",
    "CVE-2023-52675",
    "CVE-2023-52679",
    "CVE-2023-52683",
    "CVE-2023-52693",
    "CVE-2023-52698",
    "CVE-2023-6915",
    "CVE-2024-1085",
    "CVE-2024-26589",
    "CVE-2024-26591",
    "CVE-2024-26598",
    "CVE-2024-26631",
    "CVE-2024-26632",
    "CVE-2024-26633",
    "CVE-2024-35839",
    "CVE-2024-35840"
  );

  script_name(english:"Amazon Linux 2023 : bpftool, kernel, kernel-devel (ALAS2023-2024-519)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-519 advisory.

    2024-12-05: CVE-2024-35839 was added to this advisory.

    2024-12-05: CVE-2023-52683 was added to this advisory.

    2024-12-05: CVE-2023-52693 was added to this advisory.

    2024-12-05: CVE-2023-52679 was added to this advisory.

    2024-09-12: CVE-2024-35840 was added to this advisory.

    2024-09-12: CVE-2023-52675 was added to this advisory.

    2024-07-03: CVE-2024-26631 was added to this advisory.

    2024-07-03: CVE-2024-26632 was added to this advisory.

    2024-07-03: CVE-2023-52610 was added to this advisory.

    2024-07-03: CVE-2024-26633 was added to this advisory.

    2024-07-03: CVE-2023-52612 was added to this advisory.

    2024-06-06: CVE-2023-52698 was added to this advisory.

    2024-04-25: CVE-2023-52462 was added to this advisory.

    2024-04-25: CVE-2024-26591 was added to this advisory.

    2024-04-25: CVE-2023-52467 was added to this advisory.

    2024-04-25: CVE-2023-52458 was added to this advisory.

    2024-04-25: CVE-2023-52447 was added to this advisory.

    2024-04-10: CVE-2024-26598 was added to this advisory.

    2024-03-27: CVE-2023-52439 was added to this advisory.

    2024-03-13: CVE-2023-52463 was added to this advisory.

    2024-03-13: CVE-2024-26589 was added to this advisory.

    2024-02-29: CVE-2023-6915 was added to this advisory.

    2024-02-29: CVE-2023-46838 was added to this advisory.

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

    bpf: Defer the free of inner map when necessary

    When updating or deleting an inner map in map array or map htab, the mapmay still be accessed by non-
    sleepable program or sleepable program.However bpf_map_fd_put_ptr() decreases the ref-counter of the inner
    mapdirectly through bpf_map_put(), if the ref-counter is the last one(which is true for most cases), the
    inner map will be freed byops->map_free() in a kworker. But for now, most .map_free() callbacksdon't use
    synchronize_rcu() or its variants to wait for the elapse of aRCU grace period, so after the invocation of
    ops->map_free completes,the bpf program which is accessing the inner map may incuruse-after-free problem.

    Fix the free of inner map by invoking bpf_map_free_deferred() after bothone RCU grace period and one tasks
    trace RCU grace period if the innermap has been removed from the outer map before. The deferment
    isaccomplished by using call_rcu() or call_rcu_tasks_trace() whenreleasing the last ref-counter of bpf
    map. The newly-added rcu_headfield in bpf_map shares the same storage space with work field toreduce the
    size of bpf_map. (CVE-2023-52447)

    In the Linux kernel, the following vulnerability has been resolved:

    block: add check that partition length needs to be aligned with block size

    Before calling add partition or resize partition, there is no checkon whether the length is aligned with
    the logical block size.If the logical block size of the disk is larger than 512 bytes,then the partition
    size maybe not the multiple of the logical block size,and when the last sector is read, bio_truncate()
    will adjust the bio size,resulting in an IO error if the size of the read command is smaller thanthe
    logical block size.If integrity data is supported, this will alsoresult in a null pointer dereference when
    calling bio_integrity_free. (CVE-2023-52458)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: fix check for attempt to corrupt spilled pointer (CVE-2023-52462)

    In the Linux kernel, the following vulnerability has been resolved: efivarfs: force RO when remounting if
    SetVariable is not supported If SetVariable at runtime is not supported by the firmware we never assign a
    callback for that function. At the same time mount the efivarfs as RO so no one can call that. However, we
    never check the permission flags when someone remounts the filesystem as RW. As a result this leads to a
    crash (CVE-2023-52463)

    In the Linux kernel, the following vulnerability has been resolved:

    mfd: syscon: Fix null pointer dereference in of_syscon_register()

    kasprintf() returns a pointer to dynamically allocated memorywhich can be NULL upon failure.
    (CVE-2023-52467)

    In the Linux kernel, the following vulnerability has been resolved:

    net/sched: act_ct: fix skb leak and crash on ooo frags (CVE-2023-52610)

    In the Linux kernel, the following vulnerability has been resolved:

    crypto: scomp - fix req->dst buffer overflow (CVE-2023-52612)

    In the Linux kernel, the following vulnerability has been resolved:

    powerpc/imc-pmu: Add a null pointer check in update_events_in_group() (CVE-2023-52675)

    In the Linux kernel, the following vulnerability has been resolved:

    of: Fix double free in of_parse_phandle_with_args_map (CVE-2023-52679)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: LPIT: Avoid u32 multiplication overflow (CVE-2023-52683)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: video: check for error while searching for backlight device parent (CVE-2023-52693)

    In the Linux kernel, the following vulnerability has been resolved:

    calipso: fix memory leak in netlbl_calipso_add_pass() (CVE-2023-52698)

    A Null pointer dereference problem was found in ida_free in lib/idr.c in the Linux Kernel. This issue may
    allow an attacker using this library to cause a denial of service problem due to a missing check at a
    function return. (CVE-2023-6915)

    A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation.

    The nft_setelem_catchall_deactivate() function checks whether the catch-all set element is active in the
    current generation instead of the next generation before freeing it, but only flags it inactive in the
    next generation, making it possible to free the element multiple times, leading to a double free
    vulnerability.

    We recommend upgrading past commit b1db244ffd041a49ecc9618e8feb6b5c1afcdaa7. (CVE-2024-1085)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Reject variable offset alu on PTR_TO_FLOW_KEYS

    check_flow_keys_access() results in out of bounds access .For PTR_TO_FLOW_KEYS, check_flow_keys_access()
    only uses fixed offfor validation. However, variable offset ptr alu is not prohibitedfor this ptr kind. So
    the variable offset is not checked. (CVE-2024-26589)

    bpf: Fix re-attachment branch in bpf_tracing_prog_attach

    The following case can cause a crash due to missing attach_btf:

    1) load rawtp program2) load fentry program with rawtp as target_fd3) create tracing link for fentry
    program with target_fd = 04) repeat 3 (CVE-2024-26591)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: arm64: vgic-its: Avoid potential UAF in LPI translation cache (CVE-2024-26598)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: mcast: fix data-race in ipv6_mc_down / mld_ifc_work (CVE-2024-26631)

    In the Linux kernel, the following vulnerability has been resolved:

    block: Fix iterating over an empty bio with bio_for_each_folio_all (CVE-2024-26632)

    In the Linux kernel, the following vulnerability has been resolved:

    ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (CVE-2024-26633)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: bridge: replace physindev with physinif in nf_bridge_info (CVE-2024-35839)

    In the Linux kernel, the following vulnerability has been resolved:

    mptcp: use OPTION_MPTCP_MPJ_SYNACK in subflow_finish_connect() (CVE-2024-35840)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-519.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-46838.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52439.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52447.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52458.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52462.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52463.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52467.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52610.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52612.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52679.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52683.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52693.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-52698.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-6915.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-1085.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26589.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26591.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26598.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26631.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26632.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-26633.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35839.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35840.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update kernel --releasever 2023.3.20240219' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26598");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-libbpf-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-6.1.75-99.163");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-modules-extra-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2023-6915", "CVE-2023-46838", "CVE-2023-52439", "CVE-2023-52447", "CVE-2023-52458", "CVE-2023-52462", "CVE-2023-52463", "CVE-2023-52467", "CVE-2023-52610", "CVE-2023-52612", "CVE-2023-52675", "CVE-2023-52679", "CVE-2023-52683", "CVE-2023-52693", "CVE-2023-52698", "CVE-2024-1085", "CVE-2024-26589", "CVE-2024-26591", "CVE-2024-26598", "CVE-2024-26631", "CVE-2024-26632", "CVE-2024-26633", "CVE-2024-35839", "CVE-2024-35840");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS2023-2024-519");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var pkgs = [
    {'reference':'bpftool-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-aarch64-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-devel-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-libbpf-static-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.75-99.163-1.0-0.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-livepatch-6.1.75-99.163-1.0-0.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-common-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-debuginfo-6.1.75-99.163.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
