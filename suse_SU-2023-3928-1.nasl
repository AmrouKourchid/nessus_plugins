#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3928-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(182507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id(
    "CVE-2023-1829",
    "CVE-2023-3609",
    "CVE-2023-3776",
    "CVE-2023-3812",
    "CVE-2023-4273",
    "CVE-2023-31248"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3928-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (Live Patch 0 for SLE 15 SP5) (SUSE-SU-2023:3928-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:3928-1 advisory.

  - A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited
    to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate
    filters in case of a perfect hashes while deleting the underlying structure which can later lead to double
    freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to root.
    We recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28. (CVE-2023-1829)

  - Linux Kernel nftables Use-After-Free Local Privilege Escalation Vulnerability; `nft_chain_lookup_byid()`
    failed to check whether a chain was active and CAP_NET_ADMIN is in any user or network namespace
    (CVE-2023-31248)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to
    achieve local privilege escalation. If tcf_change_indev() fails, u32_set_parms() will immediately return
    an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can
    control the reference counter and set it to zero, they can cause the reference to be freed, leading to a
    use-after-free vulnerability. We recommend upgrading past commit 04c55383fa5689357bcdd2c8036725a55ed632bc.
    (CVE-2023-3609)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to
    achieve local privilege escalation. If tcf_change_indev() fails, fw_set_parms() will immediately return an
    error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can
    control the reference counter and set it to zero, they can cause the reference to be freed, leading to a
    use-after-free vulnerability. We recommend upgrading past commit 0323bce598eea038714f941ce2b22541c46d488f.
    (CVE-2023-3776)

  - An out-of-bounds memory access flaw was found in the Linux kernel's TUN/TAP device driver functionality in
    how a user generates a malicious (too big) networking packet when napi frags is enabled. This flaw allows
    a local user to crash or potentially escalate their privileges on the system. (CVE-2023-3812)

  - A flaw was found in the exFAT driver of the Linux kernel. The vulnerability exists in the implementation
    of the file name reconstruction function, which is responsible for reading file name entries from a
    directory index and merging file name parts belonging to one file into a single long file name. Since the
    file name characters are copied into a stack variable, a local privileged attacker could use this flaw to
    overflow the kernel stack. (CVE-2023-4273)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215119");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-October/016475.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbea0fb9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4273");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-livepatch-5_14_21-150400_24_21-default, kernel-livepatch-5_14_21-150500_53-default and / or
kernel-livepatch-5_3_18-150300_59_115-default packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3812");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_24_21-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_53-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_115-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

var uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4/5", os_ver + " SP" + service_pack);

var kernel_live_checks = [
  {
    'kernels': {
      '5.14.21-150400.24.21-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_14_21-150400_24_21-default-14-150400.2.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']}
        ]
      },
      '5.14.21-150500.53-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_14_21-150500_53-default-4-150500.9.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']}
        ]
      },
      '5.3.18-150300.59.115-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_115-default-7-150300.2.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      }
    }
  }
];

var ltss_caveat_required = FALSE;
var flag = 0;
var kernel_affected = FALSE;
foreach var kernel_array ( kernel_live_checks ) {
  var kpatch_details = kernel_array['kernels'][uname_r];
  if (empty_or_null(kpatch_details)) continue;
  kernel_affected = TRUE;
  foreach var package_array ( kpatch_details['pkgs'] ) {
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
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

# No kpatch details found for the running kernel version
if (!kernel_affected) audit(AUDIT_INST_VER_NOT_VULN, 'kernel', uname_r);

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-5_14_21-150400_24_21-default / etc');
}
