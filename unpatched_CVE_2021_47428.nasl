#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224323);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47428");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47428");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: powerpc/64s: fix program check
    interrupt emergency stack path Emergency stack path was jumping into a 3: label inside the
    __GEN_COMMON_BODY macro for the normal path after it had finished, rather than jumping over it. By a small
    miracle this is the correct place to build up a new interrupt frame with the existing stack pointer, so
    things basically worked okay with an added weird looking 700 trap frame on top (which had the wrong ->nip
    so it didn't decode bug messages either). Fix this by avoiding using numeric labels when jumping over non-
    trivial macros. Before: LE PAGE_SIZE=64K MMU=Radix SMP NR_CPUS=2048 NUMA PowerNV Modules linked in: CPU: 0
    PID: 88 Comm: sh Not tainted 5.15.0-rc2-00034-ge057cdade6e5 #2637 NIP: 7265677368657265 LR:
    c00000000006c0c8 CTR: c0000000000097f0 REGS: c0000000fffb3a50 TRAP: 0700 Not tainted MSR: 9000000000021031
    <SF,HV,ME,IR,DR,LE> CR: 00000700 XER: 20040000 CFAR: c0000000000098b0 IRQMASK: 0 GPR00: c00000000006c964
    c0000000fffb3cf0 c000000001513800 0000000000000000 GPR04: 0000000048ab0778 0000000042000000
    0000000000000000 0000000000001299 GPR08: 000001e447c718ec 0000000022424282 0000000000002710
    c00000000006bee8 GPR12: 9000000000009033 c0000000016b0000 00000000000000b0 0000000000000001 GPR16:
    0000000000000000 0000000000000002 0000000000000000 0000000000000ff8 GPR20: 0000000000001fff
    0000000000000007 0000000000000080 00007fff89d90158 GPR24: 0000000002000000 0000000002000000
    0000000000000255 0000000000000300 GPR28: c000000001270000 0000000042000000 0000000048ab0778
    c000000080647e80 NIP [7265677368657265] 0x7265677368657265 LR [c00000000006c0c8]
    ___do_page_fault+0x3f8/0xb10 Call Trace: [c0000000fffb3cf0] [c00000000000bdac] soft_nmi_common+0x13c/0x1d0
    (unreliable) --- interrupt: 700 at decrementer_common_virt+0xb8/0x230 NIP: c0000000000098b8 LR:
    c00000000006c0c8 CTR: c0000000000097f0 REGS: c0000000fffb3d60 TRAP: 0700 Not tainted MSR: 9000000000021031
    <SF,HV,ME,IR,DR,LE> CR: 22424282 XER: 20040000 CFAR: c0000000000098b0 IRQMASK: 0 GPR00: c00000000006c964
    0000000000002400 c000000001513800 0000000000000000 GPR04: 0000000048ab0778 0000000042000000
    0000000000000000 0000000000001299 GPR08: 000001e447c718ec 0000000022424282 0000000000002710
    c00000000006bee8 GPR12: 9000000000009033 c0000000016b0000 00000000000000b0 0000000000000001 GPR16:
    0000000000000000 0000000000000002 0000000000000000 0000000000000ff8 GPR20: 0000000000001fff
    0000000000000007 0000000000000080 00007fff89d90158 GPR24: 0000000002000000 0000000002000000
    0000000000000255 0000000000000300 GPR28: c000000001270000 0000000042000000 0000000048ab0778
    c000000080647e80 NIP [c0000000000098b8] decrementer_common_virt+0xb8/0x230 LR [c00000000006c0c8]
    ___do_page_fault+0x3f8/0xb10 --- interrupt: 700 Instruction dump: XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX
    XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX
    XXXXXXXX ---[ end trace 6d28218e0cc3c949 ]--- After: ------------[ cut here ]------------ kernel BUG at
    arch/powerpc/kernel/exceptions-64s.S:491! Oops: Exception in kernel mode, sig: 5 [#1] LE PAGE_SIZE=64K
    MMU=Radix SMP NR_CPUS=2048 NUMA PowerNV Modules linked in: CPU: 0 PID: 88 Comm: login Not tainted
    5.15.0-rc2-00034-ge057cdade6e5-dirty #2638 NIP: c0000000000098b8 LR: c00000000006bf04 CTR:
    c0000000000097f0 REGS: c0000000fffb3d60 TRAP: 0700 Not tainted MSR: 9000000000021031 <SF,HV,ME,IR,DR,LE>
    CR: 24482227 XER: 00040000 CFAR: c0000000000098b0 IRQMASK: 0 GPR00: c00000000006bf04 0000000000002400
    c000000001513800 c000000001271868 GPR04: 00000000100f0d29 0000000042000000 0000000000000007
    0000000000000009 GPR08: 00000000100f0d29 0000000024482227 0000000000002710 c000000000181b3c GPR12:
    9000000000009033 c0000000016b0000 00000000100f0d29 c000000005b22f00 GPR16: 00000000ffff0000
    0000000000000001 0000000000000009 00000000100eed90 GPR20: 00000000100eed90 00000 ---truncated---
    (CVE-2021-47428)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-ibm",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "kernel-rt",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "9"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
