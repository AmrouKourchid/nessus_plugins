#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227538);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26589");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26589");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Reject variable offset alu on
    PTR_TO_FLOW_KEYS For PTR_TO_FLOW_KEYS, check_flow_keys_access() only uses fixed off for validation.
    However, variable offset ptr alu is not prohibited for this ptr kind. So the variable offset is not
    checked. The following prog is accepted: func#0 @0 0: R1=ctx() R10=fp0 0: (bf) r6 = r1 ; R1=ctx()
    R6_w=ctx() 1: (79) r7 = *(u64 *)(r6 +144) ; R6_w=ctx() R7_w=flow_keys() 2: (b7) r8 = 1024 ; R8_w=1024 3:
    (37) r8 /= 1 ; R8_w=scalar() 4: (57) r8 &= 1024 ; R8_w=scalar(smin=smin32=0,
    smax=umax=smax32=umax32=1024,var_off=(0x0; 0x400)) 5: (0f) r7 += r8 mark_precise: frame0: last_idx 5
    first_idx 0 subseq_idx -1 mark_precise: frame0: regs=r8 stack= before 4: (57) r8 &= 1024 mark_precise:
    frame0: regs=r8 stack= before 3: (37) r8 /= 1 mark_precise: frame0: regs=r8 stack= before 2: (b7) r8 =
    1024 6: R7_w=flow_keys(smin=smin32=0,smax=umax=smax32=umax32=1024,var_off =(0x0; 0x400))
    R8_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=1024, var_off=(0x0; 0x400)) 6: (79) r0 = *(u64 *)(r7 +0)
    ; R0_w=scalar() 7: (95) exit This prog loads flow_keys to r7, and adds the variable offset r8 to r7, and
    finally causes out-of-bounds access: BUG: unable to handle page fault for address: ffffc90014c80038 [...]
    Call Trace: <TASK> bpf_dispatcher_nop_func include/linux/bpf.h:1231 [inline] __bpf_prog_run
    include/linux/filter.h:651 [inline] bpf_prog_run include/linux/filter.h:658 [inline]
    bpf_prog_run_pin_on_cpu include/linux/filter.h:675 [inline] bpf_flow_dissect+0x15f/0x350
    net/core/flow_dissector.c:991 bpf_prog_test_run_flow_dissector+0x39d/0x620 net/bpf/test_run.c:1359
    bpf_prog_test_run kernel/bpf/syscall.c:4107 [inline] __sys_bpf+0xf8f/0x4560 kernel/bpf/syscall.c:5475
    __do_sys_bpf kernel/bpf/syscall.c:5561 [inline] __se_sys_bpf kernel/bpf/syscall.c:5559 [inline]
    __x64_sys_bpf+0x73/0xb0 kernel/bpf/syscall.c:5559 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0x3f/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b Fix this by
    rejecting ptr alu with variable offset on flow_keys. Applying the patch rejects the program with R7
    pointer arithmetic on flow_keys prohibited. (CVE-2024-26589)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26589");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
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
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
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
