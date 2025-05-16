#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231858);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-50223");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-50223");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: sched/numa: Fix the potential null
    pointer dereference in task_numa_work() When running stress-ng-vm-segv test, we found a null pointer
    dereference error in task_numa_work(). Here is the backtrace: [323676.066985] Unable to handle kernel NULL
    pointer dereference at virtual address 0000000000000020 ...... [323676.067108] CPU: 35 PID: 2694524 Comm:
    stress-ng-vm-se ...... [323676.067113] pstate: 23401009 (nzCv daif +PAN -UAO +TCO +DIT +SSBS BTYPE=--)
    [323676.067115] pc : vma_migratable+0x1c/0xd0 [323676.067122] lr : task_numa_work+0x1ec/0x4e0
    [323676.067127] sp : ffff8000ada73d20 [323676.067128] x29: ffff8000ada73d20 x28: 0000000000000000 x27:
    000000003e89f010 [323676.067130] x26: 0000000000080000 x25: ffff800081b5c0d8 x24: ffff800081b27000
    [323676.067133] x23: 0000000000010000 x22: 0000000104d18cc0 x21: ffff0009f7158000 [323676.067135] x20:
    0000000000000000 x19: 0000000000000000 x18: ffff8000ada73db8 [323676.067138] x17: 0001400000000000 x16:
    ffff800080df40b0 x15: 0000000000000035 [323676.067140] x14: ffff8000ada73cc8 x13: 1fffe0017cc72001 x12:
    ffff8000ada73cc8 [323676.067142] x11: ffff80008001160c x10: ffff000be639000c x9 : ffff8000800f4ba4
    [323676.067145] x8 : ffff000810375000 x7 : ffff8000ada73974 x6 : 0000000000000001 [323676.067147] x5 :
    0068000b33e26707 x4 : 0000000000000001 x3 : ffff0009f7158000 [323676.067149] x2 : 0000000000000041 x1 :
    0000000000004400 x0 : 0000000000000000 [323676.067152] Call trace: [323676.067153]
    vma_migratable+0x1c/0xd0 [323676.067155] task_numa_work+0x1ec/0x4e0 [323676.067157]
    task_work_run+0x78/0xd8 [323676.067161] do_notify_resume+0x1ec/0x290 [323676.067163] el0_svc+0x150/0x160
    [323676.067167] el0t_64_sync_handler+0xf8/0x128 [323676.067170] el0t_64_sync+0x17c/0x180 [323676.067173]
    Code: d2888001 910003fd f9000bf3 aa0003f3 (f9401000) [323676.067177] SMP: stopping secondary CPUs
    [323676.070184] Starting crashdump kernel... stress-ng-vm-segv in stress-ng is used to stress test the
    SIGSEGV error handling function of the system, which tries to cause a SIGSEGV error on return from
    unmapping the whole address space of the child process. Normally this program will not cause kernel
    crashes. But before the munmap system call returns to user mode, a potential task_numa_work() for numa
    balancing could be added and executed. In this scenario, since the child process has no vma after munmap,
    the vma_next() in task_numa_work() will return a null pointer even if the vma iterator restarts from 0.
    Recheck the vma pointer before dereferencing it in task_numa_work(). (CVE-2024-50223)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "linux-aws-cloud-tools-6.8.0-1008",
     "linux-aws-headers-6.8.0-1008",
     "linux-aws-tools-6.8.0-1008",
     "linux-azure-cloud-tools-6.8.0-1007",
     "linux-azure-headers-6.8.0-1007",
     "linux-azure-tools-6.8.0-1007",
     "linux-buildinfo-6.8.0-1003-gke",
     "linux-buildinfo-6.8.0-1004-raspi",
     "linux-buildinfo-6.8.0-1005-ibm",
     "linux-buildinfo-6.8.0-1005-oem",
     "linux-buildinfo-6.8.0-1005-oracle",
     "linux-buildinfo-6.8.0-1005-oracle-64k",
     "linux-buildinfo-6.8.0-1007-azure",
     "linux-buildinfo-6.8.0-1007-gcp",
     "linux-buildinfo-6.8.0-1008-aws",
     "linux-buildinfo-6.8.0-31-generic",
     "linux-buildinfo-6.8.0-31-generic-64k",
     "linux-buildinfo-6.8.0-31-lowlatency",
     "linux-cloud-tools-6.8.0-1005-ibm",
     "linux-cloud-tools-6.8.0-1005-oem",
     "linux-cloud-tools-6.8.0-1005-oracle",
     "linux-cloud-tools-6.8.0-1005-oracle-64k",
     "linux-cloud-tools-6.8.0-1007-azure",
     "linux-cloud-tools-6.8.0-1008-aws",
     "linux-cloud-tools-6.8.0-31",
     "linux-cloud-tools-6.8.0-31-generic",
     "linux-cloud-tools-6.8.0-31-generic-64k",
     "linux-cloud-tools-6.8.0-31-lowlatency",
     "linux-cloud-tools-6.8.0-31-lowlatency-64k",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-headers-6.8.0-1007",
     "linux-gcp-tools-6.8.0-1007",
     "linux-gke-headers-6.8.0-1003",
     "linux-gke-tools-6.8.0-1003",
     "linux-gkeop",
     "linux-headers-6.8.0-1003-gke",
     "linux-headers-6.8.0-1004-raspi",
     "linux-headers-6.8.0-1005-ibm",
     "linux-headers-6.8.0-1005-oem",
     "linux-headers-6.8.0-1005-oracle",
     "linux-headers-6.8.0-1005-oracle-64k",
     "linux-headers-6.8.0-1007-azure",
     "linux-headers-6.8.0-1007-gcp",
     "linux-headers-6.8.0-1008-aws",
     "linux-headers-6.8.0-31",
     "linux-headers-6.8.0-31-generic",
     "linux-headers-6.8.0-31-generic-64k",
     "linux-headers-6.8.0-31-lowlatency",
     "linux-headers-6.8.0-31-lowlatency-64k",
     "linux-ibm-cloud-tools-6.8.0-1005",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-6.8.0-1005",
     "linux-ibm-source-6.8.0",
     "linux-ibm-tools-6.8.0-1005",
     "linux-ibm-tools-common",
     "linux-image-6.8.0-1004-raspi",
     "linux-image-6.8.0-1004-raspi-dbgsym",
     "linux-image-6.8.0-31-generic",
     "linux-image-6.8.0-31-generic-dbgsym",
     "linux-image-unsigned-6.8.0-1003-gke",
     "linux-image-unsigned-6.8.0-1003-gke-dbgsym",
     "linux-image-unsigned-6.8.0-1005-ibm",
     "linux-image-unsigned-6.8.0-1005-ibm-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oem",
     "linux-image-unsigned-6.8.0-1005-oem-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oracle",
     "linux-image-unsigned-6.8.0-1005-oracle-64k",
     "linux-image-unsigned-6.8.0-1005-oracle-64k-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oracle-dbgsym",
     "linux-image-unsigned-6.8.0-1007-azure",
     "linux-image-unsigned-6.8.0-1007-azure-dbgsym",
     "linux-image-unsigned-6.8.0-1007-gcp",
     "linux-image-unsigned-6.8.0-1007-gcp-dbgsym",
     "linux-image-unsigned-6.8.0-1008-aws",
     "linux-image-unsigned-6.8.0-1008-aws-dbgsym",
     "linux-image-unsigned-6.8.0-31-generic",
     "linux-image-unsigned-6.8.0-31-generic-64k",
     "linux-image-unsigned-6.8.0-31-generic-64k-dbgsym",
     "linux-image-unsigned-6.8.0-31-generic-dbgsym",
     "linux-image-unsigned-6.8.0-31-lowlatency",
     "linux-image-unsigned-6.8.0-31-lowlatency-64k",
     "linux-image-unsigned-6.8.0-31-lowlatency-64k-dbgsym",
     "linux-image-unsigned-6.8.0-31-lowlatency-dbgsym",
     "linux-intel",
     "linux-lib-rust-6.8.0-31-generic",
     "linux-lib-rust-6.8.0-31-generic-64k",
     "linux-libc-dev",
     "linux-lowlatency-cloud-tools-6.8.0-31",
     "linux-lowlatency-cloud-tools-common",
     "linux-lowlatency-headers-6.8.0-31",
     "linux-lowlatency-hwe-6.11",
     "linux-lowlatency-lib-rust-6.8.0-31-lowlatency",
     "linux-lowlatency-lib-rust-6.8.0-31-lowlatency-64k",
     "linux-lowlatency-tools-6.8.0-31",
     "linux-lowlatency-tools-common",
     "linux-lowlatency-tools-host",
     "linux-modules-6.8.0-1003-gke",
     "linux-modules-6.8.0-1004-raspi",
     "linux-modules-6.8.0-1005-ibm",
     "linux-modules-6.8.0-1005-oem",
     "linux-modules-6.8.0-1005-oracle",
     "linux-modules-6.8.0-1005-oracle-64k",
     "linux-modules-6.8.0-1007-azure",
     "linux-modules-6.8.0-1007-gcp",
     "linux-modules-6.8.0-1008-aws",
     "linux-modules-6.8.0-31-generic",
     "linux-modules-6.8.0-31-generic-64k",
     "linux-modules-6.8.0-31-lowlatency",
     "linux-modules-6.8.0-31-lowlatency-64k",
     "linux-modules-extra-6.8.0-1003-gke",
     "linux-modules-extra-6.8.0-1005-ibm",
     "linux-modules-extra-6.8.0-1005-oem",
     "linux-modules-extra-6.8.0-1005-oracle",
     "linux-modules-extra-6.8.0-1005-oracle-64k",
     "linux-modules-extra-6.8.0-1007-azure",
     "linux-modules-extra-6.8.0-1007-gcp",
     "linux-modules-extra-6.8.0-1008-aws",
     "linux-modules-extra-6.8.0-31-generic",
     "linux-modules-extra-6.8.0-31-generic-64k",
     "linux-modules-extra-6.8.0-31-lowlatency",
     "linux-modules-extra-6.8.0-31-lowlatency-64k",
     "linux-modules-ipu6-6.8.0-1005-oem",
     "linux-modules-ipu6-6.8.0-31-generic",
     "linux-modules-ivsc-6.8.0-31-generic",
     "linux-modules-iwlwifi-6.8.0-1004-raspi",
     "linux-modules-iwlwifi-6.8.0-1005-ibm",
     "linux-modules-iwlwifi-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1005-oracle",
     "linux-modules-iwlwifi-6.8.0-1005-oracle-64k",
     "linux-modules-iwlwifi-6.8.0-1007-azure",
     "linux-modules-iwlwifi-6.8.0-1007-gcp",
     "linux-modules-iwlwifi-6.8.0-31-generic",
     "linux-modules-iwlwifi-6.8.0-31-lowlatency",
     "linux-nvidia",
     "linux-nvidia-lowlatency",
     "linux-oem-6.8-headers-6.8.0-1005",
     "linux-oem-6.8-lib-rust-6.8.0-1005-oem",
     "linux-oem-6.8-tools-6.8.0-1005",
     "linux-oracle-headers-6.8.0-1005",
     "linux-oracle-tools-6.8.0-1005",
     "linux-raspi-headers-6.8.0-1004",
     "linux-raspi-realtime",
     "linux-raspi-tools-6.8.0-1004",
     "linux-realtime",
     "linux-riscv-headers-6.8.0-31",
     "linux-riscv-tools-6.8.0-31",
     "linux-source-6.8.0",
     "linux-tools-6.8.0-1003-gke",
     "linux-tools-6.8.0-1004-raspi",
     "linux-tools-6.8.0-1005-ibm",
     "linux-tools-6.8.0-1005-oem",
     "linux-tools-6.8.0-1005-oracle",
     "linux-tools-6.8.0-1005-oracle-64k",
     "linux-tools-6.8.0-1007-azure",
     "linux-tools-6.8.0-1007-gcp",
     "linux-tools-6.8.0-1008-aws",
     "linux-tools-6.8.0-31",
     "linux-tools-6.8.0-31-generic",
     "linux-tools-6.8.0-31-generic-64k",
     "linux-tools-6.8.0-31-lowlatency",
     "linux-tools-6.8.0-31-lowlatency-64k",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure"
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
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-6.8",
     "linux-azure-6.8",
     "linux-gcp-6.8",
     "linux-hwe-6.8",
     "linux-lowlatency-hwe-6.8",
     "linux-nvidia-6.8",
     "linux-oracle-6.8",
     "linux-riscv-6.8"
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
        "os_version": "22.04"
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
