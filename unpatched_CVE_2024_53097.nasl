#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231107);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53097");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53097");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm: krealloc: Fix MTE false alarm in
    __do_krealloc This patch addresses an issue introduced by commit 1a83a716ec233 (mm: krealloc: consider
    spare memory for __GFP_ZERO) which causes MTE (Memory Tagging Extension) to falsely report a slab-out-of-
    bounds error. The problem occurs when zeroing out spare memory in __do_krealloc. The original code only
    considered software-based KASAN and did not account for MTE. It does not reset the KASAN tag before
    calling memset, leading to a mismatch between the pointer tag and the memory tag, resulting in a false
    positive. Example of the error: ==================================================================
    swapper/0: BUG: KASAN: slab-out-of-bounds in __memset+0x84/0x188 swapper/0: Write at addr f4ffff8005f0fdf0
    by task swapper/0/1 swapper/0: Pointer tag: [f4], memory tag: [fe] swapper/0: swapper/0: CPU: 4 UID: 0
    PID: 1 Comm: swapper/0 Not tainted 6.12. swapper/0: Hardware name: MT6991(ENG) (DT) swapper/0: Call trace:
    swapper/0: dump_backtrace+0xfc/0x17c swapper/0: show_stack+0x18/0x28 swapper/0: dump_stack_lvl+0x40/0xa0
    swapper/0: print_report+0x1b8/0x71c swapper/0: kasan_report+0xec/0x14c swapper/0:
    __do_kernel_fault+0x60/0x29c swapper/0: do_bad_area+0x30/0xdc swapper/0: do_tag_check_fault+0x20/0x34
    swapper/0: do_mem_abort+0x58/0x104 swapper/0: el1_abort+0x3c/0x5c swapper/0:
    el1h_64_sync_handler+0x80/0xcc swapper/0: el1h_64_sync+0x68/0x6c swapper/0: __memset+0x84/0x188 swapper/0:
    btf_populate_kfunc_set+0x280/0x3d8 swapper/0: __register_btf_kfunc_id_set+0x43c/0x468 swapper/0:
    register_btf_kfunc_id_set+0x48/0x60 swapper/0: register_nf_nat_bpf+0x1c/0x40 swapper/0:
    nf_nat_init+0xc0/0x128 swapper/0: do_one_initcall+0x184/0x464 swapper/0: do_initcall_level+0xdc/0x1b0
    swapper/0: do_initcalls+0x70/0xc0 swapper/0: do_basic_setup+0x1c/0x28 swapper/0:
    kernel_init_freeable+0x144/0x1b8 swapper/0: kernel_init+0x20/0x1a8 swapper/0: ret_from_fork+0x10/0x20
    ================================================================== (CVE-2024-53097)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/25");
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
     "linux-aws-5.15",
     "linux-ibm-5.15"
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
    "name": [
     "linux-aws-fips",
     "linux-azure-fips",
     "linux-buildinfo-5.15.0-1004-kvm",
     "linux-cloud-tools-5.15.0-1004-kvm",
     "linux-fips",
     "linux-gcp-fips",
     "linux-headers-5.15.0-1004-kvm",
     "linux-image-unsigned-5.15.0-1004-kvm",
     "linux-image-unsigned-5.15.0-1004-kvm-dbgsym",
     "linux-intel-iot-realtime",
     "linux-kvm-cloud-tools-5.15.0-1004",
     "linux-kvm-headers-5.15.0-1004",
     "linux-kvm-tools-5.15.0-1004",
     "linux-modules-5.15.0-1004-kvm",
     "linux-modules-extra-5.15.0-1004-kvm",
     "linux-realtime",
     "linux-tools-5.15.0-1004-kvm",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "kernel",
     "kernel-rt"
    ],
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
