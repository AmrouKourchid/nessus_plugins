#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228895);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41065");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41065");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: powerpc/pseries: Whitelist dtl slub
    object for copying to userspace Reading the dispatch trace log from /sys/kernel/debug/powerpc/dtl/cpu-*
    results in a BUG() when the config CONFIG_HARDENED_USERCOPY is enabled as shown below. kernel BUG at
    mm/usercopy.c:102! Oops: Exception in kernel mode, sig: 5 [#1] LE PAGE_SIZE=64K MMU=Radix SMP NR_CPUS=2048
    NUMA pSeries Modules linked in: xfs libcrc32c dm_service_time sd_mod t10_pi sg ibmvfc scsi_transport_fc
    ibmveth pseries_wdt dm_multipath dm_mirror dm_region_hash dm_log dm_mod fuse CPU: 27 PID: 1815 Comm:
    python3 Not tainted 6.10.0-rc3 #85 Hardware name: IBM,9040-MRX POWER10 (raw) 0x800200 0xf000006
    of:IBM,FW1060.00 (NM1060_042) hv:phyp pSeries NIP: c0000000005d23d4 LR: c0000000005d23d0 CTR:
    00000000006ee6f8 REGS: c000000120c078c0 TRAP: 0700 Not tainted (6.10.0-rc3) MSR: 8000000000029033
    <SF,EE,ME,IR,DR,RI,LE> CR: 2828220f XER: 0000000e CFAR: c0000000001fdc80 IRQMASK: 0 [ ... GPRs omitted ...
    ] NIP [c0000000005d23d4] usercopy_abort+0x78/0xb0 LR [c0000000005d23d0] usercopy_abort+0x74/0xb0 Call
    Trace: usercopy_abort+0x74/0xb0 (unreliable) __check_heap_object+0xf8/0x120 check_heap_object+0x218/0x240
    __check_object_size+0x84/0x1a4 dtl_file_read+0x17c/0x2c4 full_proxy_read+0x8c/0x110 vfs_read+0xdc/0x3a0
    ksys_read+0x84/0x144 system_call_exception+0x124/0x330 system_call_vectored_common+0x15c/0x2ec ---
    interrupt: 3000 at 0x7fff81f3ab34 Commit 6d07d1cd300f (usercopy: Restrict non-usercopy caches to size 0)
    requires that only whitelisted areas in slab/slub objects can be copied to userspace when usercopy
    hardening is enabled using CONFIG_HARDENED_USERCOPY. Dtl contains hypervisor dispatch events which are
    expected to be read by privileged users. Hence mark this safe for user access. Specify useroffset=0 and
    usersize=DISPATCH_LOG_BYTES to whitelist the entire object. (CVE-2024-41065)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41065");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
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
    "name": "linux-azure-fde",
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
    "name": "linux-azure-fde-5.15",
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
