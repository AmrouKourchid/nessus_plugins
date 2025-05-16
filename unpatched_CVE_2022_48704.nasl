#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225633);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48704");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48704");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/radeon: add a force flush to delay
    work when radeon Although radeon card fence and wait for gpu to finish processing current batch rings,
    there is still a corner case that radeon lockup work queue may not be fully flushed, and meanwhile the
    radeon_suspend_kms() function has called pci_set_power_state() to put device in D3hot state. Per PCI spec
    rev 4.0 on 5.3.1.4.1 D3hot State. > Configuration and Message requests are the only TLPs accepted by a
    Function in > the D3hot state. All other received Requests must be handled as Unsupported Requests, > and
    all received Completions may optionally be handled as Unexpected Completions. This issue will happen in
    following logs: Unable to handle kernel paging request at virtual address 00008800e0008010 CPU 0
    kworker/0:3(131): Oops 0 pc = [<ffffffff811bea5c>] ra = [<ffffffff81240844>] ps = 0000 Tainted: G W pc is
    at si_gpu_check_soft_reset+0x3c/0x240 ra is at si_dma_is_lockup+0x34/0xd0 v0 = 0000000000000000 t0 =
    fff08800e0008010 t1 = 0000000000010000 t2 = 0000000000008010 t3 = fff00007e3c00000 t4 = fff00007e3c00258
    t5 = 000000000000ffff t6 = 0000000000000001 t7 = fff00007ef078000 s0 = fff00007e3c016e8 s1 =
    fff00007e3c00000 s2 = fff00007e3c00018 s3 = fff00007e3c00000 s4 = fff00007fff59d80 s5 = 0000000000000000
    s6 = fff00007ef07bd98 a0 = fff00007e3c00000 a1 = fff00007e3c016e8 a2 = 0000000000000008 a3 =
    0000000000000001 a4 = 8f5c28f5c28f5c29 a5 = ffffffff810f4338 t8 = 0000000000000275 t9 = ffffffff809b66f8
    t10 = ff6769c5d964b800 t11= 000000000000b886 pv = ffffffff811bea20 at = 0000000000000000 gp =
    ffffffff81d89690 sp = 00000000aa814126 Disabling lock debugging due to kernel taint Trace:
    [<ffffffff81240844>] si_dma_is_lockup+0x34/0xd0 [<ffffffff81119610>] radeon_fence_check_lockup+0xd0/0x290
    [<ffffffff80977010>] process_one_work+0x280/0x550 [<ffffffff80977350>] worker_thread+0x70/0x7c0
    [<ffffffff80977410>] worker_thread+0x130/0x7c0 [<ffffffff80982040>] kthread+0x200/0x210
    [<ffffffff809772e0>] worker_thread+0x0/0x7c0 [<ffffffff80981f8c>] kthread+0x14c/0x210 [<ffffffff80911658>]
    ret_from_kernel_thread+0x18/0x20 [<ffffffff80981e40>] kthread+0x0/0x210 Code: ad3e0008 43f0074a ad7e0018
    ad9e0020 8c3001e8 40230101 <88210000> 4821ed21 So force lockup work queue flush to fix this problem.
    (CVE-2022-48704)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
    "name": "linux-gcp-5.15",
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
