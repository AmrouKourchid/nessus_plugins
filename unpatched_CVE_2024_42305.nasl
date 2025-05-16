#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229584);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42305");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42305");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ext4: check dot and dotdot of dx_root
    before making dir indexed Syzbot reports a issue as follows: ============================================
    BUG: unable to handle page fault for address: ffffed11022e24fe PGD 23ffee067 P4D 23ffee067 PUD 0 Oops:
    Oops: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 0 PID: 5079 Comm: syz-executor306 Not tainted
    6.10.0-rc5-g55027e689933 #0 Call Trace: <TASK> make_indexed_dir+0xdaf/0x13c0 fs/ext4/namei.c:2341
    ext4_add_entry+0x222a/0x25d0 fs/ext4/namei.c:2451 ext4_rename fs/ext4/namei.c:3936 [inline]
    ext4_rename2+0x26e5/0x4370 fs/ext4/namei.c:4214 [...] ============================================ The
    immediate cause of this problem is that there is only one valid dentry for the block to be split during
    do_split, so split==0 results in out of bounds accesses to the map triggering the issue. do_split unsigned
    split dx_make_map count = 1 split = count/2 = 0; continued = hash2 == map[split - 1].hash; --->
    map[4294967295] The maximum length of a filename is 255 and the minimum block size is 1024, so it is
    always guaranteed that the number of entries is greater than or equal to 2 when do_split() is called. But
    syzbot's crafted image has no dot and dotdot in dir, and the dentry distribution in dirblock is as
    follows: bus dentry1 hole dentry2 free
    |xx--|xx-------------|...............|xx-------------|...............| 0 12 (8+248)=256 268 256 524
    (8+256)=264 788 236 1024 So when renaming dentry1 increases its name_len length by 1, neither hole nor
    free is sufficient to hold the new dentry, and make_indexed_dir() is called. In make_indexed_dir() it is
    assumed that the first two entries of the dirblock must be dot and dotdot, so bus and dentry1 are left in
    dx_root because they are treated as dot and dotdot, and only dentry2 is moved to the new leaf block.
    That's why count is equal to 1. Therefore add the ext4_check_dx_root() helper function to add more sanity
    checks to dot and dotdot before starting the conversion to avoid the above issue. (CVE-2024-42305)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
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
