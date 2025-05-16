#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230177);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46913");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46913");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: nftables: clone set element
    expression template memcpy() breaks when using connlimit in set elements. Use nft_expr_clone() to
    initialize the connlimit expression list, otherwise connlimit garbage collector crashes when walking on
    the list head copy. [ 493.064656] Workqueue: events_power_efficient nft_rhash_gc [nf_tables] [ 493.064685]
    RIP: 0010:find_or_evict+0x5a/0x90 [nf_conncount] [ 493.064694] Code: 2b 43 40 83 f8 01 77 0d 48 c7 c0 f5
    ff ff ff 44 39 63 3c 75 df 83 6d 18 01 48 8b 43 08 48 89 de 48 8b 13 48 8b 3d ee 2f 00 00 <48> 89 42 08 48
    89 10 48 b8 00 01 00 00 00 00 ad de 48 89 03 48 83 [ 493.064699] RSP: 0018:ffffc90000417dc0 EFLAGS:
    00010297 [ 493.064704] RAX: 0000000000000000 RBX: ffff888134f38410 RCX: 0000000000000000 [ 493.064708]
    RDX: 0000000000000000 RSI: ffff888134f38410 RDI: ffff888100060cc0 [ 493.064711] RBP: ffff88812ce594a8 R08:
    ffff888134f38438 R09: 00000000ebb9025c [ 493.064714] R10: ffffffff8219f838 R11: 0000000000000017 R12:
    0000000000000001 [ 493.064718] R13: ffffffff82146740 R14: ffff888134f38410 R15: 0000000000000000 [
    493.064721] FS: 0000000000000000(0000) GS:ffff88840e440000(0000) knlGS:0000000000000000 [ 493.064725] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 493.064729] CR2: 0000000000000008 CR3: 00000001330aa002
    CR4: 00000000001706e0 [ 493.064733] Call Trace: [ 493.064737] nf_conncount_gc_list+0x8f/0x150
    [nf_conncount] [ 493.064746] nft_rhash_gc+0x106/0x390 [nf_tables] (CVE-2021-46913)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-bluefield",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
