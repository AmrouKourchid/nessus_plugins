#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225685);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48640");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48640");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bonding: fix NULL deref in
    bond_rr_gen_slave_id Fix a NULL dereference of the struct bonding.rr_tx_counter member because if a bond
    is initially created with an initial mode != zero (Round Robin) the memory required for the counter is
    never created and when the mode is changed there is never any attempt to verify the memory is allocated
    upon switching modes. This causes the following Oops on an aarch64 machine: [ 334.686773] Unable to handle
    kernel paging request at virtual address ffff2c91ac905000 [ 334.694703] Mem abort info: [ 334.697486] ESR
    = 0x0000000096000004 [ 334.701234] EC = 0x25: DABT (current EL), IL = 32 bits [ 334.706536] SET = 0, FnV =
    0 [ 334.709579] EA = 0, S1PTW = 0 [ 334.712719] FSC = 0x04: level 0 translation fault [ 334.717586] Data
    abort info: [ 334.720454] ISV = 0, ISS = 0x00000004 [ 334.724288] CM = 0, WnR = 0 [ 334.727244] swapper
    pgtable: 4k pages, 48-bit VAs, pgdp=000008044d662000 [ 334.733944] [ffff2c91ac905000]
    pgd=0000000000000000, p4d=0000000000000000 [ 334.740734] Internal error: Oops: 96000004 [#1] SMP [
    334.745602] Modules linked in: bonding tls veth rfkill sunrpc arm_spe_pmu vfat fat acpi_ipmi ipmi_ssif
    ixgbe igb i40e mdio ipmi_devintf ipmi_msghandler arm_cmn arm_dsu_pmu cppc_cpufreq acpi_tad fuse zram
    crct10dif_ce ast ghash_ce sbsa_gwdt nvme drm_vram_helper drm_ttm_helper nvme_core ttm xgene_hwmon [
    334.772217] CPU: 7 PID: 2214 Comm: ping Not tainted 6.0.0-rc4-00133-g64ae13ed4784 #4 [ 334.779950]
    Hardware name: GIGABYTE R272-P31-00/MP32-AR1-00, BIOS F18v (SCP: 1.08.20211002) 12/01/2021 [ 334.789244]
    pstate: 60400009 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) [ 334.796196] pc :
    bond_rr_gen_slave_id+0x40/0x124 [bonding] [ 334.801691] lr : bond_xmit_roundrobin_slave_get+0x38/0xdc
    [bonding] [ 334.807962] sp : ffff8000221733e0 [ 334.811265] x29: ffff8000221733e0 x28: ffffdbac8572d198
    x27: ffff80002217357c [ 334.818392] x26: 000000000000002a x25: ffffdbacb33ee000 x24: ffff07ff980fa000 [
    334.825519] x23: ffffdbacb2e398ba x22: ffff07ff98102000 x21: ffff07ff981029c0 [ 334.832646] x20:
    0000000000000001 x19: ffff07ff981029c0 x18: 0000000000000014 [ 334.839773] x17: 0000000000000000 x16:
    ffffdbacb1004364 x15: 0000aaaabe2f5a62 [ 334.846899] x14: ffff07ff8e55d968 x13: ffff07ff8e55db30 x12:
    0000000000000000 [ 334.854026] x11: ffffdbacb21532e8 x10: 0000000000000001 x9 : ffffdbac857178ec [
    334.861153] x8 : ffff07ff9f6e5a28 x7 : 0000000000000000 x6 : 000000007c2b3742 [ 334.868279] x5 :
    ffff2c91ac905000 x4 : ffff2c91ac905000 x3 : ffff07ff9f554400 [ 334.875406] x2 : ffff2c91ac905000 x1 :
    0000000000000001 x0 : ffff07ff981029c0 [ 334.882532] Call trace: [ 334.884967]
    bond_rr_gen_slave_id+0x40/0x124 [bonding] [ 334.890109] bond_xmit_roundrobin_slave_get+0x38/0xdc [bonding]
    [ 334.896033] __bond_start_xmit+0x128/0x3a0 [bonding] [ 334.901001] bond_start_xmit+0x54/0xb0 [bonding] [
    334.905622] dev_hard_start_xmit+0xb4/0x220 [ 334.909798] __dev_queue_xmit+0x1a0/0x720 [ 334.913799]
    arp_xmit+0x3c/0xbc [ 334.916932] arp_send_dst+0x98/0xd0 [ 334.920410] arp_solicit+0xe8/0x230 [ 334.923888]
    neigh_probe+0x60/0xb0 [ 334.927279] __neigh_event_send+0x3b0/0x470 [ 334.931453]
    neigh_resolve_output+0x70/0x90 [ 334.935626] ip_finish_output2+0x158/0x514 [ 334.939714]
    __ip_finish_output+0xac/0x1a4 [ 334.943800] ip_finish_output+0x40/0xfc [ 334.947626] ip_output+0xf8/0x1a4
    [ 334.950931] ip_send_skb+0x5c/0x100 [ 334.954410] ip_push_pending_frames+0x3c/0x60 [ 334.958758]
    raw_sendmsg+0x458/0x6d0 [ 334.962325] inet_sendmsg+0x50/0x80 [ 334.965805] sock_sendmsg+0x60/0x6c [
    334.969286] __sys_sendto+0xc8/0x134 [ 334.972853] __arm64_sys_sendto+0x34/0x4c ---truncated---
    (CVE-2022-48640)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
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
