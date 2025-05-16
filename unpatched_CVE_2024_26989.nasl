#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227628);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26989");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26989");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: arm64: hibernate: Fix level3
    translation fault in swsusp_save() On arm64 machines, swsusp_save() faults if it attempts to access
    MEMBLOCK_NOMAP memory ranges. This can be reproduced in QEMU using UEFI when booting with rodata=off
    debug_pagealloc=off and CONFIG_KFENCE=n: Unable to handle kernel paging request at virtual address
    ffffff8000000000 Mem abort info: ESR = 0x0000000096000007 EC = 0x25: DABT (current EL), IL = 32 bits SET =
    0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x07: level 3 translation fault Data abort info: ISV = 0, ISS =
    0x00000007, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess = 0 GCS = 0, Overlay = 0, DirtyBit = 0,
    Xs = 0 swapper pgtable: 4k pages, 39-bit VAs, pgdp=00000000eeb0b000 [ffffff8000000000]
    pgd=180000217fff9803, p4d=180000217fff9803, pud=180000217fff9803, pmd=180000217fff8803,
    pte=0000000000000000 Internal error: Oops: 0000000096000007 [#1] SMP Internal error: Oops:
    0000000096000007 [#1] SMP Modules linked in: xt_multiport ipt_REJECT nf_reject_ipv4 xt_conntrack
    nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 libcrc32c iptable_filter bpfilter rfkill at803x
    snd_hda_codec_hdmi snd_hda_intel snd_intel_dspcfg dwmac_generic stmmac_platform snd_hda_codec stmmac
    joydev pcs_xpcs snd_hda_core phylink ppdev lp parport ramoops reed_solomon ip_tables x_tables
    nls_iso8859_1 vfat multipath linear amdgpu amdxcp drm_exec gpu_sched drm_buddy hid_generic usbhid hid
    radeon video drm_suballoc_helper drm_ttm_helper ttm i2c_algo_bit drm_display_helper cec drm_kms_helper drm
    CPU: 0 PID: 3663 Comm: systemd-sleep Not tainted 6.6.2+ #76 Source Version:
    4e22ed63a0a48e7a7cff9b98b7806d8d4add7dc0 Hardware name: Greatwall GW-XXXXXX-XXX/GW-XXXXXX-XXX, BIOS KunLun
    BIOS V4.0 01/19/2021 pstate: 600003c5 (nZCv DAIF -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc :
    swsusp_save+0x280/0x538 lr : swsusp_save+0x280/0x538 sp : ffffffa034a3fa40 x29: ffffffa034a3fa40 x28:
    ffffff8000001000 x27: 0000000000000000 x26: ffffff8001400000 x25: ffffffc08113e248 x24: 0000000000000000
    x23: 0000000000080000 x22: ffffffc08113e280 x21: 00000000000c69f2 x20: ffffff8000000000 x19:
    ffffffc081ae2500 x18: 0000000000000000 x17: 6666662074736420 x16: 3030303030303030 x15: 3038666666666666
    x14: 0000000000000b69 x13: ffffff9f89088530 x12: 00000000ffffffea x11: 00000000ffff7fff x10:
    00000000ffff7fff x9 : ffffffc08193f0d0 x8 : 00000000000bffe8 x7 : c0000000ffff7fff x6 : 0000000000000001
    x5 : ffffffa0fff09dc8 x4 : 0000000000000000 x3 : 0000000000000027 x2 : 0000000000000000 x1 :
    0000000000000000 x0 : 000000000000004e Call trace: swsusp_save+0x280/0x538 swsusp_arch_suspend+0x148/0x190
    hibernation_snapshot+0x240/0x39c hibernate+0xc4/0x378 state_store+0xf0/0x10c kobj_attr_store+0x14/0x24 The
    reason is swsusp_save() -> copy_data_pages() -> page_is_saveable() -> kernel_page_present() assuming that
    a page is always present when can_set_direct_map() is false (all of rodata_full, debug_pagealloc_enabled()
    and arm64_kfence_can_set_direct_map() false), irrespective of the MEMBLOCK_NOMAP ranges. Such
    MEMBLOCK_NOMAP regions should not be saved during hibernation. This problem was introduced by changes to
    the pfn_valid() logic in commit a7d9f306ba70 (arm64: drop pfn_valid_within() and simplify pfn_valid()).
    Similar to other architectures, drop the !can_set_direct_map() check in kernel_page_present() so that
    page_is_savable() skips such pages. [catalin.marinas@arm.com: rework commit message] (CVE-2024-26989)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
