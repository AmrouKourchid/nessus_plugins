#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229852);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47302");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47302");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: igc: Fix use-after-free error during
    reset Cleans the next descriptor to watch (next_to_watch) when cleaning the TX ring. Failure to do so can
    cause invalid memory accesses. If igc_poll() runs while the controller is being reset this can lead to the
    driver try to free a skb that was already freed. Log message: [ 101.525242] refcount_t: underflow; use-
    after-free. [ 101.525251] WARNING: CPU: 1 PID: 646 at lib/refcount.c:28 refcount_warn_saturate+0xab/0xf0 [
    101.525259] Modules linked in: sch_etf(E) sch_mqprio(E) rfkill(E) intel_rapl_msr(E) intel_rapl_common(E)
    x86_pkg_temp_thermal(E) intel_powerclamp(E) coretemp(E) binfmt_misc(E) kvm_intel(E) kvm(E) irqbypass(E)
    crc32_pclmul(E) ghash_clmulni_intel(E) aesni_intel(E) mei_wdt(E) libaes(E) crypto_simd(E) cryptd(E)
    glue_helper(E) snd_hda_codec_hdmi(E) rapl(E) intel_cstate(E) snd_hda_intel(E) snd_intel_dspcfg(E) sg(E)
    soundwire_intel(E) intel_uncore(E) at24(E) soundwire_generic_allocation(E) iTCO_wdt(E)
    soundwire_cadence(E) intel_pmc_bxt(E) serio_raw(E) snd_hda_codec(E) iTCO_vendor_support(E) watchdog(E)
    snd_hda_core(E) snd_hwdep(E) snd_soc_core(E) snd_compress(E) snd_pcsp(E) soundwire_bus(E) snd_pcm(E)
    evdev(E) snd_timer(E) mei_me(E) snd(E) soundcore(E) mei(E) configfs(E) ip_tables(E) x_tables(E) autofs4(E)
    ext4(E) crc32c_generic(E) crc16(E) mbcache(E) jbd2(E) sd_mod(E) t10_pi(E) crc_t10dif(E)
    crct10dif_generic(E) i915(E) ahci(E) libahci(E) ehci_pci(E) igb(E) xhci_pci(E) ehci_hcd(E) [ 101.525303]
    drm_kms_helper(E) dca(E) xhci_hcd(E) libata(E) crct10dif_pclmul(E) cec(E) crct10dif_common(E) tsn(E)
    igc(E) e1000e(E) ptp(E) i2c_i801(E) crc32c_intel(E) psmouse(E) i2c_algo_bit(E) i2c_smbus(E) scsi_mod(E)
    lpc_ich(E) pps_core(E) usbcore(E) drm(E) button(E) video(E) [ 101.525318] CPU: 1 PID: 646 Comm:
    irq/37-enp7s0-T Tainted: G E 5.10.30-rt37-tsn1-rt-ipipe #ipipe [ 101.525320] Hardware name: SIEMENS AG
    SIMATIC IPC427D/A5E31233588, BIOS V17.02.09 03/31/2017 [ 101.525322] RIP:
    0010:refcount_warn_saturate+0xab/0xf0 [ 101.525325] Code: 05 31 48 44 01 01 e8 f0 c6 42 00 0f 0b c3 80 3d
    1f 48 44 01 00 75 90 48 c7 c7 78 a8 f3 a6 c6 05 0f 48 44 01 01 e8 d1 c6 42 00 <0f> 0b c3 80 3d fe 47 44 01
    00 0f 85 6d ff ff ff 48 c7 c7 d0 a8 f3 [ 101.525327] RSP: 0018:ffffbdedc0917cb8 EFLAGS: 00010286 [
    101.525329] RAX: 0000000000000000 RBX: ffff98fd6becbf40 RCX: 0000000000000001 [ 101.525330] RDX:
    0000000000000001 RSI: ffffffffa6f2700c RDI: 00000000ffffffff [ 101.525332] RBP: ffff98fd6becc14c R08:
    ffffffffa7463d00 R09: ffffbdedc0917c50 [ 101.525333] R10: ffffffffa74c3578 R11: 0000000000000034 R12:
    00000000ffffff00 [ 101.525335] R13: ffff98fd6b0b1000 R14: 0000000000000039 R15: ffff98fd6be35c40 [
    101.525337] FS: 0000000000000000(0000) GS:ffff98fd6e240000(0000) knlGS:0000000000000000 [ 101.525339] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 101.525341] CR2: 00007f34135a3a70 CR3: 0000000150210003
    CR4: 00000000001706e0 [ 101.525343] Call Trace: [ 101.525346] sock_wfree+0x9c/0xa0 [ 101.525353]
    unix_destruct_scm+0x7b/0xa0 [ 101.525358] skb_release_head_state+0x40/0x90 [ 101.525362]
    skb_release_all+0xe/0x30 [ 101.525364] napi_consume_skb+0x57/0x160 [ 101.525367] igc_poll+0xb7/0xc80 [igc]
    [ 101.525376] ? sched_clock+0x5/0x10 [ 101.525381] ? sched_clock_cpu+0xe/0x100 [ 101.525385]
    net_rx_action+0x14c/0x410 [ 101.525388] __do_softirq+0xe9/0x2f4 [ 101.525391]
    __local_bh_enable_ip+0xe3/0x110 [ 101.525395] ? irq_finalize_oneshot.part.47+0xe0/0xe0 [ 101.525398]
    irq_forced_thread_fn+0x6a/0x80 [ 101.525401] irq_thread+0xe8/0x180 [ 101.525403] ?
    wake_threads_waitq+0x30/0x30 [ 101.525406] ? irq_thread_check_affinity+0xd0/0xd0 [ 101.525408]
    kthread+0x183/0x1a0 [ 101.525412] ? kthread_park+0x80/0x80 [ 101.525415] ret_from_fork+0x22/0x30
    (CVE-2021-47302)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47302");

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
        "os_version": "8"
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
