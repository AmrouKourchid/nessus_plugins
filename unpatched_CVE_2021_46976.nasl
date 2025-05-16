#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230118);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46976");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46976");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/i915: Fix crash in auto_retire The
    retire logic uses the 2 lower bits of the pointer to the retire function to store flags. However, the
    auto_retire function is not guaranteed to be aligned to a multiple of 4, which causes crashes as we jump
    to the wrong address, for example like this: 2021-04-24T18:03:53.804300Z WARNING kernel: [ 516.876901]
    invalid opcode: 0000 [#1] PREEMPT SMP NOPTI 2021-04-24T18:03:53.804310Z WARNING kernel: [ 516.876906] CPU:
    7 PID: 146 Comm: kworker/u16:6 Tainted: G U 5.4.105-13595-g3cd84167b2df #1 2021-04-24T18:03:53.804311Z
    WARNING kernel: [ 516.876907] Hardware name: Google Volteer2/Volteer2, BIOS Google_Volteer2.13672.76.0
    02/22/2021 2021-04-24T18:03:53.804312Z WARNING kernel: [ 516.876911] Workqueue: events_unbound active_work
    2021-04-24T18:03:53.804313Z WARNING kernel: [ 516.876914] RIP: 0010:auto_retire+0x1/0x20
    2021-04-24T18:03:53.804314Z WARNING kernel: [ 516.876916] Code: e8 01 f2 ff ff eb 02 31 db 48 89 d8 5b 5d
    c3 0f 1f 44 00 00 55 48 89 e5 f0 ff 87 c8 00 00 00 0f 88 ab 47 4a 00 31 c0 5d c3 0f <1f> 44 00 00 55 48 89
    e5 f0 ff 8f c8 00 00 00 0f 88 9a 47 4a 00 74 2021-04-24T18:03:53.804319Z WARNING kernel: [ 516.876918]
    RSP: 0018:ffff9b4d809fbe38 EFLAGS: 00010286 2021-04-24T18:03:53.804320Z WARNING kernel: [ 516.876919] RAX:
    0000000000000007 RBX: ffff927915079600 RCX: 0000000000000007 2021-04-24T18:03:53.804320Z WARNING kernel: [
    516.876921] RDX: ffff9b4d809fbe40 RSI: 0000000000000286 RDI: ffff927915079600 2021-04-24T18:03:53.804321Z
    WARNING kernel: [ 516.876922] RBP: ffff9b4d809fbe68 R08: 8080808080808080 R09: fefefefefefefeff
    2021-04-24T18:03:53.804321Z WARNING kernel: [ 516.876924] R10: 0000000000000010 R11: ffffffff92e44bd8 R12:
    ffff9279150796a0 2021-04-24T18:03:53.804322Z WARNING kernel: [ 516.876925] R13: ffff92791c368180 R14:
    ffff927915079640 R15: 000000001c867605 2021-04-24T18:03:53.804323Z WARNING kernel: [ 516.876926] FS:
    0000000000000000(0000) GS:ffff92791ffc0000(0000) knlGS:0000000000000000 2021-04-24T18:03:53.804323Z
    WARNING kernel: [ 516.876928] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 2021-04-24T18:03:53.804324Z
    WARNING kernel: [ 516.876929] CR2: 0000239514955000 CR3: 00000007f82da001 CR4: 0000000000760ee0
    2021-04-24T18:03:53.804325Z WARNING kernel: [ 516.876930] PKRU: 55555554 2021-04-24T18:03:53.804325Z
    WARNING kernel: [ 516.876931] Call Trace: 2021-04-24T18:03:53.804326Z WARNING kernel: [ 516.876935]
    __active_retire+0x77/0xcf 2021-04-24T18:03:53.804326Z WARNING kernel: [ 516.876939]
    process_one_work+0x1da/0x394 2021-04-24T18:03:53.804327Z WARNING kernel: [ 516.876941]
    worker_thread+0x216/0x375 2021-04-24T18:03:53.804327Z WARNING kernel: [ 516.876944] kthread+0x147/0x156
    2021-04-24T18:03:53.804335Z WARNING kernel: [ 516.876946] ? pr_cont_work+0x58/0x58
    2021-04-24T18:03:53.804335Z WARNING kernel: [ 516.876948] ? kthread_blkcg+0x2e/0x2e
    2021-04-24T18:03:53.804336Z WARNING kernel: [ 516.876950] ret_from_fork+0x1f/0x40
    2021-04-24T18:03:53.804336Z WARNING kernel: [ 516.876952] Modules linked in: cdc_mbim cdc_ncm cdc_wdm
    xt_cgroup rfcomm cmac algif_hash algif_skcipher af_alg xt_MASQUERADE uinput snd_soc_rt5682_sdw
    snd_soc_rt5682 snd_soc_max98373_sdw snd_soc_max98373 snd_soc_rl6231 regmap_sdw snd_soc_sof_sdw
    snd_soc_hdac_hdmi snd_soc_dmic snd_hda_codec_hdmi snd_sof_pci snd_sof_intel_hda_common intel_ipu6_psys
    snd_sof_xtensa_dsp soundwire_intel soundwire_generic_allocation soundwire_cadence snd_sof_intel_hda
    snd_sof snd_soc_hdac_hda snd_soc_acpi_intel_match snd_soc_acpi snd_hda_ext_core soundwire_bus
    snd_hda_intel snd_intel_dspcfg snd_hda_codec snd_hwdep snd_hda_core intel_ipu6_isys videobuf2_dma_contig
    videobuf2_v4l2 videobuf2_common videobuf2_memops mei_hdcp intel_ipu6 ov2740 ov8856 at24 sx9310 dw9768
    v4l2_fwnode cros_ec_typec intel_pmc_mux roles acpi_als typec fuse iio_trig_sysfs cros_ec_light_prox
    cros_ec_lid_angle cros_ec_sensors cros ---truncated--- (CVE-2021-46976)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46976");

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
