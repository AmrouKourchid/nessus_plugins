#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225531);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48702");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48702");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ALSA: emu10k1: Fix out of bounds
    access in snd_emu10k1_pcm_channel_alloc() The voice allocator sometimes begins allocating from near the
    end of the array and then wraps around, however snd_emu10k1_pcm_channel_alloc() accesses the newly
    allocated voices as if it never wrapped around. This results in out of bounds access if the first voice
    has a high enough index so that first_voice + requested_voice_count > NUM_G (64). The more voices are
    requested, the more likely it is for this to occur. This was initially discovered using PipeWire, however
    it can be reproduced by calling aplay multiple times with 16 channels: aplay -r 48000 -D
    plughw:CARD=Live,DEV=3 -c 16 /dev/zero UBSAN: array-index-out-of-bounds in
    sound/pci/emu10k1/emupcm.c:127:40 index 65 is out of range for type 'snd_emu10k1_voice [64]' CPU: 1 PID:
    31977 Comm: aplay Tainted: G W IOE 6.0.0-rc2-emu10k1+ #7 Hardware name: ASUSTEK COMPUTER INC P5W DH
    Deluxe/P5W DH Deluxe, BIOS 3002 07/22/2010 Call Trace: <TASK> dump_stack_lvl+0x49/0x63
    dump_stack+0x10/0x16 ubsan_epilogue+0x9/0x3f __ubsan_handle_out_of_bounds.cold+0x44/0x49
    snd_emu10k1_playback_hw_params+0x3bc/0x420 [snd_emu10k1] snd_pcm_hw_params+0x29f/0x600 [snd_pcm]
    snd_pcm_common_ioctl+0x188/0x1410 [snd_pcm] ? exit_to_user_mode_prepare+0x35/0x170 ?
    do_syscall_64+0x69/0x90 ? syscall_exit_to_user_mode+0x26/0x50 ? do_syscall_64+0x69/0x90 ?
    exit_to_user_mode_prepare+0x35/0x170 snd_pcm_ioctl+0x27/0x40 [snd_pcm] __x64_sys_ioctl+0x95/0xd0
    do_syscall_64+0x5c/0x90 ? do_syscall_64+0x69/0x90 ? do_syscall_64+0x69/0x90
    entry_SYSCALL_64_after_hwframe+0x63/0xcd (CVE-2022-48702)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48702");

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
