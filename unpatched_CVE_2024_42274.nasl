#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229200);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42274");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42274");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Revert ALSA: firewire-lib: operate
    for period elapse event in process context Commit 7ba5ca32fe6e (ALSA: firewire-lib: operate for period
    elapse event in process context) removed the process context workqueue from
    amdtp_domain_stream_pcm_pointer() and update_pcm_pointers() to remove its overhead. With RME Fireface 800,
    this lead to a regression since Kernels 5.14.0, causing an AB/BA deadlock competition for the substream
    lock with eventual system freeze under ALSA operation: thread 0: * (lock A) acquire substream lock by
    snd_pcm_stream_lock_irq() in snd_pcm_status64() * (lock B) wait for tasklet to finish by calling
    tasklet_unlock_spin_wait() in tasklet_disable_in_atomic() in ohci_flush_iso_completions() of ohci.c thread
    1: * (lock B) enter tasklet * (lock A) attempt to acquire substream lock, waiting for it to be released:
    snd_pcm_stream_lock_irqsave() in snd_pcm_period_elapsed() in update_pcm_pointers() in
    process_ctx_payloads() in process_rx_packets() of amdtp-stream.c ? tasklet_unlock_spin_wait </NMI> <TASK>
    ohci_flush_iso_completions firewire_ohci amdtp_domain_stream_pcm_pointer snd_firewire_lib
    snd_pcm_update_hw_ptr0 snd_pcm snd_pcm_status64 snd_pcm ? native_queued_spin_lock_slowpath </NMI> <IRQ>
    _raw_spin_lock_irqsave snd_pcm_period_elapsed snd_pcm process_rx_packets snd_firewire_lib
    irq_target_callback snd_firewire_lib handle_it_packet firewire_ohci context_tasklet firewire_ohci Restore
    the process context work queue to prevent deadlock AB/BA deadlock competition for ALSA substream lock of
    snd_pcm_stream_lock_irq() in snd_pcm_status64() and snd_pcm_stream_lock_irqsave() in
    snd_pcm_period_elapsed(). revert commit 7ba5ca32fe6e (ALSA: firewire-lib: operate for period elapse event
    in process context) Replace inline description to prevent future deadlock. (CVE-2024-42274)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42274");

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
