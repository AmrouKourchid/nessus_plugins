#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229375);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36930");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36930");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: spi: fix null pointer dereference
    within spi_sync If spi_sync() is called with the non-empty queue and the same spi_message is then reused,
    the complete callback for the message remains set while the context is cleared, leading to a null pointer
    dereference when the callback is invoked from spi_finalize_current_message(). With function inlining
    disabled, the call stack might look like this: _raw_spin_lock_irqsave from complete_with_flags+0x18/0x58
    complete_with_flags from spi_complete+0x8/0xc spi_complete from spi_finalize_current_message+0xec/0x184
    spi_finalize_current_message from spi_transfer_one_message+0x2a8/0x474 spi_transfer_one_message from
    __spi_pump_transfer_message+0x104/0x230 __spi_pump_transfer_message from
    __spi_transfer_message_noqueue+0x30/0xc4 __spi_transfer_message_noqueue from __spi_sync+0x204/0x248
    __spi_sync from spi_sync+0x24/0x3c spi_sync from mcp251xfd_regmap_crc_read+0x124/0x28c [mcp251xfd]
    mcp251xfd_regmap_crc_read [mcp251xfd] from _regmap_raw_read+0xf8/0x154 _regmap_raw_read from
    _regmap_bus_read+0x44/0x70 _regmap_bus_read from _regmap_read+0x60/0xd8 _regmap_read from
    regmap_read+0x3c/0x5c regmap_read from mcp251xfd_alloc_can_err_skb+0x1c/0x54 [mcp251xfd]
    mcp251xfd_alloc_can_err_skb [mcp251xfd] from mcp251xfd_irq+0x194/0xe70 [mcp251xfd] mcp251xfd_irq
    [mcp251xfd] from irq_thread_fn+0x1c/0x78 irq_thread_fn from irq_thread+0x118/0x1f4 irq_thread from
    kthread+0xd8/0xf4 kthread from ret_from_fork+0x14/0x28 Fix this by also setting message->complete to NULL
    when the transfer is complete. (CVE-2024-36930)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
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
