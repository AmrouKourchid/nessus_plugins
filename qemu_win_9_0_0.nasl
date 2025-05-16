#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200136);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id(
    "CVE-2023-6693",
    "CVE-2024-24474",
    "CVE-2024-3446",
    "CVE-2024-3447",
    "CVE-2024-3567",
    "CVE-2024-4693"
  );
  script_xref(name:"IAVB", value:"2024-B-0070-S");

  script_name(english:"QEMU < 9.0.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of QEMU installed on the remote Windows host is prior to 9.0.0 and therefore vulnerable to the following:

  - A double free vulnerability was found in QEMU virtio devices (virtio-gpu, virtio-serial-bus, virtio-crypto), where 
    the mem_reentrancy_guard flag insufficiently protects against DMA reentrancy issues. This issue could allow a 
    malicious privileged guest user to crash the QEMU process on the host, resulting in a denial of service or allow 
    arbitrary code execution within the context of the QEMU process on the host. (CVE-2024-3446)

  - A stack based buffer overflow was found in the virtio-net device of QEMU. This issue occurs when flushing TX in 
    the virtio_net_flush_tx function if guest features VIRTIO_NET_F_HASH_REPORT, VIRTIO_F_VERSION_1 and 
    VIRTIO_NET_F_MRG_RXBUF are enabled. This could allow a malicious user to overwrite local variables allocated on the 
    stack. Specifically, the `out_sg` variable could be used to read a part of process memory and send it to the wire, 
    causing an information leak. (CVE-2023-6693)

  - A flaw was found in QEMU. An assertion failure was present in the update_sctp_checksum() function in 
    hw/net/net_tx_pkt.c when trying to calculate the checksum of a short-sized fragmented packet. This flaw allows a 
    malicious guest to crash QEMU and cause a denial of service condition. (CVE-2024-3567)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qemu.org/download/#source");
  # https://github.com/qemu/qemu/commit/2220e8189fb94068dbad333228659fbac819abb0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19c0c850");
  # https://github.com/qemu/qemu/commit/f4729ec39ad97a42ceaa7b5697f84f440ea6e5dc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3354048");
  # https://github.com/qemu/qemu/commit/9e4b27ca6bf4974f169bbca7f3dca117b1208b6f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65ca6cdc");
  # https://github.com/qemu/qemu/commit/83ddb3dbba2ee0f1767442ae6ee665058aeb1093
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d10b4244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 9.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3446");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-6693");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU");

  exit(0);
}

include('vcf.inc');

var app = 'QEMU';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'fixed_version': '9.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
