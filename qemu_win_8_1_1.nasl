#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182514);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2023-3180", "CVE-2023-3354");
  script_xref(name:"IAVB", value:"2023-B-0073-S");

  script_name(english:"QEMU < 8.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of QEMU installed on the remote Windows host is prior to 8.1.1 and therefore vulnerable to the following:

  - A flaw was found in the QEMU virtual crypto device while handling data encryption/decryption requests in 
    virtio_crypto_handle_sym_req. There is no check for the value of `src_len` and `dst_len` in 
    virtio_crypto_sym_op_helper, potentially leading to a heap buffer overflow when the two values differ.
    (CVE-2023-3180)

  - A flaw was found in the QEMU built-in VNC server. When a client connects to the VNC server, QEMU checks whether 
    the current number of connections crosses a certain threshold and if so, cleans up the previous connection. If the 
    previous connection happens to be in the handshake phase and fails, QEMU cleans up the connection again, resulting 
    in a NULL pointer dereference issue. This could allow a remote unauthenticated client to cause a denial of service.
    (CVE-2023-3354)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qemu.org/download/#source");
  # https://github.com/qemu/qemu/commit/9d38a8434721a6479fe03fb5afb150ca793d3980
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6980e9af");
  # https://github.com/qemu/qemu/commit/10be627d2b5ec2d6b3dce045144aa739eef678b4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a401f107");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 8.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3354");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU");

  exit(0);
}

include('vcf.inc');

var app = 'QEMU';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [{'fixed_version': '8.1.1' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);