#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179666);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2023-3301");
  script_xref(name:"IAVB", value:"2023-B-0058-S");

  script_name(english:"QEMU < 8.1.0-rc2 DOS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has virtualization software installed that is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of QEMU installed on the remote Windows host is affected by a race condition due to the async nature of 
hot-unplug. hot-unplug enables a race scenario where the net device backend is cleared before the virtio-net pci 
frontend has been unplugged. A malicious guest could use this time window to trigger an assertion and cause a denial 
of service.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qemu.org/download/#source");
  # https://github.com/qemu/qemu/commit/a0d7215e339b61c7d7a7b3fcf754954d80d93eb8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87674107");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QEMU 8.1.0-rc2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qemu:qemu");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qemu_installed_windows.nbin");
  script_require_keys("installed_sw/QEMU");

  exit(0);
}

include('vcf.inc');

var app = 'QEMU';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [{'max_version' : '8.1.0-rc3', 'fixed_display':'8.1.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);