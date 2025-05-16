#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Inc.
##

include('compat.inc');

if (description)
{
  script_id(182973);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/15");

  script_cve_id("CVE-2023-34327", "CVE-2023-34328");
  script_xref(name:"IAVB", value:"2023-B-0081-S");

  script_name(english:"Xen: x86/AMD: Debug Mask handling (XSA-444)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"AMD CPUs since ~2014 have extensions to normal x86 debugging functionality. Xen supports guests using these 
extensions.

Unfortunately there are errors in Xen's handling of the guest state, leading to denials of service.

  - CVE-2023-34327 - An HVM vCPU can end up operating in the context of
    a previous vCPUs debug mask state.

  - CVE-2023-34328 - A PV vCPU can place a breakpoint over the live GDT.
    This allows the PV vCPU to exploit XSA-156 / CVE-2015-8104 and lock
    up the CPU entirely.

For CVE-2023-34327, any guest (PV or HVM) using Debug Masks normally for it's own purposes can cause incorrect 
behaviour in an unrelated HVM vCPU, most likely resulting in a guest crash.

For CVE-2023-34328, a buggy or malicious PV guest kernel can lock up the host.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-444.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34328");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var fixes;
var app = 'Xen Hypervisor';
var app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes['4.15']['fixed_ver']           = '4.15.5';
fixes['4.15']['fixed_ver_display']   = '4.15.5 (changeset 4a4daf6)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('1f0d217', 'c844124',
  '75aa1c9', '9a502b6', '3ab7e4a', '609b76c', '844bcf0', 'ff2ba13', 
  '586aab2', '964840a', '8c1075d', '60aed4c', '1b8dbe4', '0a70ce9', 
  '3a9a290', 'd7b7804', 'b007f82', 'dac9060', 'd39e5cf', 'd75cb6d', 
  '93504b3', '67b9743', '806893a', '094cd5c', 'db3386e', '0517763', 'da7f151');

fixes['4.17']['fixed_ver']           = '4.17.3';
fixes['4.17']['fixed_ver_display']   = '4.17.3-pre (changeset 0b56bed)';
fixes['4.17']['affected_ver_regex']  = "^4\.17([^0-9]|$)";
fixes['4.17']['affected_changesets'] = make_list('3f8b444', '46d00db',
  '42bf49d', 'f5e2116', '8ee1924', '3797742', 'e7059f1', '8a58412', 
  'eb4efda', '78143c5', 'f1cd620', 'd665c66', '0d8f9f7', 'c4e05c9', 
  '90c540c', '9ac2f49', '19ee1e1', '2e2c3ef', 'e4a71bc', '5f7efd4', 
  'ba023e9', '3952c73', '84690fb', 'dc28aba', 'd2d2dca', 'd31e5b2', 
  '699de51', '8be85d8', 'a939e95', '7ca58fb', '0429822', 'ba360fb', 
  '5116fe1', 'e08e733', '1bd4523', 'a885649', 'd0cdd34', 'f04295d', 
  'e5f9987', '7b5155a', '052a8d2', 'f00d563', 'e418a77', '24487fe', 
  'ae1045c', '37f1d68', '476d262', 'a1f68fb', '36e84ea', '56076ef', 
  '1c3927f', '8d84be5', '7d88979', '2f337a0');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);