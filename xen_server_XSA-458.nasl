#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Inc.
##

include('compat.inc');

if (description)
{
  script_id(202621);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2024-31143");
  script_xref(name:"IAVB", value:"2024-B-0095-S");

  script_name(english:"Xen: double unlock in x86 guest IRQ handling (XSA-458)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An optional feature of PCI MSI called 'Multiple Message' allows a device to use multiple consecutive interrupt 
vectors. Unlike for MSI-X, the setting up of these consecutive vectors needs to happen all in one go. In this handling 
an error path could be taken in different situations, with or without a particular lock held. This error path wrongly 
releases the lock even when it is not currently held.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2024/q3/73");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-31143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixes['4.17']['fixed_ver']           = '4.17.5';
fixes['4.17']['fixed_ver_display']   = '4.17.5-pre (changeset 8f65398)';
fixes['4.17']['affected_ver_regex']  = "^4\.17([^0-9]|$)";
fixes['4.17']['affected_changesets'] = make_list('43d5f8f', 'b61a4ba',
  'a626bfb', '7504750', 'f121420', '4baf3a3', '5021656', 'fb9f984', 
  '8e522bf', '5afa8fe', 'fd4a15b', 'cf0342d', 'ac48584', '0433bae', 
  '16bc1d8', '8cea82a', '79f8310', '87a49d2', '02f94ea', '80fe1fe', 
  '9dfe294', '7d3fee8', 'a1c62c2', 'ee1e76e', 'dbcc4fb', '6f39608', 
  'a86a0df', 'eeefc57', '2165a8d', 'f15af3e', '9fa0df9', '373e022', 
  'cd8aab4', '3c7c922', 'afcce3c', 'cd3f405', 'e31e8ed', 'a14a7b9', 
  '620387c', '3020a20', 'df09596', 'c5c4646', '5305b3b', 'fdeacd4', 
  '910e9a7', '9cef774', 'ef9f147', '8d1c36d', 'ae19cd7', '2044364', 'f772bab');

fixes['4.18']['fixed_ver']           = '4.18.3';
fixes['4.18']['fixed_ver_display']   = '4.18.3-pre (changeset d46a1ce)';
fixes['4.18']['affected_ver_regex']  = "^4\.18([^0-9]|$)";
fixes['4.18']['affected_changesets'] = make_list('45c5333', '7e636b8',
  '30c695d', '26b8ff1', 'd689bb4', 'd1b3bbb', '8e51c8f', 'c9f50d2', 
  '2b3bf02', '0dc5fbe', '7967bd3', '77cf215', '1743102', '75b4f94', 
  '22f6236', '0ebfa35', '5ac3cbb', 'e95d30f', '9b43092', '4ee1df8', 
  '5397ab9', '3a8f4ec', '39a6170', 'c4b2849', '3b777c2', 'd31385b', 
  '6e647ef', 'ce0a0cb', '98238d4', '80f2d2c', '52e16bf', '1ffb29d', 
  'cd873f0', '01f7a3c');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
