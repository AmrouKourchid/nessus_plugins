#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(178183);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/11");

  script_cve_id("CVE-2023-33149", "CVE-2023-33158", "CVE-2023-33161");
  script_xref(name:"IAVA", value:"2023-A-0341-S");
  script_xref(name:"IAVA", value:"2023-A-0349-S");

  script_name(english:"Security Updates for Microsoft Office Products (July 2023) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple remote code
execution vulnerabilities.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ed1b90");
  # https://learn.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#july-11-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d60092e6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "installed_sw/Microsoft Excel");

  exit(0);
}

include('vcf_extras_office.inc');

var apps = make_list('Microsoft Outlook', 'Microsoft Excel', 'Microsoft Word',
                     'Microsoft PowerPoint','Microsoft OneNote');

var app_info = vcf::microsoft::office_for_mac::get_app_info(apps:apps);

var constraints = [
  {'min_version':'16.17.0', 'fixed_version':'16.75', 'fixed_display':'16.75 (23070901)'}
];

vcf::microsoft::office_for_mac::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  os_min_lvl:'11.0'
);
