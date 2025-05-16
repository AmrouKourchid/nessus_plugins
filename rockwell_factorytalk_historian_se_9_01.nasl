#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196950);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-31274", "CVE-2023-34348");
  script_xref(name:"ICSA", value:"24-130-01");

  script_name(english:"Rockwell FactoryTalk Historian < 9.01 DoS");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rockwell FactoryTalk Historian installed on the remote Windows host is prior to 9.01. It is, therefore, affected by a
vulnerability.

  - FactoryTalk Historian SE utilizes the AVEVA PI Server, which contains a
    vulnerability that could allow an unauthenticated user to cause a partial
    denial-of-service condition in the PI Message Subsystem of a PI Server by
    consuming available memory. This vulnerability exists in FactoryTalk
    Historian SE versions 9.0 and earlier. Exploitation of this vulnerability
    could cause FactoryTalk Historian SE to become unavailable, requiring a
    power cycle to recover it. (CVE-2023-31274)

  - FactoryTalk Historian SE uses the AVEVA PI Server, which contains a
    vulnerability that could allow an unauthenticated user to remotely crash the
    PI Message Subsystem of a PI Server, resulting in a denial-of-service
    condition. This vulnerability exists in FactoryTalk Historian SE versions
    9.0 and earlier. Exploitation of this vulnerability could cause FactoryTalk
    Historian SE to become unavailable, requiring a power cycle to recover it.
    (CVE-2023-34348)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-24-130-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rockwell FactoryTalk Historian version 9.01 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34348");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:rockwellautomation:factorytalk_historian");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rockwell_factorytalk_historian_installed.nbin");
  script_require_keys("installed_sw/Rockwell FactoryTalk Historian");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Rockwell FactoryTalk Historian', win_local:TRUE);

var constraints = [
  {'fixed_version' : '9.01' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
