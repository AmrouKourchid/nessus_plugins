#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-03-18.
# Plugin deprecated in favor of mongodb_SERVER_92382_CVE-2024-8305.nasl
##

include('compat.inc');

if (description)
{
  script_id(209641);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2024-8305");
  script_xref(name:"IAVB", value:"2024-B-0160-S");

  script_name(english:"MongoDB  6.0.x < 6.0.17 / 7.0.x < 7.0.13 / 7.3.x < 7.3.4 incorrect enforcement of index constraints (SERVER-92382) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin deprecated in favor of mongodb_SERVER_92382_CVE-2024-8305.nasl");
  script_set_attribute(attribute:"description", value:
"Plugin deprecated in favor of mongodb_SERVER_92382_CVE-2024-8305.nasl");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-92382");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("installed_sw/MongoDB");

  exit(0);
}

exit(0, "Plugin deprecated in favor of mongodb_SERVER_92382_CVE-2024-8305.nasl");
