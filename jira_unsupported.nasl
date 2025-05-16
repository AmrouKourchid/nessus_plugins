#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109318);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/29");
  script_xref(name:"IAVA", value:"0001-A-0519");

  script_name(english:"Atlassian JIRA Unsupported Version Detection (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. For plugins which identify unsupported instances of this product, 
search the plugin feed for Atlassian JIRA SEoL.");
  # https://confluence.atlassian.com/support/atlassian-support-end-of-life-policy-201851003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1ae64c0");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"The software is unsupported.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Atlassian JIRA");
  script_require_ports("Services/www", 80, 8080, 443);

  exit(0);
}
exit(0, 'This plugin has been deprecated. For plugins which identify unsupported instances of this product, search the plugin feed for Atlassian JIRA SEoL.');