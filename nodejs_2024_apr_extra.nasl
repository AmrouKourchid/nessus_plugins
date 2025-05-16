#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024-07-08.
# Duplicates an existing plugin Replaced by nodejs_2024_apr2.nasl (193573).
##

include('compat.inc');

if (description)
{
  script_id(193580);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/08");

  script_cve_id("CVE-2024-27980");

  script_name(english:"Node.js 18.x < 18.20.2 / 20.x < 20.12.2 / 21.x < 21.7.3 Multiple Vulnerabilities (Wednesday, April 10, 2024 Security Releases). (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Duplicates an existing plugin Replaced by nodejs_2024_apr2.nasl (193573).");
  script_set_attribute(attribute:"description", value:
"Duplicates an existing plugin Replaced by nodejs_2024_apr2.nasl (193573).");
  # https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f839ef4");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("installed_sw/Node.js", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "Duplicates an existing plugin Replaced by nodejs_2024_apr2.nasl (193573).");
