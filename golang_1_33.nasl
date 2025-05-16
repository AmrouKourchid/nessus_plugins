#%NASL_MIN_LEVEL 80900
##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/03/20.
##

include('compat.inc');

if (description)
{
  script_id(191710);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/20");

  script_cve_id("CVE-2024-24786");
  script_xref(name:"IAVB", value:"2024-B-0020");

  script_name(english:"Golang < 1.33.0 DOS (Deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://pkg.go.dev/vuln/GO-2024-2611");
  script_set_attribute(attribute:"see_also", value:"https://go.dev/cl/569356");
  script_set_attribute(attribute:"see_also", value:"https://vuln.go.dev/ID/GO-2024-2611.json");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Golang Go Programming Language", "SMB/Registry/Enumerated");

  exit(0);
}

exit(0, 'This plugin has been deprecated.');