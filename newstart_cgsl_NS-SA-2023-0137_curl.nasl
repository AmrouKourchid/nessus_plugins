#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/12/04 due to vendor advisory.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0137. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185407);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/04");

  script_cve_id(
    "CVE-2022-35252",
    "CVE-2022-43552",
    "CVE-2023-23916",
    "CVE-2023-27535"
  );
  script_xref(name:"IAVA", value:"2023-A-0008-S");
  script_xref(name:"IAVA", value:"2023-A-0153-S");
  script_xref(name:"IAVA", value:"2023-A-0531");
  script_xref(name:"IAVA", value:"2022-A-0350-S");

  script_name(english:"NewStart CGSL MAIN 6.06 : curl Multiple Vulnerabilities (NS-SA-2023-0137) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0137");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-35252");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-43552");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-23916");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-27535");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27535");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:curl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:curl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libcurl-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated.");
