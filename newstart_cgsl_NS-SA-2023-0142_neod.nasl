#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/12/04 due to vendor advisory.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0142. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185402);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/04");

  script_cve_id(
    "CVE-2019-16884",
    "CVE-2020-7919",
    "CVE-2021-21334",
    "CVE-2021-30465",
    "CVE-2021-41103",
    "CVE-2021-43784",
    "CVE-2022-23648"
  );

  script_name(english:"NewStart CGSL MAIN 6.06 : neod Multiple Vulnerabilities (NS-SA-2023-0142) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0142");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-16884");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-7919");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-21334");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30465");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-41103");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-43784");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-23648");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41103");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:neod");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated.");
