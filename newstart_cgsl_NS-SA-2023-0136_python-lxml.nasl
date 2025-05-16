#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/12/04 due to vendor advisory.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0136. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185428);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2019-6446",
    "CVE-2019-7164",
    "CVE-2019-7548",
    "CVE-2019-9636",
    "CVE-2019-9740",
    "CVE-2019-9947",
    "CVE-2019-9948",
    "CVE-2019-11236",
    "CVE-2019-11324",
    "CVE-2019-16056",
    "CVE-2019-16935",
    "CVE-2019-18874",
    "CVE-2019-20477",
    "CVE-2019-20907",
    "CVE-2020-8492",
    "CVE-2020-14343",
    "CVE-2020-14422",
    "CVE-2020-26137",
    "CVE-2020-27619",
    "CVE-2020-28493",
    "CVE-2021-3177",
    "CVE-2021-3426",
    "CVE-2021-3733",
    "CVE-2021-3737",
    "CVE-2021-4189",
    "CVE-2021-23336",
    "CVE-2021-29921",
    "CVE-2021-33503",
    "CVE-2021-42771",
    "CVE-2022-0391",
    "CVE-2022-42919"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"NewStart CGSL MAIN 6.06 : python-lxml Multiple Vulnerabilities (NS-SA-2023-0136) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0136");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-11236");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-11324");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-16056");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-16935");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-18874");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-20477");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-20907");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-6446");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-7164");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-7548");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-9636");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-9740");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-9947");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-9948");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-14343");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-14422");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-26137");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-27619");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-28493");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-8492");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-23336");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-29921");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3177");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-33503");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3426");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3733");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3737");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-4189");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-42771");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-0391");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42919");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14343");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-lxml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated.");
