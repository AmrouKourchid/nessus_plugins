#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/12/28. Plugin only referenced a rejected CVE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152306);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id("CVE-2021-20095");

  script_name(english:"EulerOS 2.0 SP8 : babel (EulerOS-SA-2021-2287) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to only referencing a CVE that has been rejected.

According to the version of the babel packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerability :

  - A flaw was found in python-babel. A path traversal
    vulnerability was found in how locale data files are
    checked and loaded within python-babel, allowing a
    local attacker to trick an application that uses
    python-babel to load a file outside of the intended
    locale directory. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as service availability.(CVE-2021-20095)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2287
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9b3d31f");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-babel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

exit(0, 'This plugin has been deprecated due to only referencing a rejected CVE.');
