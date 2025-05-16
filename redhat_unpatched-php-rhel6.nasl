#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024-05-31.
# This plugin has been deprecated as it does not adhere to established standards for this style of check.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory php. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196157);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2016-2554",
    "CVE-2016-3074",
    "CVE-2016-3141",
    "CVE-2016-3142",
    "CVE-2016-3185",
    "CVE-2016-4072",
    "CVE-2016-4073",
    "CVE-2016-4342",
    "CVE-2016-4343",
    "CVE-2016-4537",
    "CVE-2016-4538",
    "CVE-2016-4539",
    "CVE-2016-4540",
    "CVE-2016-4541",
    "CVE-2016-4542",
    "CVE-2016-4543",
    "CVE-2016-4544",
    "CVE-2016-5093",
    "CVE-2016-5096",
    "CVE-2016-5114",
    "CVE-2016-5399",
    "CVE-2016-5768",
    "CVE-2016-5771",
    "CVE-2016-5772",
    "CVE-2016-5773",
    "CVE-2016-6288",
    "CVE-2016-6289",
    "CVE-2016-6290",
    "CVE-2016-6291",
    "CVE-2016-6294",
    "CVE-2016-6296",
    "CVE-2016-6297",
    "CVE-2016-7124",
    "CVE-2016-7125",
    "CVE-2016-7126",
    "CVE-2016-7127",
    "CVE-2016-7128",
    "CVE-2016-7129",
    "CVE-2016-7130",
    "CVE-2016-7131",
    "CVE-2016-7132",
    "CVE-2016-7411",
    "CVE-2016-7412",
    "CVE-2016-7413",
    "CVE-2016-7414",
    "CVE-2016-7416",
    "CVE-2016-7417",
    "CVE-2016-7418",
    "CVE-2016-7478",
    "CVE-2016-7479",
    "CVE-2016-7480",
    "CVE-2016-9137",
    "CVE-2016-9138",
    "CVE-2016-9934",
    "CVE-2016-9935",
    "CVE-2016-9936",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-10160",
    "CVE-2016-10161",
    "CVE-2016-10162",
    "CVE-2016-10397",
    "CVE-2016-10712",
    "CVE-2017-5340",
    "CVE-2017-7189",
    "CVE-2017-7272",
    "CVE-2017-7890",
    "CVE-2017-9118",
    "CVE-2017-11143",
    "CVE-2017-11144",
    "CVE-2017-11145",
    "CVE-2017-11147",
    "CVE-2017-11362",
    "CVE-2017-11628",
    "CVE-2017-12933",
    "CVE-2017-16642",
    "CVE-2018-5712",
    "CVE-2018-7584",
    "CVE-2018-10545",
    "CVE-2018-10546",
    "CVE-2018-10547",
    "CVE-2018-10548",
    "CVE-2018-14851",
    "CVE-2018-14883",
    "CVE-2018-17082",
    "CVE-2018-19518",
    "CVE-2018-20783",
    "CVE-2019-9020",
    "CVE-2019-9021",
    "CVE-2019-9023",
    "CVE-2019-9024",
    "CVE-2019-9637",
    "CVE-2019-9640",
    "CVE-2019-9641",
    "CVE-2019-11034",
    "CVE-2019-11035",
    "CVE-2019-11036",
    "CVE-2019-11040",
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-11045",
    "CVE-2019-11047",
    "CVE-2019-11048",
    "CVE-2019-11050",
    "CVE-2020-7059",
    "CVE-2020-7060",
    "CVE-2020-7062",
    "CVE-2020-7063",
    "CVE-2020-7068",
    "CVE-2020-7070",
    "CVE-2020-7071",
    "CVE-2021-21702",
    "CVE-2021-21703",
    "CVE-2021-21705",
    "CVE-2021-21707",
    "CVE-2022-4900",
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-31631",
    "CVE-2023-0567",
    "CVE-2023-0568",
    "CVE-2023-3247",
    "CVE-2024-1874",
    "CVE-2024-2756",
    "CVE-2024-3096"
  );

  script_name(english:"RHEL 6 : php (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2554");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-9641");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'php imap_open Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
