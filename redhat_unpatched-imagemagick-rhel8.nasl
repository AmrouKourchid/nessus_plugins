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
# extracted from Red Hat Security Advisory imagemagick. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195375);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2017-17879",
    "CVE-2017-17880",
    "CVE-2017-17881",
    "CVE-2017-17882",
    "CVE-2017-17884",
    "CVE-2017-17885",
    "CVE-2017-17886",
    "CVE-2017-17887",
    "CVE-2017-17914",
    "CVE-2017-17934",
    "CVE-2017-18008",
    "CVE-2017-18022",
    "CVE-2017-18027",
    "CVE-2017-18028",
    "CVE-2017-18029",
    "CVE-2017-18209",
    "CVE-2017-18210",
    "CVE-2017-18211",
    "CVE-2017-18250",
    "CVE-2017-18251",
    "CVE-2017-18252",
    "CVE-2017-18253",
    "CVE-2017-18254",
    "CVE-2017-18271",
    "CVE-2017-18272",
    "CVE-2017-18273",
    "CVE-2017-1000445",
    "CVE-2018-5246",
    "CVE-2018-5247",
    "CVE-2018-5357",
    "CVE-2018-6405",
    "CVE-2018-6876",
    "CVE-2018-6930",
    "CVE-2018-7443",
    "CVE-2018-7470",
    "CVE-2018-8804",
    "CVE-2018-8960",
    "CVE-2018-9133",
    "CVE-2018-9135",
    "CVE-2018-10177",
    "CVE-2018-10804",
    "CVE-2018-10805",
    "CVE-2018-11251",
    "CVE-2018-11624",
    "CVE-2018-11655",
    "CVE-2018-11656",
    "CVE-2018-12599",
    "CVE-2018-12600",
    "CVE-2018-13153",
    "CVE-2018-14434",
    "CVE-2018-14435",
    "CVE-2018-14436",
    "CVE-2018-14437",
    "CVE-2018-14551",
    "CVE-2018-15607",
    "CVE-2018-16323"
  );

  script_name(english:"RHEL 8 : imagemagick (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14551");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
