#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-02-12.
# Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory netpbm. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199301);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2014-8138",
    "CVE-2014-8157",
    "CVE-2014-9029",
    "CVE-2015-5203",
    "CVE-2016-2089",
    "CVE-2016-8690",
    "CVE-2016-8691",
    "CVE-2016-8692",
    "CVE-2016-8693",
    "CVE-2016-8883",
    "CVE-2016-8884",
    "CVE-2016-8885",
    "CVE-2016-9262",
    "CVE-2016-9387",
    "CVE-2016-9389",
    "CVE-2016-9390",
    "CVE-2016-9391",
    "CVE-2016-9392",
    "CVE-2016-9393",
    "CVE-2016-9394",
    "CVE-2016-9560",
    "CVE-2016-9583",
    "CVE-2016-9591",
    "CVE-2016-10248",
    "CVE-2016-10249",
    "CVE-2016-10251",
    "CVE-2017-2581",
    "CVE-2017-2586",
    "CVE-2017-2587",
    "CVE-2017-13745"
  );

  script_name(english:"RHEL 5 : netpbm (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9029");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-2581");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netpbm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
