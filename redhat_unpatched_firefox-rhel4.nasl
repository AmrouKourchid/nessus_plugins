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
# extracted from Red Hat Security Advisory firefox. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200017);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id(
    "CVE-2008-7293",
    "CVE-2012-0455",
    "CVE-2012-0456",
    "CVE-2012-0457",
    "CVE-2012-0458",
    "CVE-2012-0461",
    "CVE-2012-0462",
    "CVE-2012-0464"
  );

  script_name(english:"RHEL 4 : firefox (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-45590.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0136bc55");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9398.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fd036b2");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-42460.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?155a4b65");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9394.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c329a33");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-42459.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f037a11");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9396.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a7e3e79");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9393.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?443af80c");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9400.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66887bd5");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-8900.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c5e7fea");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9680.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74862a3f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9399.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83e7037f");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9401.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8745a918");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-4068.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89d67ae0");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-42461.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3946585");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9936.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9f00b2a");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9402.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c09009e9");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9397.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ced1ba26");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9392.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaf0c5aa");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0457");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-0455");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
