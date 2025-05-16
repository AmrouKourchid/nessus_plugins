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
  script_id(200040);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id(
    "CVE-2013-6167",
    "CVE-2014-8642",
    "CVE-2015-6525",
    "CVE-2016-10195",
    "CVE-2016-10196",
    "CVE-2016-10197",
    "CVE-2017-5429",
    "CVE-2017-5430",
    "CVE-2017-5432",
    "CVE-2017-5433",
    "CVE-2017-5434",
    "CVE-2017-5435",
    "CVE-2017-5436",
    "CVE-2017-5438",
    "CVE-2017-5439",
    "CVE-2017-5440",
    "CVE-2017-5441",
    "CVE-2017-5442",
    "CVE-2017-5443",
    "CVE-2017-5444",
    "CVE-2017-5445",
    "CVE-2017-5446",
    "CVE-2017-5447",
    "CVE-2017-5448",
    "CVE-2017-5449",
    "CVE-2017-5451",
    "CVE-2017-5454",
    "CVE-2017-5455",
    "CVE-2017-5456",
    "CVE-2017-5459",
    "CVE-2017-5460",
    "CVE-2017-5464",
    "CVE-2017-5465",
    "CVE-2017-5466",
    "CVE-2017-5467",
    "CVE-2017-5469",
    "CVE-2018-5148",
    "CVE-2018-12403",
    "CVE-2020-6823",
    "CVE-2020-6824"
  );

  script_name(english:"RHEL 5 : firefox (Unpatched Vulnerability) (deprecated)");

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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6823");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
