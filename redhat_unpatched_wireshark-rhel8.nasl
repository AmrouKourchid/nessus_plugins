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
# extracted from Red Hat Security Advisory wireshark. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199495);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2018-5334",
    "CVE-2018-5335",
    "CVE-2018-5336",
    "CVE-2018-6836",
    "CVE-2019-5716",
    "CVE-2019-5717",
    "CVE-2019-5718",
    "CVE-2019-5719",
    "CVE-2019-9208",
    "CVE-2019-9209",
    "CVE-2019-10894",
    "CVE-2019-10895",
    "CVE-2019-10896",
    "CVE-2019-10899",
    "CVE-2019-10901",
    "CVE-2019-10903",
    "CVE-2019-12295",
    "CVE-2019-13619",
    "CVE-2019-16319",
    "CVE-2019-19553",
    "CVE-2020-7045",
    "CVE-2020-9428",
    "CVE-2020-9430",
    "CVE-2020-9431",
    "CVE-2020-11647",
    "CVE-2020-13164",
    "CVE-2020-15466",
    "CVE-2020-25862",
    "CVE-2020-25863",
    "CVE-2020-26418",
    "CVE-2020-26421",
    "CVE-2020-26575",
    "CVE-2020-28030",
    "CVE-2021-4185",
    "CVE-2021-22207",
    "CVE-2023-0411",
    "CVE-2023-0412",
    "CVE-2023-0413",
    "CVE-2023-0417",
    "CVE-2023-0667",
    "CVE-2023-1161",
    "CVE-2023-1992",
    "CVE-2023-1993",
    "CVE-2023-1994",
    "CVE-2023-2906",
    "CVE-2023-4511",
    "CVE-2023-4512",
    "CVE-2023-4513",
    "CVE-2023-5371",
    "CVE-2023-6174",
    "CVE-2023-6175",
    "CVE-2024-2955",
    "CVE-2024-24476"
  );

  script_name(english:"RHEL 8 : wireshark (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2011/cve-2011-1142.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1482807e");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-9781.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd415663");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6836");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
