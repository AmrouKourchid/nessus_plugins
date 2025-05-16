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
# extracted from Red Hat Security Advisory vim. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198465);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2018-20786",
    "CVE-2020-20703",
    "CVE-2021-3236",
    "CVE-2021-3927",
    "CVE-2021-3974",
    "CVE-2021-4166",
    "CVE-2022-0351",
    "CVE-2022-1619",
    "CVE-2022-1720",
    "CVE-2022-2124",
    "CVE-2022-2125",
    "CVE-2022-2126",
    "CVE-2022-2129",
    "CVE-2022-2175",
    "CVE-2022-2182",
    "CVE-2022-2183",
    "CVE-2022-2206",
    "CVE-2022-2207",
    "CVE-2022-2208",
    "CVE-2022-2210",
    "CVE-2022-2284",
    "CVE-2022-2285",
    "CVE-2022-2286",
    "CVE-2022-2287",
    "CVE-2022-2343",
    "CVE-2022-2344",
    "CVE-2022-2345",
    "CVE-2022-2522",
    "CVE-2022-2819",
    "CVE-2022-2845",
    "CVE-2022-2849",
    "CVE-2022-2923",
    "CVE-2022-2946",
    "CVE-2022-2980",
    "CVE-2022-3037",
    "CVE-2022-3153",
    "CVE-2022-3234",
    "CVE-2022-3235",
    "CVE-2022-3256",
    "CVE-2022-3296",
    "CVE-2022-3352",
    "CVE-2022-3705",
    "CVE-2022-4292",
    "CVE-2022-4293",
    "CVE-2023-0049",
    "CVE-2023-0054",
    "CVE-2023-0288",
    "CVE-2023-0433",
    "CVE-2023-0512",
    "CVE-2023-1127",
    "CVE-2023-1170",
    "CVE-2023-1175",
    "CVE-2023-1264",
    "CVE-2023-2609",
    "CVE-2023-2610",
    "CVE-2023-4734",
    "CVE-2023-4735",
    "CVE-2023-4738",
    "CVE-2023-4751",
    "CVE-2023-4752",
    "CVE-2023-4781",
    "CVE-2023-5344",
    "CVE-2023-5441",
    "CVE-2023-5535",
    "CVE-2023-46246",
    "CVE-2023-48231",
    "CVE-2023-48232",
    "CVE-2023-48233",
    "CVE-2023-48234",
    "CVE-2023-48235",
    "CVE-2023-48236",
    "CVE-2023-48237",
    "CVE-2023-48706",
    "CVE-2024-22667"
  );

  script_name(english:"RHEL 8 : vim (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-41965.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8268cf5");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2345");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-20703");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
