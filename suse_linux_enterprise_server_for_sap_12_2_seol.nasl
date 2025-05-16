#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209131);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_name(english:"SUSE Linux Enterprise Server For SAP SEoL (12.2.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of SUSE Linux Enterprise Server For SAP is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, SUSE Linux Enterprise Server For SAP is 12.2.x. It is, therefore, no longer maintained by its
vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/lifecycle/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of SUSE Linux Enterprise Server For SAP that is currently supported.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"seol_date", value:"2018/03/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:linux_enterprise_server_for_sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:sles_sap");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info2.nasl");

  exit(0);
}

include('ucf.inc');

var os = ucf::get_os_cpe(vendor:'suse', product:'suse_linux_enterprise_server_for_sap', type:'combined');

var constraints = [
  { max_branch : '12.2', min_branch : '12.2', eseol : 20210331, seol : 20180331 }
];

ucf::os::check_and_report(os_info:os.info, constraints:constraints, severity:SECURITY_HOLE);
