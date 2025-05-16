#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63683);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_xref(name:"IAVA", value:"0001-A-0620");

  script_name(english:"VMware Horizon View SEoL");
  script_summary(english:"Checks if a VMware Horizon View version is unsupported");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a virtual desktop
solution.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of VMware Horizon View, formerly known as VMWare View Server, and VMware
Virtual Desktop Infrastructure, on the remote host is no longer supported.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is
likely to contain security vulnerabilities.");
  # https://lifecycle.vmware.com/#/?advancedFilter=checkbox_sup,checkbox_unsup&filters=%7B%22name%22:%22View%22,%22lifecycle_policy%22:null,%22text%22:null%7D
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2660ffa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of VMware Horizon that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:'cvss_score_source', value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"seol_date", value:"2019/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:view");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");

  script_dependencies("vmware_horizon_view_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View");
  exit(0);
}

include('ucf.inc');

var app = 'VMware Horizon View';

var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { min_branch : '0', max_branch:'1.7', seol : 20151209},
  { min_branch : '1.7', max_branch:'2', seol : 20100602},
  { branch:'3', seol : 20150511},
  { branch:'4', seol : 20141116},
  { branch:'5', seol : 20160914, eseol : 20180914},
  { branch:'6', seol : 20190619, eseol : 20210619}
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
