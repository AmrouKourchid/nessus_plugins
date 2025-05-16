include('compat_shared.inc');
include('debug.inc');
include('tenable_ot_assets_funcs.inc');

namespace tenable_ot
{
  namespace eol
  {
    ##
    # Compare EOL info to model asset
    #
    # @param [asset:array] asset information
    # @param [eol_info:array] End of Life information
    #
    # @remark reports or audits out
    #
    # @return NULL always
    ##
    function compare_and_report(asset, eol_info, severity)
    {
      var items, order, level, plugin_article_number, _plugin_article_number, report, key, model_name, _model_name;
      
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'entry point');
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:'eol_info: '+obj_rep(eol_info)+'\n');
      
      items = NULL;
      order = NULL;

      if (!empty_or_null(asset.modelName))
      {

        model_name = asset.modelName;

        # For Rockwell, we need to skip the series part, eg /A in 1756-EN2T/A
        if ( asset.vendor == 'Rockwell' )
        {
          _model_name = pregmatch(pattern:"\w+(?:-\w+)+", string:model_name);
          
          if( !empty_or_null(_model_name) && !empty_or_null(_model_name[0]) )
          {
            model_name = _model_name[0];
          }
        }

        # Ensuring that 'BMX P34 2030' can match 'BMXP342030'
        model_name = preg_replace(pattern:"[\W_]", replace:"", string:model_name);

        # Process each model in eol_info
        foreach plugin_article_number (keys(eol_info))
        {
          _plugin_article_number = preg_replace(pattern:"[\W_]", replace:"", string:plugin_article_number);

          # The article number is the key as it refers to the base part number, without the series or revision details.
          # 'model_name' is the model we get from ICP
          # >< stands for 'substring of'
          if (tolower(_plugin_article_number) == tolower(model_name))
          {
            items = {
              'Vendor' : asset.vendor,
              'Model'  : asset.modelName,
              'Vendor Lifecycle Status' : eol_info[plugin_article_number].LifecycleStatus,
              'Reference'    : eol_info[plugin_article_number].Reference,
            };

            order = ['Vendor', 'Model', 'Vendor Lifecycle Status', 'Reference'];

            # Adding DiscontinuedDate if in a end of life/discontinued status
            # Rockwell active statuses; Active, Active Mature
            if('active' >!< tolower(eol_info[plugin_article_number].LifecycleStatus))
            {
              items['Discontinued Date'] = eol_info[plugin_article_number].DiscontinuedDate;
              order[len(order)] = 'Discontinued Date';
            }

            # Adding ReplacementProduct if mentioned
            if(!empty_or_null(eol_info[plugin_article_number].ReplacementProduct))
            {
              items['Replacement Product'] = eol_info[plugin_article_number].ReplacementProduct;
              order[len(order)] = 'Replacement Product';
            }

            # Adding LastModifiedDate if mentioned
            if(!empty_or_null(eol_info[plugin_article_number].LastModifiedDate))
            {
              items['Last Modified Date'] = eol_info[plugin_article_number].LastModifiedDate;
              order[len(order)] = 'Last Modified Date';
            }
            
            # If some items values are undefined, calling report_items_str with those values NULL will cause a NULL output
            # This is only for plugin output and will not interfere with detection logic
            foreach key (keys(items))
            {
              if (empty_or_null(items[key]))
              {
                items[key] = '';
              }
            }

            break;
          }
        }
      }

      if(!items)
      {
        audit(AUDIT_DEVICE_NOT_VULN, strcat(asset.vendor, ' ', asset.family));
      }

      report = report_items_str(report_items:items, ordered_fields:order);

      if (severity == SECURITY_NOTE) level = 0;
      else if (severity == SECURITY_WARNING) level = 2;
      else if (severity == SECURITY_HOLE) level = 3;

      security_report(port:0, level:level, extra:report, host:asset.id); 

      return NULL;
    }
  }
}
