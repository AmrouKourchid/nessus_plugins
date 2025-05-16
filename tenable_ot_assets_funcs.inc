#TRUSTED a8ad5b0f5fcdc60fe416211222086398ee2ada3dd41cbae779fa2781891bfbd4d061754cb93b7aecb1d12997642e57970cbadd79f2030979a9c608bc07c35a7765ca63dcc0d14aeae771df788a19290fefdf458677179e98a603e4093a4e51fb4af78ad9fec85217d3e30ee2546dfb01a7da0e79f95b2185ae3261ade1391e4df3b964be0e2601b28fe61ceee6a001c7e3954a9636305f092be21883158eff74b8907c654359bfdc54acba9942d79d7d063bc9944a19d6f198e232d783575c4c515b7dcdbbe143f5fce39c9d6c7cd30a2688a9557863289d1e023bcfe7506f20ed9870e2f43d5a72c6ecbfe96c4f37d43bd66201cd2b9b3753211e39db7342622e59c79928ff93d008c2aeca395cccd8d9443d18d2b0ea3745b0da80f7afbb561fd5418b32779556ff42eeca20a375aadda89e68ed9c49192740cb639cf26ad9662a6999b7a84e92fcbd80231beb042d5ef7fd16c91a4a11a3da276505bff8e8a8331ee6f19c9082697ee5961841ef5cc4bdb294ca70c5d9f6a957e553b2b6da1ac014da63783ef884b52f18bcad7d0de45d3afadbfde4d189685e0170fda895f2e99beb174383c2eded2e540850a3aebf44f80038cd767e3edb5dd8500d419a8ffef4609e4cd2a29bb2eab7add99e1c53ca1eb500517efc6f74852b60270c3f9901518f598d3295df7d4fa2d4ddac64220fa05a2fe003972050c4bc69fbc4cf
#TRUST-RSA-SHA256 086ea85063da7ea5183611c77c9e5e2f98c8f03ac09f320b49c724acdd94d31de861d746c0cac972fe39834b81acebab98a8ffee082982ca3f07ba64ab7e077ad66aefb6a5385283021f0011a6133b4c29d2559c8f487bd387c20b663ca51d73dcd92e2c8661cdd85f1f65fdda79786992cef26910468b68b1cad500ff89124a870cc14483d97f4056cb4f8c8bae0cfb85e39cc6cfa3ba31877a46f1818fae1952dce6d46c91e8348fa61baf1bfa1b46555308c1e90bd3a5cd803e68a00d25bce8407bc388b1dcc840a4e8d4410f4c7f9c2537c78cd72ada1b69fe68cdb499b914d428a893ec46f60bd0fdfb3861bbfd6d411346a45e08f08505009a37ad1c056ee8f5f111791d1eaa8ea7c520ec78161430fddade65b18e98dbdb704dcc7435e8907fca85ce4193880e3e5e128bd528a45364f587ed6690512379890ffd97596fd70b6049fa73f884f5476eaeb8fad64bd07e2077654ffca8c0e7ebc9ff34931992ec07b4cbafe8aa4615148eed151333767980e1eec248520d135dd9a629ddb6b4fcd7c1a1804723aa5d61dc6d03aa771237cdbba9f5a655d61ea1b6665f70208ea23d640fa9dc0bb040e9be9cd4408325f47fc36f0b61e4681f4518d54bb9b8cc94073b62c06d58bff4ad27c8465a996be8b0a968cc88f729a9fc431863208b68e4519961d4d7c008d3fc214b71c8cd0b301406fe7de96d57b467ed197fa4
include('compat_shared.inc');
include('debug.inc');
include('sql.inc');

namespace tenable_ot
{
  namespace assets
  {
    var ASSETS_TABLE = 'tenable_ot_assets';

    ##
    # Create the assets table
    #
    # @param [asset_keys:list] asset keys to create columns in table
    #
    # @return true if successful; false otherwise
    ##
    function create_table(asset_keys)
    {
      var schema, asset_key, column, columns;

      columns = [];

      schema = strcat('CREATE TABLE IF NOT EXISTS ', ASSETS_TABLE, '(
          "id" TEXT PRIMARY KEY,');
          #"__index__" INTEGER PRIMARY KEY AUTOINCREMENT,';

      foreach asset_key (asset_keys)
      {
        if (asset_key == 'id') continue;

        column = strcat("'", asset_key, "' TEXT");
        append_element(var:columns, value:column);
      }

      schema += join(columns, sep:',\n        ');
      schema += ');';

      dbg::log(src:FUNCTION_NAME, msg:'Creating table with:\n' + schema);
      
      query_scratchpad(schema);
    
      return true;
    }

    ##
    # Populate the assets table with asset data
    #
    # @param [asset_data:array] asset data to add to table
    #
    # @return true if successful; false otherwise
    ##
    function populate_table(asset_data)
    {
      var query;

      query = strcat('INSERT INTO ', ASSETS_TABLE, "('id') VALUES (?)");
      query_scratchpad(query, asset_data.id);
      
      update(asset_data:asset_data);

      return true; 
    }

    ##
    # Update the assets table
    #
    # @param [asset_data:array] asset data to add to table
    #
    # @return true if successful; false otherwise
    ##
    function update(asset_data)
    {
      var key, value, query;

      foreach key (keys(asset_data))
      {
        if (key == 'id') continue;

        # Add lists as string separated by ', '
        value = asset_data[key];
        if (typeof(value) == 'array')
          value = join(value, sep:', ');  

        query = strcat('UPDATE ', ASSETS_TABLE, ' SET ', key, '=? WHERE id=?');
        query_scratchpad(query, value, asset_data.id);
      }

      #dbg::log(src:FUNCTION_NAME, msg:'Updated table:\n' + sql::dump_table(ASSETS_TABLE, key:asset_data.id));

      return true;
    }

    ##
    # Retrieves the asset info
    #
    # @param [vendor:string] vendor CPE (e.g. rockwellautomation)
    #
    # @remark this function will branch if more than one asset matches
    #
    # @return asset data for each asset; NULL otherwise
    ##
    function get(vendor, hasAssetBag)
    {
      var query, results;

      if (!sql::check_table(ASSETS_TABLE))
        return NULL;

      if (hasAssetBag == TRUE){
        query = strcat('SELECT * FROM ', ASSETS_TABLE, ' WHERE assetBag IS NOT NULL');
        results = query_scratchpad(query);
      }
      else
      {
        query = strcat('SELECT * FROM ', ASSETS_TABLE, ' WHERE vendor=?');
        results = query_scratchpad(query, vendor);
      }

      if (empty_or_null(results))
        return NULL;

      return branch(results);
    }

    ##
    # Report the asset info using the 'id' as the host
    #
    # @param [asset:array] asset data to report
    #
    # @return true if successful; false otherwise
    ##
    function report(asset)
    {
      var key, value, report; 

      # Process asset data so that reporting function don't choke
      foreach key (keys(asset))
      {
        value = asset[key];

        # Remove k/v pairs with NULL value
        if (empty_or_null(value))
          delete_element(var:asset, idx:key);

        # Add lists as string separated by ', '
        if (typeof(value) == 'array')
          value = join(value, sep:', ');

        asset[key] = value;
      }

      report = report_items_str(
        report_items   : asset,
        ordered_fields : keys(asset)
      );

      security_report(port:0, level:0, extra:report, host:asset.id);

      return true;
    }
  }
}
