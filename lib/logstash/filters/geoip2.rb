# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# The GeoIP2 filter adds information about the geographical location of IP addresses,
# based on data from the Maxmind database.
#
# Starting with version 1.3.0 of Logstash, a `[geoip][location]` field is created if
# the GeoIP lookup returns a latitude and longitude. The field is stored in
# http://geojson.org/geojson-spec.html[GeoJSON] format. Additionally,
# the default Elasticsearch template provided with the
# <<plugins-outputs-elasticsearch,`elasticsearch` output>> maps
# the `[geoip][location]` field to an https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-geo-point-type.html#_mapping_options[Elasticsearch geo_point].
#
# As this field is a `geo_point` _and_ it is still valid GeoJSON, you get
# the awesomeness of Elasticsearch's geospatial query, facet and filter functions
# and the flexibility of having GeoJSON for all other applications (like Kibana's
# map visualization).
#
# Logstash releases ship with the GeoLiteCity database made available from
# Maxmind with a CCA-ShareAlike 3.0 license. For more details on GeoLite, see
# <http://www.maxmind.com/en/geolite>.

class LogStash::Filters::GeoIP2 < LogStash::Filters::Base
  attr_accessor :geoipdb

  config_name "geoip2"

  # The path to the GeoIP2 database file which Logstash should use. Country, City, ASN, ISP
  # and organization databases are supported.
  #
  # If not specified, this will default to the GeoLiteCity database that ships
  # with Logstash.
  # Up-to-date databases can be downloaded from here: <https://dev.maxmind.com/geoip/legacy/geolite/>
  # Please be sure to download a legacy format database.
  config :database, :validate => :path

  # The field containing the IP address or hostname to map via geoip. If
  # this field is an array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # An array of geoip fields to be included in the event.
  #
  # Possible fields depend on the database type. By default, all geoip fields
  # are included in the event.
  #
  # For the built-in GeoLite2-City database, the following are available:
  # `city`, `continent`, `country`, `location`, `postal`, `registered_country`
  # `subdivisions`
  config :fields, :validate => :array

  # Specify the field into which Logstash should store the geoip data.
  # This can be useful, for example, if you have `src\_ip` and `dst\_ip` fields and
  # would like the GeoIP information of both IPs.
  #
  # If you save the data to a target field other than `geoip` and want to use the
  # `geo\_point` related functions in Elasticsearch, you need to alter the template
  # provided with the Elasticsearch output and configure the output to use the
  # new template.
  #
  # Even if you don't use the `geo\_point` mapping, the `[target][location]` field
  # is still valid GeoJSON.
  config :target, :validate => :string, :default => 'geoip'

  # With GeoIP2 there are localazations of the named saved. Standard we will return
  # the english name of a item, as everybody expect to see those but you can set
  # another default langue with this option.
  # If the requested translation does not exists for that item, the english one will
  # be supplied instead.
  #
  # Please note that I rely on the notation in the maxmind database for matching.
  # This means that for most translations the 2 letter country code is valid.
  # But sometimes they also seem to use the locale language notation (for example: pt-BR)
  config :language, :validate => :string, :default => 'en'

  public
  def register
    require 'maxminddb'

    if @database.nil?
      @database = ::Dir.glob(::File.join(::File.expand_path("../../../vendor/", ::File.dirname(__FILE__)),"GeoLite2-*.mmdb")).first
      if @database.nil? || !File.exists?(@database)
        raise "You must specify 'database => ...' in your geoip2 filter (I looked for '#{@database}')"
      end
    end
    @logger.info("Using geoip database", :path => @database)

    # The new Maxmind database driver doesn't seem to expose a mutex.
    # So why not load and globalise it now.
    # Will throw 'invalid file format' on !File.exists
    begin
        @geoipdb = MaxMindDB.new(@database)
    rescue Exception => e
        raise "Could'nt load the database file. (Do I have read access for '#{@database}'?)"
    end
  end # def register

  public
  def filter(event)
    return unless event[@source]

    eSource = event[@source]

    if !event[@target].is_a?(Hash)
      eTarget = {}
    else
      eTarget = event[@target]
    end

    case eSource
      when Array
        eTarget = Array.new if !eTarget.is_a?(Array)

        eSource.each do |value|
            begin
                eTarget.push(resolveIP(value))
            rescue Exception => e
                @logger.error("IP Field contained invalid IP address or hostname", :e => e, :field => @source, :event => event)
            end
        end
      when String
        begin
            # Make sure we are dealing with a String here...
            eTarget = resolveIP(eSource)
        rescue Exception => e
            @logger.error("IP Field contained invalid IP address or hostname", :e => e, :field => @source, :event => event)
        end
      else
        @logger.warn("geoip2 filter has no support for this type of data", :type => eSource.class, :value => eSource)
        return
    end

    if (!eTarget.empty?)
      if !event[@target].is_a?(Hash)
        if (event[@target])
          @logger.debug("Overwriting existing target field", :target => @target)
        end

        event[@target] = eTarget
      else
        event[@target].merge!(eTarget)
      end

      filter_matched(event)
    end
  end # def filter

  private
  def resolveIP(ip)
    data = @geoipdb.lookup(ip)
    return {} if (!data.found?)
    data = data.to_hash

    if (data.key?("location") && data["location"].key?("latitude") && data["location"].key?("longitude"))
      data["location"]["longitude"] = data["location"]["longitude"].to_f
      data["location"]["latitude"]  = data["location"]["latitude"].to_f
    end

    data.each do |key, val|
        next if val.nil? || (val.is_a?(String) && val.empty?)

        if (@fields.respond_to?(:empty?) && !@fields.empty? && !@fields.include?(key))
          next if data.delete(key)
        elsif ((@fields == nil || (@fields.respond_to?(:empty?) && @fields.empty?)) && key == "registered_country")
          next if data.delete(key)
        end

        getName(val)

        if val.is_a?(Hash) && val.length == 1 && val.values.first.is_a?(String)
          data[key] = val.values.first.to_s
        end
    end
  end

  private
  def getName(item)
    return if !(item.is_a?(Hash) || item.is_a?(Array))

    case item
      when Array
        item.each do |skey, sval|
          # Yes, this is correct, as the array doesnt has any keys.
          # So skey == value
          getName(skey)
        end
      when Hash
        if item.key?("names") && item["names"].key?(@language)
          item["name"] = item["names"][@language]
          item.delete("names")
        elsif item.key?("names") && item["names"].key?("en")
          item["name"] = item["names"]["en"]
          item.delete("names")
        end

        if item.key?("geoname_id")
          item.delete("geoname_id")
        end
    end
  end
end # class LogStash::Filters::GeoIP

