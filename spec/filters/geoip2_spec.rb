require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/geoip2"

describe LogStash::Filters::GeoIP2 do
  describe "default" do
    config <<-CONFIG
      filter {
        geoip2 {
          source => "ip"
	  language => "en"
          database => "/opt/GeoLite2-City.mmdb"
        }
      }
    CONFIG

    sample("ip" => "8.8.8.8") do
      insist { subject }.include?("geoip")
      insist { subject["geoip"]["city"]["name"] } == "Mountain View"

      expected_fields = %w(city continent country location postal
                           registered_country subdivisions)

      expected_fields.each do |f|
        insist { subject["geoip"] }.include?(f)
      end
    end

    sample("ip" => "127.0.0.1") do
      # assume geoip fails on localhost lookups
      reject { subject }.include?("geoip")
    end
  end

end
