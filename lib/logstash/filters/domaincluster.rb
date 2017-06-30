# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "sequel"

# The DomainCluster filter groups Fully-Qualified Domain Names (FQDN) or IP address
# in groups as defined by a set of patterns in a local SQLite database.
#
# The point of such grouping is to give a more "user behavior" comprehensive view of a log,
# by associating groups (or 'clusters') of FQDNs or IP address to a semantic name;
# take the following log line for example:
#
#  1447860990.048 3 10.0.0.140 TCP_DENIED/403 3668 CONNECT api.twitter.com:443 coj NONE/- text/html
#
# If we specify the 'api.twitter.com' part of the log as the source field for our plugin,
# the DomainCluster lookup in the database would find a matching pattern, such as '\.twitter.\'
# that belongs to cluster "Social Network", which, at the same time, may include
# other patterns such as '\.facebook\.com$'.
#
# [NOTE]
# Patterns are unique, and so are groups; on lookup, groups are assigned at first match.
#
# The config should look like this
# [source,ruby]
# filter {
#   domaincluster {
#     source => "source_field"
#     database => "/var/domaincluster.sqlite"
#   }
# }
#
class LogStash::Filters::Domaincluster < LogStash::Filters::Base   
  config_name "domaincluster"  
    
  # The field containing the FQDN or IP to group via DomainCluster. If
  # this field is an array, only the first value will be used.
  config :source, :validate => :string, :required => true
  
  # Path to the DomainCluster database file which Logstash should use. Only
  # SQLite3 database file is supported by now.
  config :database, :validate => :path, :required => true
  
  # Specify the field into which Logstash should store the DomainCluster data.
  config :target, :validate => :string, :default => "domaincluster"
  
  # Tags the event on failure to look up domain cluster information. This can
  # be used in later analysis.
  config :tag_on_failure, :validate => :array, :default => ["_domaincluster_lookup_failure"]  

  public
  def register
    # Validate that database file exists
    if !File.exists?(@database)
      raise "You must specify a valid SQLite file path for 'database => ...' in your domaincluster filter (I looked for '#{@database}')"
    end
        
    # Connect to database
    @db = Sequel.connect("jdbc:sqlite:#{@database}")
    @result_set = @db['SELECT p.pattern, c.name FROM Pattern p JOIN Cluster c on c._id = p.cluster_id;']
    @logger.info("Using domaincluster database", :path => @database)
  end # def register

  public
  def filter(event)     
    if !validate_source
      tag_unsuccessful_lookup(event)  
    else      
      group = nil
      
      for row in @result_set
        row_pattern = "#{row[:pattern]}"
        re = Regexp.new row_pattern
        domain = event.get(@source)  
        
        if re.match(domain) then
          group = "#{row[:name]}"
          break
        end
      end
      
      if group != nil
        event.set(@target, group)
      else
        tag_unsuccessful_lookup(event)  
      end        
    end
        
    filter_matched(event)
  end # def filter
  
  def validate_source
    # Specified @source field must be a string representing a valid
    # IPv4, IPv6 address or Hostname to return true, will return
    # false otherwise.
    # 
    
    # RFC 791 compliant IPv4 regular expression validation 
    ipv4_re = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/
    
    # RFC 2460 compliant IPv6 regular expression validation. Source
    # can be found at https://gist.github.com/cpetschnig/294476[cpetschnig @ *GitHub*].
    # Thanks to both 'cpetschnig' and 'Dartware'
    ipv6_re = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/
    
    # RFC 1123 compliant hostname validation. The original specification
    # of hostnames in RFC 952, mandated that labels could not start
    # with a digit or with a hyphen, and must not end with a hyphen. However,
    # a subsequent specification (RFC 1123) permitted hostname labels
    # to start with digits.
    hostname_re = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/
    
    match_ipv4 = ipv4_re.match(@source)
    match_ipv6 = ipv6_re.match(@source)
    match_hostname = hostname_re.match(@source)
    
    if match_ipv4 || match_ipv6 || match_hostname
      return true
    else
      return false
    end
  end # def validate_source
  
  def tag_unsuccessful_lookup(event)
    @logger.debug? && @logger.debug("Hostname #{event.get(@source)} matched no pattern in the database", :event => event)
    @tag_on_failure.each{|tag| event.tag(tag)}
  end # def tag_unsuccessful_lookup
end # class LogStash::Filters::Domaincluster
