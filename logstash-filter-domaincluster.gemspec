Gem::Specification.new do |s|
  s.name          = 'logstash-filter-domaincluster'
  s.version       = '0.1.0'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = 'Logstash filter plugin for IP/Hostname clustering'
  s.description   = 'This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program'
  s.homepage      = 'https://github.com/nacastroc/logstash-filter-domaincluster'
  s.authors       = ['Nestor A. Castro Castillo']
  s.email         = 'nacastroc@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT','docs/**/*']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"	
  s.add_development_dependency 'logstash-devutils', '~> 1.3'
	s.add_runtime_dependency 'jdbc-sqlite3', '~> 3.15'
	s.add_runtime_dependency 'sequel', '~> 4.47'
	s.add_development_dependency 'logstash-filter-grok', '~> 3.4'
end
