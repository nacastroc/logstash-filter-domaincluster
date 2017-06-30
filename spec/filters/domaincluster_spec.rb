# encoding: utf-8
require_relative '../spec_helper'

LogStash::Environment::LOGSTASH_HOME = `gem which logstash-core`
module LogStash::Environment
  unless self.method_defined?(:pattern_path)
    def pattern_path(path)
      ::File.join(LOGSTASH_HOME, "patterns", path)
    end
  end
end

require "logstash/filters/domaincluster"
require "logstash/filters/grok"

describe LogStash::Filters::Domaincluster do   
  describe "Test plugin configuration" do
    let(:config) do <<-CONFIG
      filter {
        grok {
            match => { "message" => '%{NUMBER:fecha}%{SPACE}%{NUMBER:duracion} %{IP:ip_origen} %{WORD:tipo_conexion}/%{NUMBER:codigo_estado_http} %{NUMBER:bytes} %{WORD:metodo_http} (%{URIPROTO:protocolo}(://))?%{IPORHOST:dominio}(:%{NUMBER:puerto})?(%{NOTSPACE:recurso})? %{USERNAME:usuario} %{NOTSPACE:codigo_jerarquia}/%{NOTSPACE:ip_destino} %{GREEDYDATA:tipo_contenido}' }
        }
        domaincluster {
          source => "dominio"
          database => "testdb.sqlite"
        }
      }
    CONFIG
    end        
    
    sample("message" => "1467296673.866    216 10.53.12.227 TCP_MISS/200 770 GET www.facebook.com usuario10 HIER_DIRECT/52.16.160.11 text/html") do
      # Test that source field is obtained correctly
      expect(subject.get("dominio")).to eq('www.facebook.com')      
      # Test that source field is classified correctly
      expect(subject.get("domaincluster")).to eq('Social Network')
    end
  end
end

