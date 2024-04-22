I want to say thank for your answering. it's my Logstash.conf file.
input {
  beats {
    port => 5400
  }
}

filter {

  #-------------------------------------NGINX-----------------------------------------
  if [log][file][path] =~ "nginx/access.log" {
    grok {
      match => {
        "message" => '%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response:int} %{NUMBER:bytes:int}(?: \"%{DATA:referrer}\" \"%{DATA:agent}\")?'
      }
    }
    mutate {
      add_field => { "[@metadata][index]" => "filebeat-response-%{+YYYY.MM.dd}" }
    }
  }
  #----------------------------------IIS-----------------------------------------------
  if  [log][file][path] =~ "W3SVC1*" {

   grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:log_timestamp} %{TIMESTAMP_ISO8601:log_time} %{WORD:S-SiteName} %{NOTSPACE:S-ComputerName} %{IPORHOST:S-IP} %{WORD:CS-Method} %{URIPATH:CS-URI-Stem} %{URIPATH:CS-URI-Query} %{NUMBER:S-Port} %{NOTSPACE:CS-Username} %{WORD:c-ip} %{NOTSPACE:CS-Version} %{NOTSPACE:CS-UserAgent} %{NOTSPACE:CS-Cookie} %{NOTSPACE:CS-Referer} %{NOTSPACE:CS-Host} %{NUMBER:SC-Status} %{NUMBER:SC-SubStatus} %{NUMBER:SC-Win32-Status} %{NUMBER:SC-Bytes} %{NUMBER:CS-Bytes} %{NUMBER:Time-Taken}"}
 }


mutate {add_field => { "[@metadata][index]" => "filebeat-hresponse-%{+YYYY.MM.dd}" } }

    }



 if  [log][file][path] =~ "HTTPERR*" {
    grok { }

mutate {add_field => { "[@metadata][index]" => "filebeat-erriisesponse-%{+YYYY.MM.dd}" } }

}


I installed Filebeat on my windows for sending my IIS log into Logstash with those configs

# ============================== Filebeat inputs ===============================

filebeat.inputs:

# Each - is an input. Most options can be set at the input level, so
# you can use different inputs for various configurations.
# Below are the input-specific configurations.

# filestream is an input for collecting log messages from files.
- type: log

  document_type: iis
  # Unique ID among all inputs, an ID is required.
  id: my-filestream-id

  # Change to true to enable this input configuration.
  enabled: true

  # Paths that should be crawled and fetched. Glob based paths.
  paths:
    #- /var/log/*.log
    #- c:\programdata\elasticsearch\logs\*
    - c:\inetpub\logs\LogFiles\W3SVC1\*
	
	
# ------------------------------ Logstash Output -------------------------------	
	
	output.logstash:
  # The Logstash hosts
  hosts: ["127.0.0.1:5400"]

  # Optional SSL. By default is off.
  # List of root certificates for HTTPS server verifications
  #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]

  # Certificate for SSL client authentication
  #ssl.certificate: "/etc/pki/client/cert.pem"
  # Client Certificate Key
  #ssl.key: "/etc/pki/client/cert.key"






    #------------------------------------END---------------------------------------------
}




2024-04-02 07:04:02 W3SVC1 EVTSP-MYVIIS-02 172.168.192.15 POST /api/v1/InVoiceStuffsFav/GetGroupStuffList 80 172.168.192.16 HTTP/1.0 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:124.0)+Gecko/20100101+Firefox/124.0 https://my.evptsp.com/productList my.evptsp.com 200 0 0 184 708 35
Finally, I sent my IIS log by this pattern into Elasticsearch. I noticed that I had to test my pattern in grok debugger that is located in Kibana(Management>Dev Tools>Grok Debugger).
%{TIMESTAMP_ISO8601:log_timestamp} %{WORD:S-SiteName} %{NOTSPACE:S-ComputerName} %{IPORHOST:S-IP} %{WORD:CS-Method} %{URIPATH:CS-URI-Stem} %{NUMBER:S-Port} %{IPORHOST:c-ip} %{NOTSPACE:CS-Version} %{NOTSPACE:CS-UserAgent} %{NOTSPACE:CS-Referer} %{NOTSPACE:CS-Host} %{NUMBER:SC-Status} %{NUMBER:SC-SubStatus} %{NUMBER:SC-Win32-Status} %{NUMBER:SC-Bytes} %{NUMBER:CS-Bytes} %{NUMBER:Time-Taken}

