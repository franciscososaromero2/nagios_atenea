#!/usr/bin/python  
import os
import requests
import simplejson as json
import urllib3
import requests.packages.urllib3
import types
requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings()
from requests.auth import HTTPBasicAuth
import ConfigParser
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import time
from daemon import runner
import yaml


config = ConfigParser.RawConfigParser()
config.read('/MONITORIZACION/uti/nagios_atenea/config.properties')

nagios_username=config.get("nagios", "nagios_username")
nagios_password=config.get("nagios", "nagios_password")
nagios_url_api=config.get("nagios","nagios_url_api")
nagios_server=config.get("nagios","nagios_server")
nagios_url_service=config.get("nagios","nagios_url_service")
nagios_list_servers=config.get("nagios","list_servers")
nagios_scale=config.get("nagios","nagios_scale")


namespace=config.get("sigma","namespace")
platform=config.get("sigma","platform")  
semaas_endpoint=config.get("sigma","semaas_endpoint")
semaas_endpoint_email=config.get("sigma","semaas_endpoint_email")
semaas_cert=config.get("sigma","semaas_cert")
semaas_key=config.get("sigma","semaas_key")
interval_check=config.get("sigma","interval_check")
log_registry=config.get("sigma","log_registry")

def import_alerts_nagios():
	#get alerts from nagios   


	data = requests.get(nagios_url_api, verify=False, auth=HTTPBasicAuth(nagios_username, nagios_password))

	binary = data.content
	parsed_json = json.loads(binary)

	#print parsed_json

	items_data = len(parsed_json["data"]["servicelist"])
	alerts_detail = parsed_json["data"]["servicelist"]
	#print "Numero de alertas:"+str(items_data)

	for hostname in alerts_detail:
		for services in alerts_detail[hostname]:

			with open(nagios_list_servers, 'r') as stream:
				tuple=(yaml.safe_load(stream))

			#validate alerts status 
			if parsed_json["data"]["servicelist"][hostname][services]["scheduled_downtime_depth"] == 0 and parsed_json["data"]["servicelist"][hostname][services]["state_type"] == "hard" and  parsed_json["data"]["servicelist"][hostname][services]["notifications_enabled"] == True and hostname in tuple:			      
  				logger.info("Hostname:"+hostname+" in list servers. ")
				#hostname_format = hostname.split('.')[0]
				hostname_format = hostname
				services_format = services.replace(" ", "_")
				alert_state =  parsed_json["data"]["servicelist"][hostname][services]["status"]
				alert_description = parsed_json["data"]["servicelist"][hostname][services]["description"]
				alert_output = parsed_json["data"]["servicelist"][hostname][services]["plugin_output"]
				url_data_service = "http://"+nagios_server+"/nagios/cgi-bin/objectjson.cgi?query=service&hostname="+hostname+"&servicedescription="+services
				data_conf_service = requests.get(url_data_service, verify=False, auth=HTTPBasicAuth(nagios_username, nagios_password))
				parsed_json2 = json.loads(data_conf_service.content)
				service_contact = parsed_json2["data"]["service"]["contacts"][0]
				#Get mail_contact  
				url_data_contact=config.get("nagios", "nagios_url_contact")
				data_conf_contact=requests.get(url_data_contact+service_contact, verify=False, auth=HTTPBasicAuth(nagios_username, nagios_password))
				parsed_json_contact = json.loads(data_conf_contact.content)
				email_contact = parsed_json_contact["data"]["contact"]["email"]
				#email_contact = "francisco.sosa2.next@bbva.com"
				id_service=hostname_format+"_"+services_format
				alert_object = { id_service : {"status" : alert_state,"alert_description" : alert_description, "alert_output":alert_output,"contact": email_contact }} 
				alert_object
	
				#Insert alerts info to Semaas. 
				#Monitored Resource Type 
				semaas_data={ "_id": id_service, "description": alert_description, "sourceOf":["TRACES", "LOGS", "METRICS", "ALARMS"]}
				semaas_data_json = json.dumps(semaas_data)	
				url_semaas_mrtype=str("https://"+semaas_endpoint+"/v0/ns/"+namespace+"/mr-types")
				semaas_data_mrtype=requests.post(url_semaas_mrtype,cert=(semaas_cert,semaas_key),verify=False,data=semaas_data_json)
                                logger.info("Insert Monitored Resource Type. Status Code "+str(semaas_data_mrtype.status_code))
				logger.info("Insert Monitored Resource Type."+str(semaas_data_mrtype.content))
				
				#Monitored resource 
				semaas_data={"_id": id_service, "mrType": "//mr."+platform+"/ns/"+namespace+"/mr-types/"+id_service}
				semaas_data_json = json.dumps(semaas_data)
				url_semaas_mrs=str("https://"+semaas_endpoint+"/v0/ns/"+namespace+"/mrs")
			        semaas_data_mrs=requests.post(url_semaas_mrs,cert=(semaas_cert,semaas_key),verify=False,data=semaas_data_json)
                                logger.info("Insert Monitored Resource.Status Code "+str(semaas_data_mrs.status_code))
                                logger.info("Insert Monitored Resource."+str(semaas_data_mrs.content))
	
				#Alarm Receiver
				#semaas_data={"_id": id_service, "kind": "SUPPORT_LEVEL1", "config": {"mail": email_contact}}
				semaas_data={"_id": id_service, "kind": "SUPPORT_LEVEL1"}
				semaas_data_json = json.dumps(semaas_data)
				url_semaas_alarmr=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarm-receivers")
				semaas_data_alarm_r=requests.post(url_semaas_alarmr,cert=(semaas_cert,semaas_key),verify=False,data=semaas_data_json)
                                logger.info("Insert alarm receiver. Status Code "+str(semaas_data_alarm_r.status_code))
                                logger.info("Insert alarm receiver."+str(semaas_data_alarm_r.content))

				#Alarm type
				semaas_data={"_id": id_service, "statusFrequency": 0, "propertiesSpec":\
				{"description": alert_description, "group": service_contact }, "notificationPolicies": \
				[{"stateChangesOnly": True, "alarmReceiver": "//sigma."+platform+"/ns/"+namespace+"/alarm-receivers/"+id_service}]}
				semaas_data_json = json.dumps(semaas_data)
                       		url_semaas_alarm_t=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarm-types")
       		                semaas_data_alarm_t=requests.post(url_semaas_alarm_t,cert=(semaas_cert,semaas_key),verify=False,data=semaas_data_json)
                                logger.info("Insert alarm type. Status Code "+str(semaas_data_alarm_t.status_code))
                                logger.info("Insert alarm type."+str(semaas_data_alarm_t.content))	
		      		
				#Get phone contact 
				with open(nagios_scale, 'r') as stream:
				        dict1=(yaml.safe_load(stream))
				        dictionary=dict1["contacts"]
        				for x in dictionary:
                				if service_contact in x:
                       					 phone_contact=x[service_contact]

				 
				#creating alarm
				semaas_data={"_id": id_service, "alarmType": "//sigma."+platform+"/ns/"+namespace+"/alarm-types/"+id_service, \
 				"enabled": True, "monitoredResource": "//mr."+platform+"/ns/"+namespace+"/mrs/"+id_service,\
				"properties": {"description": alert_description, "group": service_contact,"supportEmail": email_contact,"supportPhone": str(phone_contact) }}
				semaas_data_json = json.dumps(semaas_data)
				url_semaas_alarms=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarms")
              	         	semaas_data_alarms=requests.post(url_semaas_alarms,cert=(semaas_cert,semaas_key),verify=False,data=semaas_data_json)
                                logger.info("Insert alarm.Status Code "+str(semaas_data_alarms.status_code))
                                logger.info("Insert alarm."+str(semaas_data_alarms.content))
 
				#Alarm Status  
				status_alarm=alert_state.upper()
				semaas_data={"status": status_alarm, "reason": alert_output}
				semaas_data_json = json.dumps(semaas_data)
                	        url_semaas_alarm_status=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarms/"+id_service+":setStatus")
                        	semaas_data_alarm_status=requests.post(url_semaas_alarm_status,cert=(semaas_cert,semaas_key),verify=False,data=semaas_data_json)
                                logger.info("Insert alarm State.Status Code:"+str(semaas_data_alarm_status.status_code))
                                logger.info("Insert alarm State."+str(semaas_data_alarm_status.content))







def delete_alerts(id_service_delete):

	#Delete alarms 
	url_semaas_alarms=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarms/")
	semaas_data_alarms_delete=requests.delete(url_semaas_alarms+id_service_delete,cert=(semaas_cert,semaas_key),verify=False)
        logger.info("Delete alarm.Status Code:"+str(semaas_data_alarms_delete.status_code))
        logger.info("Delete alarm."+str(semaas_data_alarms_delete.content))
	

	#Delete alarm types  
        url_semaas_alarms_types=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarm-types/")	
	semaas_data_alarm_type_delete=requests.delete(url_semaas_alarms_types+id_service_delete,cert=(semaas_cert,semaas_key),verify=False)
        logger.info("Delete alarm Type.Status Code:"+str(semaas_data_alarm_type_delete.status_code))
        logger.info("Delete alarm Type."+str(semaas_data_alarm_type_delete.content))
	
	#Delete alarm receiver
        url_semaas_alarm_receiver=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarm-receivers/")
        semaas_data_alarm_receiver_delete=requests.delete(url_semaas_alarm_receiver+id_service_delete,cert=(semaas_cert,semaas_key),verify=False)
        logger.info("Delete alarm Receiver.Status Code:"+str(semaas_data_alarm_receiver_delete.status_code))
        logger.info("Delete alarm Receiver."+str(semaas_data_alarm_receiver_delete.content))

	
	#Delete Monitored resource
	url_semaas_monitored_resource=str("https://"+semaas_endpoint+"/v0/ns/"+namespace+"/mrs/")
	semaas_data_mrs_delete=requests.delete(url_semaas_monitored_resource+id_service_delete,cert=(semaas_cert,semaas_key),verify=False)
	logger.info("Delete Monitored Resource.Status Code:"+str(semaas_data_mrs_delete.status_code))
        logger.info("Delete Monitored Resource."+str(semaas_data_mrs_delete.content))

	#Delete Monitored Resource Type  
        url_semaas_mrtype=str("https://"+semaas_endpoint+"/v0/ns/"+namespace+"/mr-types/")	
	semaas_data_mr_type_delete=requests.delete(url_semaas_mrtype+id_service_delete,cert=(semaas_cert,semaas_key),verify=False)
        logger.info("Delete Monitored Resource Type.Status Code:"+str(semaas_data_mr_type_delete.status_code))
        logger.info("Delete Monitored Resource."+str(semaas_data_mr_type_delete.content))

def delete_and_recovery_alerts():
	#Delete recovery alerts.
	#Get alarms inside Sigma
	url_semaas_alarms=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarms")
	semaas_data_alarms_get=requests.get(url_semaas_alarms,cert=(semaas_cert,semaas_key),verify=False)
	parsed_data_alarms_json = json.loads(semaas_data_alarms_get.content)

	sigma_alarms=parsed_data_alarms_json["alarms"]

	for alerts in sigma_alarms: 
		host_and_alert=alerts["_locator"].split('/')[6]
		host_alert_list=host_and_alert.split('_',1)
		sigma_host_alert=host_alert_list[0]
		sigma_service_alert=host_alert_list[1]
		sigma_service_alert_ok=sigma_service_alert.replace('_','+')
		sigma_status_servicef=alerts["status"]
		sigma_status_service=sigma_status_servicef.lower()
		#print sigma_host_alert 
		#print sigma_service_alert
		#print sigma_status_service
		#Get Service Status on API Nagios 

		nagios_service_url_status=nagios_url_service+"service&hostname="+sigma_host_alert+"&servicedescription="+sigma_service_alert_ok+"&details=true&formatoptions=enumerate"
		data_alert = requests.get(nagios_service_url_status, verify=False, auth=HTTPBasicAuth(nagios_username, nagios_password))
		#print data_alert.status_code
	        
		binary = data_alert.content
	        parsed_json_service_alert = json.loads(binary)
		#print parsed_json_service_alert
	        validate_service=parsed_json_service_alert["result"]["type_code"]
		if validate_service == 0:	
			parsed_json_service_alert_status = parsed_json_service_alert["data"]["service"]["status"]
			#print parsed_json_service_alert_status
			parsed_json_service_alert_downtime = parsed_json_service_alert["data"]["service"]["scheduled_downtime_depth"]
			parsed_json_service_alert_enable =  parsed_json_service_alert["data"]["service"]["notifications_enabled"]
			parsed_json_service_alert_output = parsed_json_service_alert["data"]["service"]["plugin_output"] 
		else: 
			nagios_service_url_status_alt=nagios_url_service+"service&hostname="+sigma_host_alert+"&servicedescription="+sigma_service_alert+"&details=true&formatoptions=enumerate"
			
                	data_alert = requests.get(nagios_service_url_status_alt, verify=False, auth=HTTPBasicAuth(nagios_username, nagios_password))
			binary = data_alert.content
                        parsed_json_service_alert = json.loads(binary)
			parsed_json_service_alert_status = parsed_json_service_alert["data"]["service"]["status"]
                        parsed_json_service_alert_downtime = parsed_json_service_alert["data"]["service"]["scheduled_downtime_depth"]
                        parsed_json_service_alert_enable =  parsed_json_service_alert["data"]["service"]["notifications_enabled"]
                        parsed_json_service_alert_output = parsed_json_service_alert["data"]["service"]["plugin_output"]
			


		def update_state(id_service_nagios,id_service_state):
		         #Alarm Status
			 alarm_status_format=parsed_json_service_alert_status.upper()
   			 semaas_data={"status": alarm_status_format, "reason": parsed_json_service_alert_output}
		         semaas_data_json = json.dumps(semaas_data)
		         url_semaas_alarm_status=str("https://"+semaas_endpoint_email+"/v0/ns/"+namespace+"/alarms/"+id_service_nagios+":setStatus")
		         semaas_data_alarm_status=requests.post(url_semaas_alarm_status,cert=(semaas_cert,semaas_key),verify=False,data=semaas_data_json)
		         logger.info("Update Alarm Status. Status Code:"+str(semaas_data_alarm_status.status_code))
		         logger.info("Update alarm Status."+str(semaas_data_alarm_status.content))


		if parsed_json_service_alert_downtime >= 1 or parsed_json_service_alert_enable == False:
		
			logger.info("Delete Service: "+str(host_and_alert))
			delete_alerts(host_and_alert)

		elif parsed_json_service_alert_status == "ok":
			logger.info("Send Recovery to sigma and delete alerts: "+str(host_and_alert))
			update_state(host_and_alert,parsed_json_service_alert_status)
			delete_alerts(host_and_alert)
		elif parsed_json_service_alert_status == "critical":
			if parsed_json_service_alert_downtime == 0 and parsed_json_service_alert_enable == True:
				logger.info("Send State to sigma alert: "+str(host_and_alert))
				update_state(host_and_alert,parsed_json_service_alert_status)
		elif parsed_json_service_alert_status == "warning":
			if parsed_json_service_alert_downtime == 0 and parsed_json_service_alert_enable == True: 
        	                logger.info("Send State to sigma alert: "+str(host_and_alert))
 	 			update_state(host_and_alert,parsed_json_service_alert_status)
		else:
				logger.warning("Service does not match with conditionals "+str(host_and_alert))



#Definicion del demonio para monitorizar cambios en los archivos.

class App():
   def __init__(self):
      self.stdin_path      = '/dev/null'
      self.stdout_path     = '/dev/tty'
      self.stderr_path     = '/dev/tty'
      self.pidfile_path    =  '/var/run/nagios_atenea.pid'
      self.pidfile_timeout = 5

   def run(self):
      i = 0
      while True:
	import_alerts_nagios()
        delete_and_recovery_alerts()

        time.sleep(float(interval_check))

if __name__ == '__main__':
	app = App()
	logger = logging.getLogger("Atenea_Nagios")
	logger.setLevel(logging.INFO)
  	formatter = logging.Formatter("%(asctime)s - %(name)s - %(message)s")
  	#handler = logging.FileHandler("/MONITORIZACION/uti/nagios_atenea/logs/atenea_nagios.log")
	handler = RotatingFileHandler(log_registry, maxBytes=20,backupCount=5)
  	handler.setFormatter(formatter)
  	logger.addHandler(handler)
   
  	serv = runner.DaemonRunner(app)
   	serv.daemon_context.files_preserve=[handler.stream]
   	serv.do_action()
