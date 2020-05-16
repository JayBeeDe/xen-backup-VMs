#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys, os, re, time, traceback, json, socket, logging
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from progressbar import ProgressBar,Percentage,Bar,ETA
import XenAPI
from smb.SMBConnection import SMBConnection
import tempfile, smtplib, ssl
from email.MIMEText import MIMEText
if sys.version_info[0] == 2:
	from urlparse import urlparse
	from urlparse import urlunparse
	import ConfigParser
elif sys.version_info[0] >= 3:
	from urllib.parse import urlparse
	from urllib.parse import urlunparse
	import configparser as ConfigParser
else:
	print("At least Python version 2 is required to run this script!")
	sys.exit(1)
from pprint import pprint
from optparse import OptionParser
from optparse import OptionGroup

PROG="xen_backup_VMs"
VERSION="0.4"

##### DEFAULT CONFIGURATION
#CONF_CFG_PATH="/etc/"+PROG+".cfg"
settings = {
	"CONF_ACTION_MODE" : "Backup",
	"CONF_LOG_PATH" : "/var/log/"+PROG+".log",
	"CONF_CFG_PATH": "backup-test.cfg",
	"CONF_DRY_RUN": False,
	"CONF_DEBUG_RUN": False,
	"CONF_VERBOSE_RUN": False,
	"TARGET_HOST": "localhost",
	"TARGET_VMS": [],
	"BCK_LOCAL-OR-SMB_HOST": "LOCAL",
	"BCK_OUTPUT_DIR": "/opt/",
	"BCK_TIMESTAMP_DIR": False,
	"BCK_ROTATE_BACKUP": 0,
	"MAIL_ENABLE_REPORT": False,
	"MAIL_TO_ADDR": "me@contoso.com",
	"MAIL_FROM_ADDR": "postmaster@contoso.com",
	"MAIL_FROM_NAME": "postmaster",
	"MAIL_SMTP_SERVER": "smtp.contoso.com",
	"MAIL_SMTP_PORT": 25,
	"MAIL_USE_SSL": False,
	"MAIL_USE_TLS": False,
	"MAIL_SSL_LOGIN": "",
	"MAIL_SSL_PASSWORD": "",
	"MAIL_SEND_RETRIES": 3,
	"XEN_HOST_URL": "localhost",
	"XEN_HOST_PORT": 80,
	"XEN_EXPORT_FORMAT": "raw",
	"XEN_HOST_LOGIN": "root",
	"XEN_HOST_PASSWORD": "lolillop",
	"SMB_SERVER_DOMAIN": "WORKGROUP",
	"SMB_SERVER_NAME": "my-nice-smb",
	"SMB_SERVER_IP": "0.0.0.0",
	"SMB_SERVER_PORT": 445,
	"SMB_SERVER_SHARE": "/",
	"SMB_CLIENT_LOGIN": "",
	"SMB_CLIENT_PASSWORD": "",
	"SMB_CLIENT_NAME": "",
	"SMB_NTLM_V2": True,
	"SMB_DIRECT_TCP": True,
	"SMB_OUTPUT_DIR": "/default/share/"
}

##### functions

class CustomFormatter(logging.Formatter):
	FORMATS={
		logging.DEBUG: "\033[0;34;21m\033[24m"+"%(message)s"+"\033[1;37;0m",
		logging.INFO: "\033[0;32;21m\033[24m"+"%(message)s"+"\033[1;37;0m",
		logging.WARNING: "\033[1;33;21m\033[24m"+"%(message)s"+"\033[1;37;0m",
		logging.ERROR: "\033[1;31;21m\033[24m"+"%(message)s"+"\033[1;37;0m",
		logging.CRITICAL: "\033[1;31;21m\033[24m"+"%(message)s"+"\033[1;37;0m"
	}
	def format(self, record):
		formatter=logging.Formatter(self.FORMATS.get(record.levelno))
		return formatter.format(record)

def init_logger():
	#logger=logging.getLogger(PROG)
	logger=logging.RootLogger(logging.DEBUG)
	console_handler=logging.StreamHandler()
	console_handler.setLevel(logging.INFO)
	if settings["CONF_DRY_RUN"] or settings["CONF_VERBOSE_RUN"]:
		console_handler.setLevel(logging.INFO)
	if settings["CONF_DEBUG_RUN"]:
	 	console_handler.setLevel(logging.DEBUG)
	console_handler.setFormatter(CustomFormatter("%(message)s"))
	logger.addHandler(console_handler)
	file_handler=logging.FileHandler(settings["CONF_LOG_PATH"])
	file_handler.setLevel(logging.INFO)
	file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
	logger.addHandler(file_handler)
	if settings["MAIL_ENABLE_REPORT"]:
		mail_handler=logging.FileHandler(mailTmpFile)
		mail_handler.setLevel(logging.INFO)
		mail_handler.setFormatter(logging.Formatter("%(levelname)s\t\t%(message)s"))
		logger.addHandler(mail_handler)
	return logger

def auto_convert(str):
	if str.lower() == "true":
		return True
	elif str.lower() == "false":
		return False
	try:
		res=int(str)
		return res
	except ValueError as e:
		pass
	try:
		res=float(str)
		return res
	except ValueError as e:
		pass
	m=re.search("^\[\(.*\)\]$", str)
	if m is not None:
		return list(str.replace("[(","").replace(")]","").split("),("))
	return str

def process_settings(argv):
	#TODO
	CONF_CFG_PATH=settings["CONF_CFG_PATH"]
	settings_cli=parse_cli_options(argv)
	if settings_cli.CONF_CFG_PATH:
		CONF_CFG_PATH=settings_cli.CONF_CFG_PATH
	if not os.path.isfile("./"+CONF_CFG_PATH):
		if os.path.isfile(os.path.dirname(os.path.realpath(__file__))+"/"+CONF_CFG_PATH):
			CONF_CFG_PATH=os.path.dirname(os.path.realpath(__file__))+"/"+CONF_CFG_PATH
	settings_cfg=parse_ini_options(CONF_CFG_PATH)

	for section_ini in settings_cfg.sections():
		for setting_ini in settings_cfg.options(section_ini):
			settings[section_ini+"_"+setting_ini]=auto_convert(str(settings_cfg.get(section_ini, setting_ini)).replace('"',''))
			# Override default values by configuration file

	for key in settings_cli.__dict__:
		if hasattr(settings_cli, key) and getattr(settings_cli, key):
			if getattr(settings_cli, key)!=None and getattr(settings_cli, key)!="version":
				settings[key]=getattr(settings_cli, key)
				# Override configuration file by command line arguments

def parse_ini_options(ini_path):
	option=ConfigParser.ConfigParser()
	option.optionxform=str
	option.readfp(open(ini_path))
	return option

def parse_cli_options(argv):
	parser=OptionParser(
		description=u"VMs Backup & Restore",
		usage=u"%prog [--help] [options]")
	option_group_CONF=OptionGroup(
		parser, u"Configuration")
	option_group_CONF.add_option(
		"-c", "--config", dest="CONF_CFG_PATH",
		help=u"Use specific configuration file",
		action="store_true")
	option_group_CONF.add_option(
		"-a", "--action", dest="CONF_ACTION_MODE",
		help=u"Script mode : Backup or Restore",
		action="store_true")
	option_group_CONF.add_option(
		"-d", "--debug", dest="CONF_DEBUG_RUN",
		help=u"Display script debug actions",
		action="store_true")
	option_group_CONF.add_option(
		"-D", "--dry-run", dest="CONF_DRY_RUN",
		help=u"Doesn't do anything, just display what it would have done",
		action="store_true")
	option_group_CONF.add_option(
		"-v", "--verbose", dest="CONF_VERBOSE_RUN",
		help=u"Increase log verbosity", action="store_true")
	option_group_CONF.add_option(
		"-V", "--version", dest="version",
		help=u"Display "+PROG+" script version",
		action="store_true",
		default=False)
	parser.add_option_group(option_group_CONF)

	(option,args)=parser.parse_args()

	if option.version:
		print(PROG+"\t version "+VERSION)
		sys.exit(0)
	return option


class SmtpConn(object):
	def __init__(self, smtp_server="localhost", smtp_port=None, use_ssl=False, ssl_login="", ssl_password="", use_tls=False, send_retries=3, from_address=None, from_name=None):
		errorMsg="Connection to SMTP server failed (send retries reached): "
		errorMsg2="Connection to SMTP succeeded but SSL failed (send retries reached): "
		if not smtp_port:
			smtp_port=25
			if use_ssl:
				smtp_port=587
		if not use_ssl:
			use_tls=False

		logger.info("Establishing connexion to smtp server "+smtp_server+":"+str(smtp_port)+"...")
		smtp_connect_attempt=0
		smtp_error=errorMsg
		while smtp_connect_attempt < send_retries and smtp_error != "":
			smtp_connect_attempt+=1
			logger.debug("SMTP connection attempt "+str(smtp_connect_attempt)+"/"+str(send_retries)+"...")
			try:
				if use_ssl:
					session=smtplib.SMTP_SSL(smtp_server,smtp_port)
				else:
					session=smtplib.SMTP(smtp_server,smtp_port)
				smtp_error=""
			except Exception as e:
				logger.debug(str(e))
				smtp_error=errorMsg+str(e)
				time.sleep(5)
			if smtp_error == "" and use_ssl:
				smtp_error=errorMsg2
				logger.debug("SMTP SSL connection attempt "+str(smtp_connect_attempt)+"/"+str(send_retries)+"...")
				try:
					session.ehlo()
					if use_tls:
						session.starttls()
					#session.connect(smtp_server,smtp_port)
					session.login(ssl_login, ssl_password)
					smtp_error=""
				except Exception as e:
					logger.debug(str(e))
					smtp_error=errorMsg2+str(e)
					time.sleep(5)
		if smtp_error != "":
			logger.error(smtp_error)
			raise NameError(smtp_error)
		if use_ssl:
			self.ssl_login=ssl_login
			self.ssl_password=ssl_password
		else:			
			self.ssl_login=""
			self.ssl_password=""
		self.smtp_server=smtp_server
		self.smtp_port=smtp_port
		self.use_ssl=use_ssl
		self.use_tls=use_tls
		self.send_retries=send_retries
		self.from_address=from_address
		self.from_name=from_name
		self.session=session
		logger.info("SMTP connection OK!")

	def send_email(self, to, subject, bodyMsg):
		errorMsg="Sending email failed (send retries reached)!"

		msg=MIMEText(bodyMsg)
		msg["subject"]=subject
		msg["From"]=self.from_address
		msg["To"]=to

		smtp_send_attempt=0
		smtp_error=errorMsg
		while smtp_send_attempt < self.send_retries and smtp_error != "":
			smtp_send_attempt+=1
			logger.debug("SMTP email sending attempt "+str(smtp_send_attempt)+"/"+str(self.send_retries)+"...")
			try:
				self.session.sendmail(self.from_address, to.split(','), msg.as_string())
				smtp_error=""
			except socket.error as e:
				smtp_error=e
				logger.debug(smtp_error)
				time.sleep(5)
			except smtplib.SMTPException as e:
				smtp_error=str(e)
				logger.debug(smtp_error)
				time.sleep(5)
		if smtp_error != "":
			logger.error(smtp_error)
			logger.error(errorMsg)
			return 1
		else:
			logger.info("Email has been sent to "+to+ "!")
			return 0

	def generate_report(self, to_addr, subject, mailFile):
		bodyMsg=subject+"\n\n"
		try:
			bodyMsg+=open(mailFile, "r").read()
		except Exception as e:
			logger.error("Error while opening temporary mail file "+mailFile+"...")
			logger.error(e)
			return 1
		return self.send_email(to_addr, subject, bodyMsg)

	def __del__(self):
		self.session.quit()
		self.ssl_password=""

class SmbConn(object):
	def __init__(self, server_ip="localhost", server_port=445, server_name="", server_domain="WORKGROUP", client_login="root", client_password="root", server_share="/", client_name=socket.gethostname(), ntlm_v2=True, direct_tcp=True):
		logger.warning("Establishing connexion to SMB server "+client_login+"@"+server_ip+":"+str(server_port)+"/"+server_share+" in domain "+server_domain+"...")
		errorMsg="An error has occured during Samba connection. Script aborting..."
		errorMsg1="An error has occured while listing samba shares. Script aborting..."
		errorMsg2="The following share doesn't exist on the remote Samba server : "+server_share+"!"
		try:
			session=SMBConnection(client_login, client_password, client_name, server_name, domain=server_domain, use_ntlm_v2=ntlm_v2, is_direct_tcp=direct_tcp)
			assert session.connect(server_ip, server_port)
		except Exception as e:
			logger.error(e)
			logger.error(errorMsg)
			raise NameError(errorMsg)
		try:
			shares=session.listShares()
		except Exception as e:
			logger.error(e)
			logger.error(errorMsg1)
			raise NameError(errorMsg1)
		flagShareFound=False
		for share in shares:
			if server_share == share.name:
				flagShareFound=True
				break
		if flagShareFound == False:
			logger.error(errorMsg2)
			raise NameError(errorMsg2)
		self.server_ip=server_ip
		self.server_port=server_port
		self.server_name=server_name
		self.server_domain=server_domain
		self.client_login=client_login
		self.client_password=client_password
		self.server_share=server_share
		self.client_name=client_name
		self.ntlm_v2=ntlm_v2
		self.direct_tcp=direct_tcp
		self.session=session
		logger.info("SMB connection OK!")

	def generate_dirname(self):
		if settings["BCK_TIMESTAMP_DIR"]:
			outputDirSmb=os.path.abspath(settings["SMB_OUTPUT_DIR"]+"/"+timestamp)
		else:
			outputDirSmb=os.path.abspath(settings["SMB_OUTPUT_DIR"])
		errorMsg="An error has occured while creating directory "+outputDirSmb+" to remote SMB server!"
		res=self.create_subdir(outputDirSmb)
		if res != 0:
			logger.error(errorMsg)
			raise NameError(errorMsg)
		return outputDirSmb

	def create_subdir(self, path, depth=1):
		if depth >= len(path.split("/")):
			return 0
		currentPath="/".join(path.split("/")[:depth])
		if currentPath == "":
			currentPath="/"
		nextPath="/".join(path.split("/")[:depth+1])
		nextItem=("").join(path.split("/")[depth])
		try:
			subDirs=self.session.listPath(self.server_share, currentPath)
		except Exception as e:
			return 1
		itemFoundFlag=False
		for subDir in subDirs:
			if subDir.filename == nextItem and subDir.isDirectory:
				itemFoundFlag=True
				break
		if not itemFoundFlag:
			try:
				self.session.createDirectory(self.server_share, nextPath)
			except Exception as e:
				return 1
			logger.info("(Sub)Directory "+nextPath+" has been created on remote SMB server!")
		else:
			logger.debug("(Sub)Directory "+nextPath+" already exists on remote SMB server!")
		return self.create_subdir(path, depth+1)

	def smb_action(self,srcPath,dstPath,action="upload"):
		if action == "upload":
			try:
				f=open(srcPath,"rb")
				self.session.storeFile(self.server_share, dstPath, f)
				f.close()
			except Exception as e:
				try:
					f.close()
				except Exception as e:
					pass
				logger.error("An error has occured while uploading the file to the Samba Share!")
				logger.error(e)
				return 1
			try:
				actual_size=self.session.getAttributes(self.server_share, dstPath).file_size
			except Exception as e:
				logger.error("An error has occured while checking file into the Samba Share!")
				logger.error(e)
				return 1
			expected_size=os.path.getsize(srcPath)
			if actual_size != expected_size:
				logger.error("An error has occured while uploading the file to the Samba Share: expected size is "+expected_size+" / actual size "+actual_size)
				return 1


			#compare hashs
			#remove from current directory
		return 0

	def __del__(self):
		self.session.close()
		self.client_password=""

class XenConn(object):
	def __init__(self, url, port, username, password):
		errorMsg="An error has occured during Xen connection. Script aborting..."
		url=url_abs_path(url)
		logger.info("Establishing connexion to xen server "+username+"@"+url+":"+str(port)+"...")
		try:
			session=XenAPI.Session(url+":"+str(port))
			session.xenapi.login_with_password(username, password)
		except Exception as e:
			if hasattr(e, "details") and e.details[0] == "HOST_IS_SLAVE":
				# Redirect to cluster master
				url=urlparse(url).scheme + "://" + e.details[1]
				try:
					session=XenAPI.Session(url)
					session.login_with_password(username, password)
				except Exception as e:
					logger.error(e)
					logger.error(errorMsg)
					raise NameError(errorMsg)
			else:
				logger.error(e)
				logger.error(errorMsg)
				raise NameError(errorMsg)
		self.url=url
		self.port=port
		self.session=session
		self.username=username
		self.password=password
		logger.info("XEN connection OK!")

	def name2uuid(self, name):
		vms=self.session.xenapi.VM.get_by_name_label(name)
		vmref=[x for x in self.session.xenapi.VM.get_by_name_label(name) if not self.session.xenapi.VM.get_is_a_snapshot(x)]
		if len(vmref) > 1:
			logger.error("Several VMs whose name is "+name+" exist... Skipping")
		elif len(vms) < 1:
			logger.error("VM "+name+" doesn't exist... Skipping")
		else:
			uuid=self.session.xenapi.VM.get_record(vms[0])["uuid"]
			return uuid
		return None

	def name2ref(self, name):
		return self.session.xenapi.VM.get_by_name_label(name)[0]

	def create_snapshot(self, ref, name):
		snapshot=self.session.xenapi.VM.snapshot(ref, name)
		self.session.xenapi.VM.set_is_a_template(snapshot, False)
		if settings["CONF_DEBUG_RUN"]:
			with open(outputDir+"/metadata", "w") as f:
				json.dump(self.session.xenapi.VM.get_record(ref), f, indent=2, default=unicode)
		return snapshot

	def remove_snapshot(self, snapshot):
		if snapshot:
			snapshot_details=self.session.xenapi.VM.get_record(snapshot)
			# Loop through all the VBDs
			for vbd_ref in snapshot_details["VBDs"]:
				# Each VDB contains a VDI and also has to be destroyed
				vbd_records=self.session.xenapi.VBD.get_record(vbd_ref)
				vdi_ref=self.session.xenapi.VBD.get_VDI(vbd_ref)
				try:
					self.session.xenapi.VDI.destroy(vdi_ref)
				except Exception as e:
					pass
				try:
					self.session.xenapi.VBD.destroy(vbd_ref)
				except Exception as e:
					pass
			try:   
				self.session.xenapi.VM.destroy(snapshot)
				return 0
			except Exception as e:
				logger.error("Snapshot could not be removed on the xen server!")
				return 1
		else:
			return 1

	def generate_url(self, snapshot):
		return url_abs_path(self.url+":"+str(self.port)+"/export?ref="+snapshot+"&session_id="+self.session.handle)

	def __del__(self):
		self.session.xenapi.session.logout()
		self.password=""

def url_abs_path(url):
	parsed=list(urlparse(url))
	parsed[2]=re.sub("/{2,}", "/", parsed[2])
	return re.sub(r"\/$", "", urlunparse(parsed))

def generate_timestamp():
	return time.strftime("%Y-%m-%d-%H%M%S")

def generate_filename(name):
	return "Snapshot-VM-"+name+"-"+timestamp+".xva"

def generate_dirname():
	if settings["BCK_TIMESTAMP_DIR"]:
		outputDir=os.path.abspath(settings["BCK_OUTPUT_DIR"]+"/"+timestamp)
	else:
		outputDir=os.path.abspath(settings["BCK_OUTPUT_DIR"])
	if not os.path.exists(outputDir):
		logger.info("Directory "+outputDir+" has been created!")
		os.makedirs(outputDir)
	return outputDir

def http_action(srcPath,dstPath,action="download"):
	block_size=1
	headers={
		"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36",
		'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language' : 'en-US,en;q=0.5',
		'Accept-Encoding' : 'gzip',
		'DNT' : '1',
		'Connection' : 'close'
	} 
	if action == "download":
		r=requests.get(srcPath, stream=True, verify=True, headers=headers)
		expected_size=int(r.headers.get("Content-Length", 0))
		if expected_size == 0:
			logger.warning("Unknown expected size... Unable to calculate remaining download time! Anyway, still downloading... Wait as long as it takes!")
		else:
			pbar=ProgressBar(widgets=[Percentage()," ", Bar()," ", ETA()], maxval=expected_size)
		try:
			with open(dstPath, "wb") as f:
				if expected_size > 0:
					pbar.start()
				status=0
				data=None
				for data in r.iter_content(chunk_size=block_size):
					status=status+block_size
					if not data: # filter out keep-alive new chunks
						continue
					if expected_size > 0:
						pbar.update(status)
					f.write(data)
					f.flush()
				if expected_size > 0:
					pbar.finish()
			actual_size=r.raw.tell()
			if expected_size > 0:
				if actual_size != expected_size:
					logger.error("An error has occured while downloading the file: expected size is "+str(expected_size)+" / actual size "+str(actual_size))
					return 1
			else:
				logger.info("Download has finished: size is "+str(actual_size))
		except Exception as e:
			logger.error("An error has occured while downloading the file...")
			logger.error(e)
			if expected_size > 0:
				try:
					pbar.finish()
				except Exception as e:
					pass
			# try to clean up a potentially incomplete backup
			try:
				os.unlink(dstPath)
			except Exception as e:
				pass
			logger.debug("Download HTTP Headers are "+str(r.headers))
			return 1
		if r.status_code != 200:
			logger.error("Download was not successfull due to HTTP error (HTTP Status Code is "+str(r.status_code)+")")
			return 1
	return 0

def remove_item(item, bypass=False):
	errorMsg="Error while trying to remove "+item
	if os.path.exists(item):
		if os.path.isdir(item) and bypass == False:
			if not os.listdir(item):
				try:
					os.rmdir(item)
					logger.info("Directory "+item+" has been removed!")
					return 0
				except Exception as e:
					logger.error(errorMsg+"...")
					logger.error(e)
			else:
				logger.error(errorMsg+" : directory is not empty!")
		elif os.path.isfile(item) or (os.path.isdir(item) and bypass == True):
			try:
				os.remove(item)
				if bypass == False:
					logger.info("File "+item+" has been removed!")
				return 0
			except Exception as e:
				if bypass == False:
					logger.error(errorMsg+"...")
					logger.error(e)
	else:
		logger.error(errorMsg+" : doesn't exist!")
	return 1
	#if item is directory if empty remove
	#if item is file remove file if exists

def main(argv):
	global logger
	global timestamp
	global mailTmpFile
	global outputDir
	global outputDirSmb
	flag_errors=False
	#process settings overriding and initialize logger
	process_settings(argv)

	if settings["MAIL_ENABLE_REPORT"]:
		mailTmpFile=tempfile.mktemp()
	logger=init_logger()
	timestamp=generate_timestamp()
	logger.info("The script "+PROG+" is starting in mode Python version "+str(sys.version_info[0])+" for a "+settings["CONF_ACTION_MODE"]+" action!")
	if settings["MAIL_ENABLE_REPORT"]:
		logger.debug("Mail report is enable and stored temporarily into "+mailTmpFile)
	if settings["CONF_DRY_RUN"]:
		logger.warning("Dry Run Mode Enabled!")

	if settings["MAIL_ENABLE_REPORT"]:
		smtp_conn_obj=SmtpConn(settings["MAIL_SMTP_SERVER"], settings["MAIL_SMTP_PORT"], settings["MAIL_USE_SSL"], settings["MAIL_SSL_LOGIN"], settings["MAIL_SSL_PASSWORD"], settings["MAIL_USE_TLS"], settings["MAIL_SEND_RETRIES"], settings["MAIL_FROM_ADDR"], settings["MAIL_FROM_NAME"])

	xen_conn_obj=XenConn(settings["XEN_HOST_URL"]+"/", settings["XEN_HOST_PORT"], settings["XEN_HOST_LOGIN"], settings["XEN_HOST_PASSWORD"])

	outputDir=generate_dirname()
	if settings["BCK_LOCAL-OR-SMB_HOST"] == "SMB":
		smb_conn_obj=SmbConn(settings["SMB_SERVER_IP"], settings["SMB_SERVER_PORT"], settings["SMB_SERVER_NAME"], settings["SMB_SERVER_DOMAIN"], settings["SMB_CLIENT_LOGIN"], settings["SMB_CLIENT_PASSWORD"], settings["SMB_SERVER_SHARE"], settings["SMB_CLIENT_NAME"], settings["SMB_NTLM_V2"], settings["SMB_DIRECT_TCP"])
		outputDirSmb=smb_conn_obj.generate_dirname()
		logger.warning("Temporary output directory for backup is "+outputDir+"!")
		logger.warning("Output directory for backup is smb://"+settings["SMB_CLIENT_LOGIN"]+"@"+settings["SMB_SERVER_IP"]+":"+outputDirSmb+"!")
	else:
		logger.warning("Output directory for backup is "+outputDir+"!")

	for vmname in settings["BCK_TARGET_VMS"]:
		outputFile=generate_filename(vmname)
		outputPath=outputDir+"/"+outputFile
		logger.debug("Output Path is "+outputPath)

		uuid=xen_conn_obj.name2uuid(vmname)
		logger.debug("VM UUID is "+uuid)
		ref=xen_conn_obj.name2ref(vmname)
		logger.debug("VM ref is "+ref)
		if uuid == None:
			logger.error("VM "+vmname+" doesn't exist on xen cluster...Skipping")
			flag_errors=True
		else:
			logger.info("Creating snapshot for VM "+vmname+"...")
			snapshot=xen_conn_obj.create_snapshot(ref, outputFile)

			url=xen_conn_obj.generate_url(snapshot)
			logger.warning("Downloading snapshot from "+url+" to "+outputPath+"...")
			res_http=http_action(url,outputPath,action="download")

			res_rmv=0
			if res_http == 0:
				logger.info("Cleaning snapshot...")
				res_rmv=xen_conn_obj.remove_snapshot(snapshot)

			res_smb=0
			res_smb2=0
			res_rmsmb=0
			res_rmsmb2=0
			if res_http == 0 and settings["BCK_LOCAL-OR-SMB_HOST"] == "SMB":
				outputPathSmb=outputDirSmb+"/"+outputFile
				logger.warning("Uploading snapshot from "+outputPath+" to "+outputPathSmb+" on samba server...")
				res_smb=smb_conn_obj.smb_action(outputPath,outputPathSmb,action="upload")
				if settings["CONF_DEBUG_RUN"]:
					res_smb2=smb_conn_obj.smb_action(outputDir+"/metadata",outputDirSmb+"/metadata",action="upload")
				
				if res_smb == 0:
					logger.warning("Cleaning local export...")
					res_rmsmb=remove_item(outputPath)
				if settings["CONF_DEBUG_RUN"]:
					if res_smb2 == 0:
						res_rmsmb2=remove_item(outputDir+"/metadata")

			if (res_http != 0 or res_rmv != 0 or res_smb != 0 or res_smb2 != 0 or res_rmsmb != 0 or res_rmsmb2 != 0):
				flag_errors=True

	logger.warning("Cleaning all connections...")
	del xen_conn_obj
	if settings["BCK_LOCAL-OR-SMB_HOST"] == "SMB":
		del smb_conn_obj
		logger.warning("Cleaning local export directory...")
		res=remove_item(outputDir)
		if res != 0:
			flag_errors=True

	if flag_errors:
		summaryMsg="The script "+PROG+" has run with some errors!"
		logger.warning(summaryMsg)
	else:
		summaryMsg="The script "+PROG+" has successfully run!"
		logger.info(summaryMsg)

	if settings["MAIL_ENABLE_REPORT"]:
		logger.warning("Generating and sending report to "+settings["MAIL_TO_ADDR"]+"...")
		smtp_conn_obj.generate_report(settings["MAIL_TO_ADDR"], summaryMsg, mailTmpFile)
		remove_item(mailTmpFile,bypass=True)

if __name__ == "__main__":
	main(sys.argv[1:])