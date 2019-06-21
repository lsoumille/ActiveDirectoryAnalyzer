#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
import json

class ActiveDirectoryAnalyzer(Analyzer):

	#Handle configuration file options
	def __init__(self):
		Analyzer.__init__(self)
		self.ad_server = self.get_param('config.server', None, 'Active Directory server is missing')
		self.bind_username = self.get_param('config.bind_username', None, 'Account is missing')
		self.bind_password = self.get_param('config.bind_password', None, 'Password is missing')
		self.base = self.get_param('config.baseDN', None, 'BaseDN is missing')
		self.service = self.get_param('config.service', None, 'Service parameter is missing')
		self.query = "(sAMAccountName=%s)" % self.get_data()

	def ad_connect(self):
		try:
			self.server = Server(self.ad_server, get_info=ALL)
			self.connection = Connection(self.server, self.bind_username, self.bind_password, auto_bind=True) 
		except Exception as e:
			self.error(e)

	def ad_search(self):
		try:
			self.connection.search(self.base, self.query, attributes=[ALL_ATTRIBUTES])
		except Exception as e:
			self.error(e)
	
	#Generate Short report
	def summary(self, raw):
		taxonomies = []
		namespace = "ActiveDirectory"
		predicate = "Attributes"
		value = "\"0\""
		result = {
			"has_result": True
		}
		#If no result then return an error
		if not self.connection.entries[0]:
			result["has_result"] = False
		else:
			level = "info"
			value = "{}".format(len(vars(self.connection.entries[0]).items()))
		#Build taxonomy
		taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
		return {"taxonomies": taxonomies}

	#Analyzer main function
	def run(self):
		if (self.bind_username is None) or (self.bind_password is None) or (self.ad_server is None) or (self.base is None):
			self.error('Invalid configuration')
		else:
			if self.service == 'ad-user':
				self.ad_connect()
				self.ad_search()
				self.report(json.loads(self.connection.entries[0].entry_to_json()))
			else:
				self.error('Invalid service')

if __name__ == '__main__':
    ActiveDirectoryAnalyzer().run()
