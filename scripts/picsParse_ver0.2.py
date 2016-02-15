#picsParse.py

#
# INFO: We use pdftotext to convert PDFs to TXTs
#

from sys import argv

class bacnet_prop:
	def __init__(self, tpe = "", w = False):
		self.type = tpe
		self.writable = w
		self.values = set()
	def toString(self):
		return self.type + " (W = " + str(self.writable) + ")"

class bacnet_obj:
	def __init__(self, tpe = "", cd = False):
		self.type = tpe
		self.credel = cd
		self.props = dict()
	def toString(self):
		res = self.type + " (CreDel = " + str(self.credel) + ")\n\t\t"
		for prop in self.props:		
			res = res + self.props[prop].toString() + ", "		
		return res + "\n"

class PICS:
	def __init__(self, n = ""):
		self.name = n
		self.bibbs = set()
		self.objs = dict();
	def toString(self):
		res = self.name + "\n\t"
		for bibb in self.bibbs:
			res = res + bibb + ", "
		res = res + "\n\t"
		for obj in self.objs:
			res = res + self.objs[obj].toString() + "\t"
		return res

#pics = PICS("Blue ID S10")

#pics.bibbs.add("DS-RP-A");
#pics.bibbs.add("DS-RP-B");

#obj1 = bacnet_obj("Accumulator", True)

#prop1_1 = bacnet_prop("Object_Identifier", False)
#prop1_2 = bacnet_prop("Object_Name", False)
#prop1_3 = bacnet_prop("Object_Type", False)
#prop1_4 = bacnet_prop("Present_Value", True)
#obj1.props["Object_Identifier"] = prop1_1
#obj1.props["Object_Name"] = prop1_2
#obj1.props["Object_Type"] = prop1_3
#obj1.props["Present_Value"] = prop1_4

#obj2 = bacnet_obj("Device", False)

#prop2_1 = bacnet_prop("Object_Identifier", False)
#prop2_2 = bacnet_prop("Object_Name", False)
#prop2_3 = bacnet_prop("Object_Type", False)
#obj2.props["Object_Identifier"] = prop2_1
#obj2.props["Object_Name"] = prop2_2
#obj2.props["Object_Type"] = prop2_3

#pics.objs["Accumulator"] = obj1
#pics.objs["Device"] = obj2

#print pics.toString()

bibbs = {"AE-ACK-A", "AE-ACK-B", "AE-ASUM-A", "AE-ASUM-B", "AE-ESUM-A", "AE-ESUM-B", "AE-INFO-A", "AE-INFO-B", "AE-LS-A", "AE-LS-B", "AE-N-A", "AE-N-E-B", "AE-N-I-B", "DS-COV-A", "DS-COV-B", "DS-COVP-A", "DS-COVP-B", "DS-COVU-A", "DS-COVU-B", "DS-RP-A", "DS-RP-B", "DS-RPC-A", "DS-RPC-B", "DS-RPM-A", "DS-RPM-B", "DS-WP-A", "DS-WP-B", "DS-WPM-A", "DS-WPM-B", "DM-BR-A", "DM-BR-B", "DM-DCC-A", "DM-DCC-B", "DM-DDB-A", "DM-DDB-B", "DM-DOB-B", "DM-LM-A", "DM-LM-B", "DM-OCD-A", "DM-OCD-B", "DM-PT-A", "DM-PT-B", "DM-R-A", "DM-R-B", "DM-RD-A", "DM-RD-B", "DM-TM-A", "DM-TM-B", "DM-TS-A", "DM-TS-B", "DM-UTC-A", "DM-UTC-B", "DM-VT-A", "DM-VT-B", "NM-CE-A", "NM-CE-B", "NM-RC-A", "NM-RC-B", "SCHED-A", "SCHED-E-B", "SCHED-I-B", "T-ATR-A", "T-ATR-B", "T-VMT-A", "T-VMT-E-B", "T-VMT-I-B"}
objects = {"analog-input", "analog-output", "analog-value", "binary-input", "binary-output", "binary-value", "calendar", "command", "device", "event-enrollment", "file", "group", "loop", "multi-state-input", "multi-state-output", "notification-class", "program", "schedule", "averaging", "multi-state-value", "trend-log", "life-safety-point", "life-safety-zone", "accumulator", "pulse-converter", "event-log", "global-group", "trend-log-multiple", "load-control", "structured-view", "access-door", "(unassigned)", "access-credential", "access-point", "access-rights", "access-user", "access-zone", "credential-data-input", "network-security", "bitstring-value", "characterstring-value", "date-pattern-value", "date-value", "datetime-pattern-value", "datetime-value", "integer-value", "large-analog-value", "octetstring-value", "positive-integer-value", "time-pattern-value", "time-value", "notification-forwarder", "alert-enrollment", "channel", "lighting-output"}
properties = {"accepted-modes", "access-alarm-events", "access-doors", "access-event", "access-event-authentication-factor", "access-event-credential", "access-event-tag", "access-event-time", "access-transaction-events", "accompaniment", "accompaniment-time", "ack-required", "acked-transitions", "action", "action-text", "activation-time", "active-authentication-policy", "active-cov-subscriptions", "active-text", "active-vt-sessions", "actual-shed-level", "adjust-value", "alarm-value", "alarm-values", "align-intervals", "all", "all-writes-successful", "allow-group-delay-inhibit", "apdu-segment-timeout", "apdu-timeout", "application-software-version", "archive", "assigned-access-rights", "attempted-samples", "authentication-factors", "authentication-policy-list", "authentication-policy-names", "authentication-status", "authorization-exemptions", "authorization-mode", "auto-slave-discovery", "average-value", "backup-and-restore-state", "backup-failure-timeout", "backup-preparation-time", "base-device-security-policy", "belongs-to", "bias", "bit-mask", "bit-text", "blink-warn-enable", "buffer-size", "change-of-state-count", "change-of-state-time", "channel-number", "client-cov-increment", "configuration-files", "control-groups", "controlled-variable-reference", "controlled-variable-units", "controlled-variable-value", "count", "count-before-change", "count-change-time", "cov-increment", "cov-period", "cov-resubscription-interval", "covu-period", "covu-recipients", "credential-disable", "credential-status", "credentials", "credentials-in-zone", "database-revision", "date-list", "daylight-savings-status", "days-remaining", "deadband", "default-fade-time", "default-ramp-rate", "default-step-increment", "derivative-constant", "derivative-constant-units", "description", "description-of-halt", "device-address-binding", "device-type", "direct-reading", "distribution-key-revision", "do-not-hide", "door-alarm-state", "door-extended-pulse-time", "door-members", "door-open-too-long-time", "door-pulse-time", "door-status", "door-unlock-delay-time", "duty-window", "effective-period", "egress-time", "egress-active", "elapsed-active-time", "entry-points", "enable", "error-limit", "event-algorithm-inhibit", "event-algorithm-inhibit-ref", "event-detection-enable", "event-enable", "event-message-texts", "event-message-texts-config", "event-state", "event-time-stamps", "event-type", "event-parameters", "exception-schedule", "execution-delay", "exit-points", "expected-shed-level", "expiry-time", "extended-time-enable", "failed-attempt-events", "failed-attempts", "failed-attempts-time", "fault-parameters", "fault-type", "fault-values", "feedback-value", "file-access-method", "file-size", "file-type", "firmware-revision", "full-duty-baseline", "global-identifier", "group-members", "group-member-names", "high-limit", "inactive-text", "in-process", "in-progress", "input-reference", "instance-of", "instantaneous-power", "integral-constant", "integral-constant-units", "interval-offset", "is-utc", "key-sets", "last-access-event", "last-access-point", "last-credential-added", "last-credential-added-time", "last-credential-removed", "last-credential-removed-time", "last-key-server", "last-notify-record", "last-priority", "last-restart-reason", "last-restore-time", "last-use-time", "life-safety-alarm-values", "lighting-command", "lighting-command-default-priority", "limit-enable", "limit-monitoring-interval", "list-of-group-members", "list-of-object-property-references", "local-date", "local-forwarding-only", "local-time", "location", "lock-status", "lockout", "lockout-relinquish-time", "log-buffer", "log-device-object-property", "log-interval", "logging-object", "logging-record", "logging-type", "low-limit", "maintenance-required", "manipulated-variable-reference", "manual-slave-address-binding", "masked-alarm-values", "maximum-output", "maximum-value", "maximum-value-timestamp", "max-actual-value", "max-apdu-length-accepted", "max-failed-attempts", "max-info-frames", "max-master", "max-pres-value", "max-segments-accepted", "member-of", "member-status-flags", "members", "minimum-off-time", "minimum-on-time", "minimum-output", "minimum-value", "minimum-value-timestamp", "min-actual-value", "min-pres-value", "mode", "model-name", "modification-date", "muster-point", "negative-access-rules", "network-access-security-policies", "node-subtype", "node-type", "notification-class", "notification-threshold", "notify-type", "number-of-apdu-retries", "number-of-authentication-policies", "number-of-states", "object-identifier", "object-list", "object-name", "object-property-reference", "object-type", "occupancy-count", "occupancy-count-adjust", "occupancy-count-enable", "occupancy-lower-limit", "occupancy-lower-limit-enforced", "occupancy-state", "occupancy-upper-limit", "occupancy-upper-limit-enforced", "operation-expected", "optional_", "out-of-service", "output-units", "packet-reorder-time", "passback-mode", "passback-timeout", "polarity", "port-filter", "positive-access-rules", "power", "prescale", "present-value", "bacnet-priority", "priority-array", "priority-for-writing", "process-identifier", "process-identifier-filter", "profile-name", "program-change", "program-location", "program-state", "property-list", "proportional-constant", "proportional-constant-units", "protocol-object-types-supported", "protocol-revision", "protocol-services-supported", "protocol-version", "pulse-rate", "read-only", "reason-for-disable", "reason-for-halt", "recipient-list", "records-since-notification", "record-count", "reliability", "reliability-evaluation-inhibit", "relinquish-default", "requested-shed-level", "requested-update-interval", "resolution", "restart-notification-recipients", "restore-completion-time", "restore-preparation-time", "scale", "scale-factor", "schedule-default", "secured-status", "security-pdu-timeout", "security-time-window", "segmentation-supported", "serial-number", "setpoint", "setpoint-reference", "setting", "shed-duration", "shed-level-descriptions", "shed-levels", "silenced", "slave-address-binding", "slave-proxy-enable", "start-time", "state-description", "state-text", "status-flags", "stop-time", "stop-when-full", "structured-object-list", "subordinate-annotations", "subordinate-list", "subscribed-recipients", "supported-formats", "supported-format-classes", "supported-security-algorithms", "system-status", "threat-authority", "threat-level", "time-delay", "time-delay-normal", "time-of-active-time-reset", "time-of-device-restart", "time-of-state-count-reset", "time-synchronization-interval", "time-synchronization-recipients", "total-record-count", "trace-flag", "tracking-value", "transaction-notification-class", "transition", "trigger", "units", "update-interval", "update-key-set-timeout", "update-time", "user-external-identifier", "user-information-reference", "user-name", "user-type", "uses-remaining", "utc-offset", "utc-time-synchronization-recipients", "valid-samples", "value-before-change", "value-set", "value-change-time", "variance-value", "vendor-identifier", "vendor-name", "verification-time", "vt-classes-supported", "weekly-schedule", "window-interval", "window-samples", "write-status", "zone-from", "zone-members", "zone-to"}

script, filename = argv

txt = open(filename)
pics = PICS(filename[:-4])

print "Parsing file %r" % filename
#print txt.read()

last_obj = ""
last_prop = ""

for line in txt:

	#print line
	words = [word.replace("\n", "") for word in line.split(" ")]
	#print words

	for word in words:

		if word in bibbs:
			#print "FOUND BIBB: " + word
			pics.bibbs.add(word)

		elif word.lower() in objects:

			if word.lower() not in pics.objs:
				#print "FOUND OBJ: " + word.lower()
				pics.objs[word.lower()] = bacnet_obj(word.lower(), False)
			
			last_obj = word.lower()
			last_prop = ""

		elif last_obj != "" and (word.lower() == "yes" or word.lower() == "y"):
			#print "OBJ" + last_obj + " is creatable/deletable"
			pics.objs[last_obj].credel = True

		elif last_obj != "" and last_obj in pics.objs and word.lower().replace("_","-") in properties:

			if word.lower().replace("_","-") not in pics.objs[last_obj].props:
				#print "FOUND PROP: " + word.lower() + " for " + last_obj
				pics.objs[last_obj].props[word.lower().replace("_","-")] = bacnet_prop(word.lower().replace("_","-"), False)

			last_prop = word.lower()

		elif last_obj != "" and last_prop != "" and (word.lower() == "w" or word.lower() == "r/w"):
			#print "PROP" + last_prop + " is writable"
			pics.objs[last_obj].props[last_prop].writable = True


	for obj in objects:
		
		if obj.replace("-", " ") in line.lower():

			if obj not in pics.objs:
				#print "FOUND OBJ: " + obj
				pics.objs[obj] = bacnet_obj(obj, False)
			
			last_obj = obj
			last_prop = ""

	for prop in properties:
		
		if prop.replace("-", " ") in line.lower() and last_obj in pics.objs:

			if prop not in pics.objs[last_obj].props:
				#print "FOUND PROP: " + prop + " for " + last_obj
				pics.objs[last_obj].props[prop] = bacnet_prop(prop, False)
			
			last_prop = prop

		if prop.replace("-", "_") in line.lower() and last_obj in pics.objs:

			if prop not in pics.objs[last_obj].props:
				#print "FOUND PROP: " + prop + " for " + last_obj
				pics.objs[last_obj].props[prop] = bacnet_prop(prop, False)
			
			last_prop = prop
	

#print pics.toString()
	


