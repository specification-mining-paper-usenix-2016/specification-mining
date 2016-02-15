#################################################################################
#
# Copyright 2015 XXX XXX
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#################################################################################

module BACnetDiscovery;

module BACnetSec;

@load bacnet_apdu.bro

#################################################################
#								#
#		              LOGs				#
#								#
#################################################################

export {

  redef enum Log::ID += { SEMANTICS };

  type Info_SEMANTICS: record {

    object:		string &log; 
    information:	string &log &optional;
  
  };

}

event bro_init()
{
  Log::create_stream(SEMANTICS, [$columns=Info_SEMANTICS]);
}

#################################################################
#								#
#		     KNOWLEDGE RETRIEVAL			#
#								#
#################################################################

function object2String(object: BACnetAPDUTypes::BACnetObjectIdentifier) : string
{ 
  if(!object?$id || !object?$instance){ return fmt("%s", object); }
  else { return fmt("%s_%s", object$id, object$instance); }
}

function info2String(object: BACnetAPDUTypes::BACnetObjectIdentifier, bacAdd: string, ipAdd: string) : string
{ 
  if(!object?$id || !object?$instance){ return fmt("%s_%s_%s", object, bacAdd, ipAdd); }
  else { return fmt("%s_%s_%s_%s", object$id, object$instance, bacAdd, ipAdd); }
}

#
# INFO:
#
#   1) Extraction of semantic information for every BACnet object
#
#   2) Link of the semantic information with online resources (e.g., PICS)
#
#   3) Creation of a unique identifier linking objects to online resources
#

global identifiers: table[string] of table[string] of table[string] of string = {

 #["device_11998"] = table([""] = table(["1.1.1.1"] = "Kieback&Peter DDC4000"))
  
};

function inIdentifiers(object: BACnetAPDUTypes::BACnetObjectIdentifier, bacAdd: string, ipAdd: string) : bool
{

  local key: string = object2String(object);
  
  if(key !in identifiers || bacAdd !in identifiers[key] || ipAdd !in identifiers[key][bacAdd]){
    return F;
  } 

  return T;

}

function inIdentifiers_partial(object: BACnetAPDUTypes::BACnetObjectIdentifier, bacAdd: string) : bool
{

  local key: string = object2String(object);

  if(key in identifiers && bacAdd == "" && |identifiers[key]| == 1){
    return T;
  } 
  else if(key in identifiers && bacAdd in identifiers[key] && |identifiers[key][bacAdd]| == 1){
    return T;
  }

  return F;

}

function addIdentifier(object: BACnetAPDUTypes::BACnetObjectIdentifier, bacAdd: string, ipAdd: string, id: string){

  local key = object2String(object);

  if(key !in identifiers){

    identifiers[key] = table();
    identifiers[key][bacAdd] = table();
    identifiers[key][bacAdd][ipAdd] = id;

  } else if(bacAdd !in identifiers[key]){

    if(bacAdd != "" && |identifiers[key]| == 1){

      identifiers[key][bacAdd] = table();

      for(ba in identifiers[key]){
        
        if(ba == ""){

          for(ia in identifiers[key][ba]){
            identifiers[key][bacAdd][ia] = identifiers[key][ba][ia];
            delete identifiers[key][ba][ia];
          }

          delete identifiers[key][ba];

        }

      }

      identifiers[key][bacAdd][ipAdd] = id;

    } else if(bacAdd == "" && |identifiers[key]| == 1){

      for(ba in identifiers[key]){
        identifiers[key][ba][ipAdd] = id;
      }

    } else {

      identifiers[key][bacAdd] = table();
      identifiers[key][bacAdd][ipAdd] = id;

    }

  } else if(ipAdd !in identifiers[key][bacAdd]){

    identifiers[key][bacAdd][ipAdd] = id;

  }

}

function getIdentifier(object: BACnetAPDUTypes::BACnetObjectIdentifier, bacAdd: string, ipAdd: string) : string
{

 local key = object2String(object);

 if(key in identifiers){

   if(bacAdd in identifiers[key]){

     if(ipAdd in identifiers[key][bacAdd]){

       return identifiers[key][bacAdd][ipAdd];

     } else if(|identifiers[key][bacAdd]| == 1){

       for(ia in identifiers[key][bacAdd]){
         return identifiers[key][bacAdd][ia];
       }

     } else {

       return "";

     }

   } else if(bacAdd != "" && |identifiers[key]| == 1) {

     for(ba in identifiers[key]){

       if(ba == ""){
         
         local id: string = "";
         for(ia in identifiers[key][ba]){
           if(id == "" || id == identifiers[key][ba][ia]){
             id = identifiers[key][ba][ia];
           } else {
             return "";
           }
         }

         return id;

       } 

       return "";

     }

   } else if(bacAdd == "" && |identifiers[key]| == 1) {

     for(ba in identifiers[key]){

       local id2: string = "";
       for(ia in identifiers[key][ba]){
         if(id2 == "" || id2 == identifiers[key][ba][ia]){
           id2 = identifiers[key][ba][ia];
         } else {
           return "";
         }
       }

       return id2;

     }

   }

   return "";

 } 

 return "";

}

type Device_Reference : record {

  object:		BACnetAPDUTypes::BACnetObjectIdentifier		&optional;
  bacAddress:		string						&optional;
  ipAddress:		string						&optional;

};

global addresses: table[string] of Device_Reference = {

  #["4000/\xa1\x0f\x00\x00\x00\x00"] = ...
  
};

type Semantic_Knowledge : record {

  vendor:		string		&optional;
  modelName:		string		&optional;
  objectName:		string		&optional;

};

global knowledge : table[string] of Semantic_Knowledge = {};

event bro_done()
{  

  #print fmt("Knowldege: %s ", knowledge);
  #print fmt("Identifiers: %s ", identifiers);
  
  print fmt("Incomplete knowldege: %s ", knowledge);

}

global currentBacSrc: string = 		"";
global currentBacDst: string = 		"";
global currentBacAdd: string = 		"";

global currentIpSrc = 			"";
global currentIpDst = 			"";
global currentIpAdd = 			"";

#
# INFO: This function updates current source and destination addresses
#
event new_packet(c: connection, p: pkt_hdr) &priority = 3
{
  
  if(p?$ip){
  
    currentIpSrc = fmt("%s", p$ip$src);
    currentIpDst = fmt("%s", p$ip$dst);
  
  } else {

   currentIpSrc = "";
   currentIpDst = "";

  }

}

event bacnet_npdu_parameters(c: connection, src: string, dst: string) &priority = 3
{
  currentBacSrc = src;
  currentBacDst = dst;
}

function checkKnowledge(semanticKnowledge: Semantic_Knowledge) : string
{

  # # # INFORMATION RETRIEVAL # # #

  local id: string = "";
  local knowledgeInformation = fmt("%s - %s - %s", semanticKnowledge$vendor, semanticKnowledge$modelName, semanticKnowledge$objectName);

  #...

  return knowledgeInformation;

}

#
# INFO: This event allows adding new devices to table identifiers
#
event bacnet_ReadProperty_ACK(c: connection, invokeid: count, info: BACnetAPDU::ReadProperty_ACK_Info) &priority = 2
{

  currentBacAdd = currentBacSrc;
  currentIpAdd = currentIpSrc;

  if(info$objectIdentifier$id == "device" && !inIdentifiers(info$objectIdentifier, currentBacAdd, currentIpAdd)){
    
    local key: string = info2String(info$objectIdentifier, currentBacAdd, currentIpAdd);

    if(key !in knowledge){
      knowledge[key] = [$vendor = "", $modelName = "", $objectName = ""];
    }

    if(info$propertyIdentifier == "vendor-identifier" && info?$propertyValue) {
      if(to_count(fmt("%s", info$propertyValue)) in BACnetAPDUTypes::BACnetVendorId){
        knowledge[key]$vendor = BACnetAPDUTypes::BACnetVendorId[to_count(fmt("%s", info$propertyValue))];
      } else {
        knowledge[key]$vendor = fmt("Unknown Vendor (%s)", info$propertyValue);
      }
    } else if(info$propertyIdentifier == "model-name" && info?$propertyValue) {
      knowledge[key]$modelName = fmt("%s", info$propertyValue);
    } else if(info$propertyIdentifier == "object-name" && info?$propertyValue) {
      knowledge[key]$objectName = fmt("%s", info$propertyValue);
    }

    local id: string = checkKnowledge(knowledge[key]);
    if(id != ""){
      
      addIdentifier(info$objectIdentifier, currentBacAdd, currentIpAdd, id);
      delete knowledge[key];

      print fmt("Device %s is a \"%s\"", info$objectIdentifier$instance, id);
      Log::write(BACnetSec::SEMANTICS, [$object = fmt("%s (device)", info$objectIdentifier$instance), $information = id]);

    }

  }
  
}

#
# INFO: This event allows adding new devices to table identifiers
#
event bacnet_ReadPropertyMultiple_ACK(c: connection, invokeid: count, info: BACnetAPDU::ReadPropertyMultiple_ACK_Info) &priority = 2
{ 
  
  currentBacAdd = currentBacSrc;
  currentIpAdd = currentIpSrc;

  for(i in info$listOfReadAccessResults){
    
    local result: BACnetAPDUTypes::ReadAccessResult = info$listOfReadAccessResults[i];
    local key: string = info2String(result$objectIdentifier, currentBacAdd, currentIpAdd);

    if(result$objectIdentifier$id == "device" && !inIdentifiers(result$objectIdentifier, currentBacAdd, currentIpAdd)){

      if(key !in knowledge){
        knowledge[key] = [$vendor = "", $modelName = "", $objectName = ""];
      }

      for(j in result$listOfResults){
    
        if(result$listOfResults[j]$propertyIdentifier == "vendor-identifier" && result$listOfResults[j]?$propertyValue) {
          knowledge[key]$vendor = BACnetAPDUTypes::BACnetVendorId[to_count(fmt("%s", result$listOfResults[j]$propertyValue))];
        } else if(result$listOfResults[j]$propertyIdentifier == "model-name" && result$listOfResults[j]?$propertyValue) {
          knowledge[key]$modelName = fmt("%s", result$listOfResults[j]$propertyValue);
        } else if(result$listOfResults[j]$propertyIdentifier == "object-name" && result$listOfResults[j]?$propertyValue) {
          knowledge[key]$objectName = fmt("%s", result$listOfResults[j]$propertyValue);
        }

      }

      local id: string = checkKnowledge(knowledge[key]);
      if(id != ""){
        
        addIdentifier(result$objectIdentifier, currentBacAdd, currentIpAdd, id);
        delete knowledge[key];
      
        print fmt("Device %s is a \"%s\"", result$objectIdentifier$instance, id);
        Log::write(BACnetSec::SEMANTICS, [$object = fmt("%s (device)", result$objectIdentifier$instance), $information = id]);

      }

    }

  }

}

#
# INFO: This event allows mapping all objects to the correct identifiers by linking them to a known device object
#
event bacnet_I_Have_Request(c: connection, info: BACnetAPDU::I_Have_Request_Info) &priority = 2
{
 
  currentBacAdd = currentBacSrc;
  currentIpAdd = currentIpSrc;

  if(!inIdentifiers(info$objectIdentifier, currentBacAdd, currentIpAdd)){

    local id: string = "";
    if(inIdentifiers(info$deviceIdentifier, currentBacAdd, currentIpAdd)){
    
      id = identifiers[object2String(info$deviceIdentifier)][currentBacAdd][currentIpAdd];
      addIdentifier(info$objectIdentifier, currentBacAdd, currentIpAdd, id);
    
    } else if(inIdentifiers_partial(info$deviceIdentifier, currentBacAdd)){

      for(ba in identifiers[object2String(info$deviceIdentifier)]){
        for(ia in identifiers[object2String(info$deviceIdentifier)][ba]){
          id = identifiers[object2String(info$deviceIdentifier)][ba][ia];
        }
      }

      addIdentifier(info$objectIdentifier, currentBacAdd, currentIpAdd, id);

    }

    if(id != ""){

      print fmt("Updating table \"identifiers\" (from device %s) -> Object: %s (%s) is \"%s\"", info$deviceIdentifier$instance, info$objectIdentifier$instance, info$objectIdentifier$id, id);
      Log::write(BACnetSec::SEMANTICS, [$object = fmt("%s (%s) from %s (\"%s\")", info$objectIdentifier$instance, info$objectIdentifier$id, info$deviceIdentifier$instance, currentBacAdd), $information = fmt("%s", id)]);

    }

  }

}

#
# INFO: This event allows mapping objects to their bacnet addresses
#
event bacnet_I_Am_Request(c: connection, info: BACnetAPDU::I_Am_Request_Info) &priority = 2
{
 
  currentBacAdd = currentBacSrc;
  currentIpAdd = currentIpSrc;
 
  if(currentBacAdd != "" && currentBacAdd !in addresses){

    local device_Reference: Device_Reference = [$object = info$iAmDeviceIdentifier, $bacAddress = currentBacAdd, $ipAddress = currentIpAdd];
    
    addresses[currentBacAdd] = device_Reference;
    
    print fmt("Updating table \"addresses\" -> Object: %s (%s) has %s at %s", info$iAmDeviceIdentifier$instance, info$iAmDeviceIdentifier$id, currentBacAdd, currentIpAdd);
     
  }

}

#
# INFO: This event allows mapping all objects to the correct identifiers by linking them to a known address
#
event bacnet_InformationUnit(c: connection, message: string, object: BACnetAPDUTypes::BACnetObjectIdentifier, property: string, value: any) &priority = 2
{

  switch (message) {

    case "ReadProperty_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "ReadProperty_ACK":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "ReadPropertyMultiple_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "ReadPropertyMultiple_ACK":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "ReadRange_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;
    
    case "ReadRange_ACK":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;
    
    case "AtomicReadFile_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "AtomicReadFile_ACK":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "SubscribeCOV_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "SubscribeCOVProperty_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "ConfirmedCOVNotification_Request":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "ConfirmedEventNotification_Request":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "ConfirmedPrivateTransfer_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;							

    case "ConfirmedPrivateTransfer_ACK":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;						

    case "WriteProperty_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "WritePropertyMultiple_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "AtomicWriteFile_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "AtomicWriteFile_ACK":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;							

    case "GetEventInformation_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "GetEventInformation_ACK":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "UnconfirmedCOVNotification_Request":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "UnconfirmedEventNotification_Request":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "UnconfirmedPrivateTransfer_Request":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;		

    case "TimeSynchronization_Request":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;		

    case "AcknowledgeAlarm_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "ReinitializeDevice_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "CreateObject_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "CreateObject_ACK":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "Who_Is_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "I_Am_Request":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

    case "Who_Has_Request":
      currentBacAdd = currentBacDst;
      currentIpAdd = currentIpDst;
      break;

    case "I_Have_Request":
      currentBacAdd = currentBacSrc;
      currentIpAdd = currentIpSrc;
      break;

  }
  
  if(!inIdentifiers(object, currentBacAdd, currentIpAdd) && currentBacAdd in addresses && inIdentifiers(addresses[currentBacAdd]$object, addresses[currentBacAdd]$bacAddress, addresses[currentBacAdd]$ipAddress)){

    local id: string = identifiers[object2String(addresses[currentBacAdd]$object)][addresses[currentBacAdd]$bacAddress][addresses[currentBacAdd]$ipAddress];
    addIdentifier(object, currentBacAdd, currentIpAdd, id);

    print fmt("Updating table \"identifiers\" (from address \"%s\") -> Object: %s (%s) belongs to \"%s\"", currentBacAdd, object$instance, object$id, id);
    Log::write(BACnetSec::SEMANTICS, [$object = fmt("%s (%s) at %s", object$instance, object$id, currentBacAdd), $information = fmt("%s", id)]);

  }

  if(!inIdentifiers(object, currentBacAdd, currentIpAdd) && currentBacAdd in addresses && inIdentifiers_partial(addresses[currentBacAdd]$object, currentBacAdd)){
        
    local id2: string;
    for(ia in identifiers[object2String(addresses[currentBacAdd]$object)][currentBacAdd]){
      id2 = identifiers[object2String(addresses[currentBacAdd]$object)][currentBacAdd][ia];
    }
    addIdentifier(object, currentBacAdd, currentIpAdd, id2);

    print fmt("Updating table \"identifiers\" (from address \"%s\") -> Object: %s (%s) belongs to \"%s\"", currentBacAdd, object$instance, object$id, id2);
    Log::write(BACnetSec::SEMANTICS, [$object = fmt("%s (%s) at %s", object$instance, object$id, currentBacAdd), $information = fmt("%s", id2)]);

  }

}

