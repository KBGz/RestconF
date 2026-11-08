# RestconF
RIP_Restconf


The IOS XE Software versions need to be up to date or atleast 16.06.04 or you cant even connect to the router because of the compatibility issue between the cisco version and Windows Schannel TLS handshake…… 

Also

Tried implementing token auth and client certificate but the IOSXE build returns 411 on /api/vl/auth/token-services and error 401 on mTLS despite correct trustpoint, AAA and EKU configurations 
The Debug Output:

PS C:\Users\cisco\Documents\Rest-Conf\Certs> python "C:\Users\cisco\Documents\test_mtls.py"
Status: 401
{
  "errors": {
    "error": [
      {
        "error-tag": "access-denied",
        "error-type": "protocol"
      }
    ]
  }
}

PS C:\Users\cisco\Documents\Rest-Conf\Certs>


So had to Use the BasicAuth with Username+Password to get it to even work.
