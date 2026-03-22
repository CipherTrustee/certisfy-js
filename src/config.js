    let hashAlg = "sha-256";
    let signAlg = "ECDSA";
	let certAlgo = (signAlg == "ECDSA"?{
                name:signAlg,
          		namedCurve:"P-256",
                  hash: "SHA-256" 
              }:{
                name: "RSASSA-PKCS1-v1_5",
                  hash: "SHA-256" 
    });


 	//module scope configurables
    let PKI_CERT_VERSION = "1.5";
    let idAnchorElements = {
      "US_SSN" : "US Social Security Number",
      "US_DLN" : "US State Drivers License Number",
      "US_STATE_ID" : "US State ID",
      "PPN" : "Passport Number",
      "LABOR_CODE_ID" : "Certain Occupational IDs (ex:Law enforcement)",
      "NATIONAL_ID" : "National Individual ID Number",
      "ORG_DOMAIN" : "Domain name of an organization, that can serve as a suitable unique id."
    };

    let clientApp;
	let trustRoots=[ 
        {
          "finger_print" : "594e1fe91a54c5f9adaa8956fa79360346c18766",
          "cert_text" : "-----BEGIN CERTIFICATE-----\nMIIDZzCCAwygAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQcm9tZXRo\nZXVzMB4XDTI0MDExNTEzMDAyOFoXDTM0MDExNTEzMDAyOFowEDEOMAwGA1UEAwwF\nSHVtYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARi6BmjmSfz5KlOI0KXxkKL\nl7iYT+WZySxC7ImZgvAgY4ofyLU+LFvjjYu6+SQRH/XphtqNzeP6YMBDNLOY6AzZ\no4ICUDCCAkwwHQYDVR0OBBYEFFB00DwJh9ngK9xLHSa4EvWw8yOwMIICKQYDVR0R\nBIICIDCCAhyCggIYeyJwa2ktYXN5bS1lbmNyeXB0aW9uLWtleSI6Ii0tLS0tQkVH\nSU4gUFVCTElDIEtFWS0tLS0tXG5NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9D\nQVE4QU1JSUJDZ0tDQVFFQTJ0TnpwczlVNVNqN3E1Sy9adWJKXHJcbkVoaDVrOG9Y\nNHc0Vnk2RVhHT1lvazZVSmU3YVJ5aTgwZnBiYTRJMUtmTWpKUW5PSjUzQ2pmZWdK\nVzVud2J0OUFcclxuVnY5N2lGa0xCZlVzOTF0eVJBeTFjRy90MWdZMDhOM05naUdH\nUXNTeEI1dDRTUXVGMHNPTFB3NHhVTWYzNktZNlxyXG5DejlBMlYyNjhuZE8rdFJi\nTDl5UXN2Uk13c3Brd2hpcDJOQjhyemZFYkJxNngvV05zeXM5NXA4aUo3VEJRNkh5\nXHJcbkhVTkJaWEJyRVJFRDc2ZmJ3V0R1UFRaZzRYY3RqMjV5T25KNEE0SGpjNFZY\nU1dFeFhZWk1aY21HVytzaW0yNzNcclxuMTFoZTlRNkMxckluNmdBU3B3ZnV0N2lr\nT2lER291VlR0Z0UwbnFtbnc0cTJ5SU52bDU3NHo4Qys4S0pvTlgzRFxyXG5zUUlE\nQVFBQlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iLCJ1cmwiOiJodHRwczov\nL2NpcGhlcmVkdHJ1c3QuY29tIn0wCgYIKoZIzj0EAwIDSQAwRgIhAKcvou9BeWIm\nktwVPZsSS8NNhduA2RDuDNpKsJn4vW8ZAiEA/uVqXLYavURiOlvy8iUFqnI0chvG\ndJg96BTWTcaQy6A=\n-----END CERTIFICATE-----",
          "type" : "trust"
        }, 
        {
          "finger_print" : "319185e648597d0a3961787cd0eeb662bcc71fbb",
          "cert_text" : "-----BEGIN CERTIFICATE-----\nMIIDrDCCA1GgAwIBAgIBATAKBggqhkjOPQQDAjAzMTEwLwYDVQQDDCg1OTRlMWZl\nOTFhNTRjNWY5YWRhYTg5NTZmYTc5MzYwMzQ2YzE4NzY2MB4XDTI0MDExNTEzMjk1\nOVoXDTM0MDExNTEzMjk1OVowEDEOMAwGA1UEAwwFSHVtYW4wWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAARDJojKrWLeCyiATDV36E5uAdCrEqBx8ksfa6cWILOqiSA+\nNXX6+ZdMEaiBYS+CkuHkZbqYDj12hpwJ15tx/aido4ICdzCCAnMwHQYDVR0OBBYE\nFCjlboEQ74MW/LO2NXGE6MSAsyr0MIICUAYDVR0RBIICRzCCAkOCggI/eyJwa2kt\nYXN5bS1lbmNyeXB0aW9uLWtleSI6Ii0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0t\nXG5NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXJh\nV2FkQStBRm8rd0lJUkErdGs1XHJcbkM3dkhVVUhTaEE5M2lzNXFPak5tZ0Y4Vm9H\nZFdMVWFPSmw0czZIOWpWNWhRazl1K0hsRTZnbU5YS0dZUThhVGVcclxueUFkYTVU\nS0dsYXpXL0tpUGZrR0VWZGhrbVdUci9OZmpwcDhmVU9kNDE5Z2Jrd0tXbGZQNmpC\nTU9TRWR3ZTJITFxyXG5SYysrRHVDeXo0dEpBMzNEbzBIVEpoM1BLRXVZU21pQWl4\nZkp2QmRBcWU5NFhDT0plNzEvWkdsM01yaUYyNHhoXHJcbjFEMDNwSGhNR2UxbTha\nWXpWS3dlVWNWbjNFd3ZGaTVMWEQwYUJhOTNYNHNVeWI3WjhEa2hpcWx2bnpyMHk2\nZGxcclxuSGFGNDFKVTg0R2l3cWRwdk5wODFhOTh3TTgxWXl3VzRFb2lTLzREdGNF\nTTh2eERpY3FUemxPT3pPWG0rZmxlVFxyXG5Id0lEQVFBQlxuLS0tLS1FTkQgUFVC\nTElDIEtFWS0tLS0tXG4iLCJ1cmwiOiJodHRwczovL2NpcGhlcmVkdHJ1c3QuY29t\nIiwiUHVycG9zZSI6IlRydXN0IEFuY2hvciBSZXZpZXdlciBSb290In0wCgYIKoZI\nzj0EAwIDSQAwRgIhAOI57dycLY5BMuIacyVJ36oBDAIvWs+gsDeMYshijLMRAiEA\n7mgqMCpW0uMkGx1P1SnUMqRfDaC+JvDm0eUtqWXGYNY=\n-----END CERTIFICATE-----",
          "type" : "reviewer"
        } 
    ];

    let trustChainRoot;
    let demoTrustAnchorFingerprint = "3e0cddfbd29f9bffcdc3c149fd768bab023fb96b";

    let apiInfo = {target:null,requestSigningInfo:null};
    let PUBLIC_PLAIN_FIELDS = ["pki-valid-from-time","pki-expiration-time","pki-vouch-for-claim","pki-claim-vouch"];

	export {
    	PKI_CERT_VERSION,
		hashAlg,
        signAlg,
        certAlgo,
        idAnchorElements,
        clientApp,
        trustRoots,
        trustChainRoot,
        demoTrustAnchorFingerprint,
      	apiInfo,
      	PUBLIC_PLAIN_FIELDS
	}