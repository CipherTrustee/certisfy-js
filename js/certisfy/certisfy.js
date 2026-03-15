    /***************************************Copyright 2026, Edmond Kemokai, pkijs example authors******************
    1. This code is provided as is without warranty of any kind. 
    2. You may modify it for your own use and only for automated signing of claims or verification 
       of claims created either via the Certisfy app or claims created via the Certisfy signer code included herein. 
    3. You may not use it to create a Certisfy alternative client, ie a competing alternative to the Certisfy app.
    4. For verification of Certisfy app claims, verification of claims created via the Certisfy signer (ie Certisfy claims), 
       or automated signing of Certisfy claims, you are free to use it for both personal and commercial needs.
    5. You may not redistribute it with or without modifications.
    **************************************************************************************************************/

	/************************************For browser environment*********************************************/
	import * as asn1js from './crypto/asn1js.js';
    import * as pkijs from './crypto/pkijs.es.js';
    import * as hmacUtil from './crypto/hmac-util.js';
    import * as pvtsutils from './crypto/pvtsutils.js';
	import * as certisfyCryptoUtil from './certisfy-crypto-util.js';
	/********************************************************************************************************/

    /************************************For nodejs environment**********************************************
    import * as pkijs from 'pkijs';
    import * as asn1js from 'asn1js';

    import * as hmacUtil from './crypto/hmac-util.js';
    import * as pvtsutils from './crypto/pvtsutils.js';
    import * as certisfyCryptoUtil from './certisfy-crypto-util.js';

	//import crypto from 'node:crypto';
    //Get the crypto extension
    const crypto = pkijs.getCrypto(true);
    *******************************************************************************************************/

    /**
     *source:https://pkijs.org/examples/PKCS10ComplexExample/bundle.js
     * Create PKCS#10
     * @param hashAlg HAsh algorithm
     * @param signAlg Sign algorithm
     * @returns
     */
    //let hashAlg = "sha-1";
    //let signAlg = "RSASSA-PKCS1-V1_5";
	let SDK_MODE = false;

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
    const demoTrustAnchorFingerprint = "3e0cddfbd29f9bffcdc3c149fd768bab023fb96b";

    let API_PROXY_TARGET = "../controller/";
	const PKI_CERT_VERSION = "1.5";
    const PUBLIC_PLAIN_FIELDS = ["pki-valid-from-time","pki-expiration-time","pki-vouch-for-claim","pki-claim-vouch"];

	function SET_SDK_MODE(mode){
    	SDK_MODE = mode;
    }

    function setAPITarget(target){
      API_PROXY_TARGET = target; 
    }

    function setClientApp(app){
      clientApp = app;
      if(app.pkiPlatformFullURL)
      	  API_PROXY_TARGET = app.pkiPlatformFullURL(API_PROXY_TARGET);
    }

    function setIdAnchorElements(elements){
       idAnchorElements = elements; 
    }

	async function sendRequest(param,method,contentType){
		return new Promise((resolve,reject)=>{
          		if(clientApp && typeof clientApp.ajaxStartFN == "function")
                  		clientApp.ajaxStartFN();
          
				fetch(API_PROXY_TARGET, {
                    method: (method?method:"POST"),
                    headers: {
                        "Content-Type": (contentType?contentType:"application/x-www-form-urlencoded")
                    },
                    body: new URLSearchParams(param)
                })
                .then(response => {
                    if(clientApp && typeof clientApp.ajaxStopFN == "function")
                  		clientApp.ajaxStopFN();
                  
                    if (!response.ok) {
                        throw new Error("Network response was not ok");
                    }
                    return response.json();
                })
                .then(resp => {
                    if(clientApp && typeof clientApp.ajaxStopFN == "function")
                  		clientApp.ajaxStopFN();
                  
                    resolve(resp);
                })
                .catch(error => {
                  	if(clientApp && typeof clientApp.ajaxStopFN == "function")
                  		clientApp.ajaxStopFN();
                    console.error("Fetch error:", error);
                });
        })
    }

    async function loadTrustRoots(useRoots){
      
      	return new Promise((resolve,reject)=>{
          
            const setRoot = (roots)=>{
              	trustRoots = roots;
              	trustChainRoot = trustRoots[0];
                resolve(trustChainRoot,trustRoots);
            }
            
            if(useRoots)
            	setRoot(useRoots);
            else
          	if(SDK_MODE){
            	setRoot(trustRoots);
            }
            else
            {
                /*
                $.ajax({url:API_PROXY_TARGET,
                        data:{
                            "action":"get-trust-roots"
                        },
                        method:"POST",
                        dataType:"json"
                }).done(function(roots){
					setRoot(roots);
                })
                */
              
              	sendRequest({
                        action: "get-trust-roots"
                }).then(roots => {
                    setRoot(roots);
                });
            }
        });      
    }

    function isIDElementHash(fieldName){
        for(let idEl in idAnchorElements){
           if(fieldName == idEl+"_HASH")
              return true;
        }
        return false;
  	}

	function randomUUID(preferredCrypto){
    	if(preferredCrypto && preferredCrypto.randomUUID)
          return preferredCrypto.randomUUID();
      
      	return crypto.randomUUID();
    }

    async function shaHex(message,algo) {
      const msgUint8 = typeof message == "string"?new TextEncoder().encode(message):message; // encode as (utf-8) Uint8Array
      const hashBuffer = await crypto.subtle.digest(algo, msgUint8); // hash the message
      const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
      const hashHex = hashArray
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""); // convert bytes to hex string
      return hashHex;
    }

    async function sha1Hex(message) {
       return await shaHex(message,"SHA-1");
    }

    async function sha2Hex(message) {
       return await shaHex(message,"SHA-256");
    }

	async function sha2HexList(vals){
		let hashes = [];
        for(let i=0;i<vals.length;i++)
           hashes.push({"text":vals[i],"hash":await sha2Hex(vals[i])});
      
        return hashes;
    }

	async function sha1HexList(vals){
		let hashes = [];
        for(let i=0;i<vals.length;i++)
           hashes.push({"text":vals[i],"hash":await sha1Hex(vals[i])});
      
        return hashes;
    }

	function hmacHex(hmacKey,val){
     	return hmacUtil.hex(hmacUtil.sign(hmacKey,val)) 
    }

    async function sha1HmacHex(hmacKey,message) {
       return hmacHex(hmacKey,await sha1Hex(message));
    }

    async function sha2HmacHex(hmacKey,message) {
       return hmacHex(hmacKey,await sha2Hex(message));
    }

    function formatTo2Digits(n){
        return n<9?"0"+n:n;
    }

	function createClaimDateTime(claimDate,claimTime,defaultTime){
      	if(claimDate && claimDate.length>0){
            let localDateTime = new Date();
            let validfromDateTime = claimDate;                  
            localDateTime.setFullYear(parseInt(validfromDateTime.split("/")[2]),parseInt(validfromDateTime.split("/")[0])-1,parseInt(validfromDateTime.split("/")[1]));
            validfromDateTime = formatTo2Digits(localDateTime.getUTCMonth()+1)+"/"+formatTo2Digits(localDateTime.getUTCDate())+"/"+localDateTime.getUTCFullYear();

            if(claimTime && claimTime.length>0){//convert to UTC
              localDateTime.setHours(parseInt(claimTime.split(":")[0].trim()));
              localDateTime.setMinutes(parseInt(claimTime.split(":")[1].trim()));
              validfromDateTime = validfromDateTime+" "+formatTo2Digits(localDateTime.getUTCHours())+":"+formatTo2Digits(localDateTime.getUTCMinutes());
            }
            else
              validfromDateTime = validfromDateTime+(defaultTime && defaultTime.trim().length>0?" "+defaultTime:"");  

            return validfromDateTime;
        }
    }

    /* eslint-disable deprecation/deprecation */
    function toPEM(buffer, tag) {
        if(typeof buffer =="string" && buffer.startsWith(`-----BEGIN ${tag}-----`))
          	return buffer;
      
        return [
            `-----BEGIN ${tag}-----`,
            typeof buffer =="string"?formatPEM(buffer):formatPEM(pvtsutils.Convert.ToBase64(buffer)),
            `-----END ${tag}-----`,
            "",
        ].join("\n");
    }

    function fromPEM(pem) {
        const base64 = pem
            .replace(/-{5}(BEGIN|END) .*-{5}/gm, "")
            .replace(/\s/gm, "");
        return pvtsutils.Convert.FromBase64(base64);
    }

    // Function to convert a base64-encoded string to an ArrayBuffer
    function base64ToArrayBuffer(base64) {
      const binaryString = atob(base64);
      const arrayBuffer = new ArrayBuffer(binaryString.length);
      const uint8Array = new Uint8Array(arrayBuffer);

      for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
      }

      return arrayBuffer;
    }   

    function base64EncodeBin(bin){
      return btoa(String.fromCharCode.apply(null, new Uint8Array(bin))); 
    }

    function base64DecodeToBin(b64){
        const binaryString = atob(b64);
        const length = binaryString.length;
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    };
    /**
     * Format string in order to have each line with length equal to 64
     * @param pemString String to format
     * @returns Formatted string
     */
    function formatPEM(pemString) {
        const PEM_STRING_LENGTH = pemString.length, LINE_LENGTH = 64;
        const wrapNeeded = PEM_STRING_LENGTH > LINE_LENGTH;
        if (wrapNeeded) {
            let formattedString = "", wrapIndex = 0;
            for (let i = LINE_LENGTH; i < PEM_STRING_LENGTH; i += LINE_LENGTH) {
                formattedString += pemString.substring(wrapIndex, i) + "\r\n";
                wrapIndex = i;
            }
            formattedString += pemString.substring(wrapIndex, PEM_STRING_LENGTH);
            return formattedString;
        }
        else {
            return pemString;
        }
    }  

    function decodePEM(pem, tag = "[A-Z0-9 ]+") {
        const pattern = new RegExp(`-{5}BEGIN ${tag}-{5}([a-zA-Z0-9=+\\/\\n\\r]+)-{5}END ${tag}-{5}`, "g");
        const res = [];
        let matches = null;
        // eslint-disable-next-line no-cond-assign
        while (matches = pattern.exec(pem)) {
            const base64 = matches[1]
                .replace(/\r/g, "")
                .replace(/\n/g, "");
            res.push(pvtsutils.Convert.FromBase64(base64));
        }
        return res;
    }

	function copyFromObject(src,fields){
    	const resp = {};
      	for(const field of fields){
        	if(src[field])
              	resp[field] = src[field];
        }
      	return resp;
    }

    function getCertIssuer(cert){
      
       if(!cert.issuer)
         	return null;
       //#region Parse and display information about "subject"
        const typemap = {
            "2.5.4.6": "C",
            "2.5.4.11": "OU",
            "2.5.4.10": "O",
            "2.5.4.3": "CN",
            "2.5.4.7": "L",
            "2.5.4.8": "ST",
            "2.5.4.12": "T",
            "2.5.4.42": "GN",
            "2.5.4.43": "I",
            "2.5.4.4": "SN",
            "1.2.840.113549.1.9.1": "E-mail"
        };  


        let issuerCN = null;
        for (let i = 0; i < cert.issuer.typesAndValues.length; i++) {
            let typeval = typemap[cert.issuer.typesAndValues[i].type];
            if (typeof typeval === "undefined")
                typeval = cert.issuer.typesAndValues[i].type;

            const subjval = cert.issuer.typesAndValues[i].value.valueBlock.value;

            if (typeval === "CN") {
                issuerCN = subjval;
            }
        }
      	return issuerCN;
    }

	async function getCertIssuerFingerPrint(cert){
        let decodedCert = decodeCertificate(cert.cert_text);     
        let issuerThumbprint = getCertIssuer(decodedCert)/*.substring(3)*/;
              
        //replace encrypted issuer finger print if necessary
        if(certPayloadHasField(cert.cert_text,"pki-is-private-issuer","true") && cert.issuer_finger_print)
          issuerThumbprint  = cert.issuer_finger_print;
      
        return issuerThumbprint;      
    }

	function issuerIsPrivate(cert){
		return (certPayloadHasField(cert.cert_text,"pki-is-private-issuer","true") && !cert.issuer_finger_print);
    }

    /*
	async function getCertIssuerFingerPrint(cert){
       let decodedCert = typeof cert == "string"?decodeCertificate(cert):cert;
       return getCertIssuer(decodedCert);
    }*/

    async function getCertFingerPrint(cert){
      	let decodedCert = typeof cert == "string"?decodeCertificate(cert):cert;
        return await sha1Hex(decodedCert.toSchema(true).toBER(false));
    }

  	async function pkiHMAC(args,pkiSpUri){
        return new Promise((resolve,reject)=>{
			sendRequest({
              "action":"get-hmac",
              "hmac_call":JSON.stringify(args),
              "sp_uri":pkiSpUri
            }).
            then(function(hmac){
                  resolve(hmac.hmac);
            })
        });
    }

    async function getEmbededSignature(embed_id){
      return new Promise((resolve,reject)=>{
			sendRequest({
              "action":"get-embedded-signature",
              "embed_id":embed_id
            }).
            then(function(signatureEmbed){
                if(typeof signatureEmbed.status == "undefined" || signatureEmbed.status != "failure")
					resolve(signatureEmbed);
            	else
                    resolve(null);
            });
      });
    }

    async function postDHExchange(params){
        return new Promise((resolve,reject)=>{
          	sendRequest(Object.assign({"action":"post-dh-exchange"},params)).
            then(function(resp){
				resolve(resp);
            });
        });
    }

    async function getDHExchange(userCode){
        return new Promise((resolve,reject)=>{
          	sendRequest({
              "user_code":userCode,
              "action":"get-dh-exchange"
            }).
            then(function(resp){
				resolve(resp);
            });
        });
    }

    async function initiateDHExchange(receiverId,useKeyPair){
        const dhKeyPair = useKeyPair?useKeyPair:(await certisfyCryptoUtil.aliceKeyGen("P-256"));
        let alice_data = receiverId?{"sp_uri":receiverId}:null;

        const resp = await postDHExchange({
            "alice_public_key":dhKeyPair.publicKeyBase64,
            "alice_data":alice_data?JSON.stringify(alice_data):undefined
        })
        
        if(resp.status == "success")
        {
            return {
              "status":"success",
              "dhExchange":{
              "create_date":new Date().getTime(),
              "user_code":resp.userCode,
              "private_key":dhKeyPair.privateKeyBase64
            }}
        }      
        return resp; 
    }

    async function executeDHExchange(userCode,fnClaimProvider,useExchange){

           const dhExchange = useExchange?useExchange:await getDHExchange(userCode);

           let skipReceiverIdVerification = true;
           let alice_data = dhExchange.alice_data?JSON.parse(dhExchange.alice_data):null;
           //let receiverIdAuth = JSON.parse(dhExchange.alice_data);
           //certisfyCryptoUtil.ECDSA_SIGNER.verifyMessage(receiverIdAuth.publicKey,receiverIdAuth.auth_signature_string,receiverIdAuth.signature).

           let verified = (skipReceiverIdVerification?true:(await certisfyCryptoUtil.ECDSA_SIGNER.verifyMessage(receiverIdAuth.publicKey,receiverIdAuth.auth_signature_string,receiverIdAuth.auth_signature)))

           let dhKey = await certisfyCryptoUtil.bobKeyGen(dhExchange.alice_public_key);
           let spUri = alice_data && alice_data.sp_uri?alice_data.sp_uri:null;

           let dhxParams = [{"name":"pki-dhx-nonce","value":userCode+"-"+dhExchange.create_date}];
           let claimSig = await fnClaimProvider(dhxParams);

           let cipherText = await certisfyCryptoUtil.AES_GCM_CIPHER.encryptMessage(dhKey.AESKey,typeof claimSig == "object"?JSON.stringify(claimSig):claimSig);

           let resp = await postDHExchange({
               "user_code":userCode,
               "bob_public_key":dhKey.publicKeyBase64,
               "bob_data":cipherText
           })

           return Object.assign(resp,{claim:claimSig});
    }

    async function getCert(finger_print){
      
      return new Promise((resolve,reject)=>{
          if(clientApp && clientApp.findCertificate(finger_print)){
               getLocalCert(finger_print).then((cert)=>resolve(cert));
                //return clientApp.findCertificate(finger_print);
          }        
          else
          {
              getCertChain(finger_print).then((chain)=>resolve(chain.certs.length>0?chain.certs[0]:null));
          }
      });    
    }

	async function getCertChainWithStatus(trustChain){
        if(SDK_MODE)
               return trustChain;
      
        let chainFingerPrints = [];
        for(let i=0;i<trustChain.length;i++)
          chainFingerPrints.push(trustChain[i].finger_print);
      	
        let chainStatus = await getCertChain(null,chainFingerPrints.join(","));
      
      	let _trustChain = [];
        for(let i=0;i<chainStatus.length;i++){
            let cert = JSON.parse(JSON.stringify(trustChain[i]));
            _trustChain.push(cert);
          
            if(chainStatus[i].notRegistered)
              continue;
          	
            cert.status =  chainStatus[i].status;
            cert.status_message =  chainStatus[i].status_message;
            cert.revocation_date =  chainStatus[i].revocation_date;

            cert.authority_status =  chainStatus[i].authority_status;
            cert.authority_status_message =  chainStatus[i].authority_status_message;
            cert.authority_suspension_date =  chainStatus[i].authority_suspension_date;
          
          	if(chainStatus[i].hasOwnProperty("isTrustworthy"))
              cert.isTrustworthy =  chainStatus[i].isTrustworthy;
          
            if(chainStatus[i].hasOwnProperty("issuer_finger_print"))
              cert.issuer_finger_print =  chainStatus[i].issuer_finger_print;
        }
      	return _trustChain;
    }

    async function getCertChain(finger_print,chain_health_check,ignoreIssuerPrivacy=true,ignoreLocalStore=false){
      	return new Promise((resolve,reject)=>{
            if(SDK_MODE)
               return resolve(chain_health_check?[]:{"certs":[]})
          
          
          	let params = chain_health_check?{
                    	"action":"get-cert-chain",
                      	"chain_health_check":chain_health_check
                    }:{
                      "action":"get-cert-chain",
                      "fingerprint":finger_print
            };
          
			sendRequest(params).
            then(function(resp){
              
                if(resp.status && resp.status != "failure"){
                	resolve(resp.chain);
                }
                else
                if(!ignoreLocalStore && clientApp && clientApp.findCertificate(finger_print))
                {
                  	getCertChainFromLocalStore(finger_print,chain_health_check,ignoreIssuerPrivacy).then((chain)=>{
                    	resolve(chain)
                    })
                    //exportCertificate(clientApp.findCertificate(finger_print).cert_text).then((cert)=>resolve({"certs":[Object.assign(cert,{"fromLocalStore":true})]}));
                }
                else
                {
                 	resolve({"certs":[]}); 
                }
            })
        });
    }

	async function getLocalCert(finger_print){
        if(clientApp){
            let certEntry = clientApp.findCertificate(finger_print);
            let certExport = await exportCertificate(certEntry.cert_text,Object.assign({"fromLocalStore":true},copyFromObject(certEntry,["issuer_finger_print"])))
            return {certExport,certEntry};
        }
    }

	function isLocalCert(finger_print){
        return (clientApp && clientApp.findCertificate(finger_print));
    }

	async function getCertChainFromLocalStore(finger_print,chain_health_check,ignoreIssuerPrivacy){
          //attempt to resolve chain, always prioritize registry lookup over 
          //local store or attached trust chains

          const certs = [];
          let cert = await getLocalCert(finger_print);
          certs.push(cert.certExport);

          const issuer = await getCertIssuerFingerPrint(cert.certExport);                        
          if(issuer != "Prometheus" && (ignoreIssuerPrivacy || !cert.certEntry.isUsingPrivateIssuer))
            certs.push(... (await getCertChain(issuer,chain_health_check,true)).certs);

      	  if(!ignoreIssuerPrivacy && cert.certEntry.isUsingPrivateIssuer)
            delete cert.certExport["issuer_finger_print"];
      
          return {"certs":certs};
    }

    async function wrapCertIdentity(idCertSig,spUri,enclosedSig,includeTrustChain,vouchedForClaimIdentities,isForPrivatePersona){
      
        let privateSPUri = await sha2Hex(spUri);
      	return new Promise((resolve,reject)=>{
			sendRequest({
                    	"action":"post-cert-identity",
                      	"id_anchor_cert_sig":idCertSig,
                        "sp_uri":privateSPUri,
                        "enclosed_sig":enclosedSig,
                      	"vouch_for_claim_identities":(vouchedForClaimIdentities && Array.isArray(vouchedForClaimIdentities)?JSON.stringify(vouchedForClaimIdentities):vouchedForClaimIdentities),
                      	"include_trust_chain":includeTrustChain,
                      	"is_private_persona":isForPrivatePersona
            }).
            then(function(resp){
                if(typeof resp.status == "undefined" || resp.status != "failure"){
                	resolve(resp);
                }
                else
                {                    
                 	alert(resp.message);
                }
            })
        });      
    }

    async function getTrackedSignature(sig_id){
      	return new Promise((resolve,reject)=>{
            if(SDK_MODE)
               return resolve({})
          
			sendRequest({
                      "action":"get-tracked-signature",
                      "sig_id":sig_id
            }).then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function getEncryptedIssuerFingerPrint(signer_signature){
      	return new Promise((resolve,reject)=>{
          
			sendRequest({
                      "action":"encrypt-issuer-fingerprint",
                      "signer_signature":(typeof signer_signature == "string"?signer_signature:JSON.stringify(signer_signature))
            }).then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function updateCertTrustchainPrivacy(signer_signature){
      	return new Promise((resolve,reject)=>{
          
			sendRequest({
                      "action":"update-cert-trustchain-privacy",
                      "signer_signature":(typeof signer_signature == "string"?signer_signature:JSON.stringify(signer_signature))
            }).then(function(resp){
                resolve(resp);
            })
        });      
    }

    function decodeCertificate(pem){
       return typeof pem == "string"?pkijs.Certificate.fromBER(fromPEM(pem)):pem;
    }

    function pemEncodeCert(cert){
     	return toPEM(cert.toSchema(true).toBER(false),"CERTIFICATE"); 
    }

    async function exportCertificate(cert,data){
        let decodedCert = typeof cert == "string"?decodeCertificate(cert):cert;
        let fingerPrint = await getCertFingerPrint(decodedCert);
      
        return Object.assign({
           "id":fingerPrint,
           "finger_print":fingerPrint,
           "issuer":getCertIssuer(decodedCert),
           "payload":getCertificatePayload(decodedCert),
           "cert_text":pemEncodeCert(decodedCert),
           "create_date":decodedCert.notBefore.value.getTime(),
           "validfrom_date":decodedCert.notBefore.value.getTime(),
           "expiration_date":decodedCert.notAfter.value.getTime(),
        },(data?data:{}));
    }

	async function extractCertPublicKey(pem){
     	let publicKey  = Object.assign(signAlg=="ECDSA"?{"kty":"EC","ext":true}:{"kty":"RSA","ext":true,"alg":"RS256"},decodeCertificate(pem).subjectPublicKeyInfo.parsedKey.toJSON());
        
        publicKey  = await crypto.subtle.importKey("jwk",publicKey,(signAlg=="ECDSA"?{
                  name:"ECDSA",
                  namedCurve: publicKey.crv,
                }:{
                  name: "RSASSA-PKCS1-v1_5",
                  hash: "SHA-256" 
         }),true,["verify"]);
        
		publicKey = await crypto.subtle.exportKey("spki",publicKey);
              
        return toPEM(publicKey,"PUBLIC KEY");
    }

    function getCertificatePayload(certObject){     
      let cert = typeof certObject == "string"?decodeCertificate(certObject):certObject;
      
      //extract payload
        for (let i = 0; i < cert.extensions.length; i++) {
          if(cert.extensions[i].extnID == "2.5.29.17"){

            let altNameBin = asn1js.fromBER(cert.extensions[i].extnValue.toBER(false)).result;              
            let altNames = pkijs.GeneralNames.fromBER(altNameBin.getValue());
            let altName = altNames.names[0].value;

            //let altName = altNameBin.valueBlock.value[0].valueBlock.value[0].valueBlock.value[0].valueBlock.value
            return JSON.parse(altName);
          }
        }      
      /*
      for (let i = 0; i < cert.attributes.length; i++) {

            if(cert.attributes[i].type == "1.2.840.113549.1.9.14"){        
              let extensions = pkijs.Extensions.fromBER(cert.attributes[i].values[0].toBER(false)).extensions;

              for (let j = 0; j < extensions.length; j++) {
                  if(extensions[j].extnID == "2.5.29.17"){

                       let altNameBin = asn1js.fromBER(extensions[j].extnValue.toBER(false)).result;              
                       let altNames = pkijs.GeneralNames.fromBER(altNameBin.getValue());
                       let altName = altNames.names[0].value;

                       //let altName = altNameBin.valueBlock.value[0].valueBlock.value[0].valueBlock.value[0].valueBlock.value
                       return JSON.parse(altName);
                  }
              }
              break;
            }
    	}
      */
      	return null;
    }

    function certPayloadHasField(cert,fieldName,fieldValue){
        let certPayload = getCertificatePayload(cert);

        if(certPayload != null && Object.keys(certPayload).length>0)
        	return ( certPayload.hasOwnProperty(fieldName) && (  (typeof fieldValue == "undefined") || (certPayload[fieldName] == fieldValue)) );

      	return false;
    }

    function getCertPayloadField(cert,fieldName){
        let certPayload = getCertificatePayload(cert);

        return certPayload[fieldName];
    }

    function getVerifiedCertificateField(fieldName,fields,sigVerified=false){
      //exec.logger().info("fieldName:"+fieldName+","+fields.size());
        for(let i =0;i<fields.length;i++){
            let field = fields[i];
            //exec.logger().info(field);
            if(Object.hasOwn(field.plainField, fieldName)){
              if(field.plainField.certificateVerified || sigVerified)
              	return field.plainField;
              else
              	return null;
            }
        }
      	return null;
    }
  
    function hasClaimField(fieldName,fields){
      //exec.logger().info("fieldName:"+fieldName+","+fields.size());
        for(let i =0;i<fields.length;i++){
            let field = fields[i];
            //exec.logger().info(field);
            if(Object.hasOwn(field.plainField?field.plainField:field, fieldName)){
               return true;
            }
        }
      	return false;
    }  

    async function verifyCertificateFields(signedString,signer,detachedPlainFields,contextLeafCert){
        let fieldVerification    = {"fields":[]};

        let signedStringPayloadText = signedString.substring(0,signedString.lastIndexOf("timestamp"));
        let signedPayload;
      
        if(!signedStringPayloadText.trim().startsWith("{") || !signedStringPayloadText.trim().endsWith("}"))
          	return fieldVerification;
      
        try
        {
        	signedPayload = JSON.parse(signedStringPayloadText);
        }
      	catch(error){
        	console.warn(`Failed to parse signedString for certificate field verification. ${error}`)
            return fieldVerification;
        }

        let isDetachedPlainFields = (typeof signedPayload.plainFields == "undefined" || signedPayload.plainFields == null);
      
      	let plainFields = !isDetachedPlainFields?signedPayload.plainFields:detachedPlainFields;
      
        if(plainFields)
        {
            let hmacKeys = plainFields.find(f=>f["pki-hmac-keys"])
            if(hmacKeys)
            	hmacKeys = JSON.parse(hmacKeys["pki-hmac-keys"]);
          
          	//exec.logger().info("verifyCertificateFields input fields:"+signedPayload.plainFields.size());
            for(let i=0;i<plainFields.length;i++)
            {
               let plainField = plainFields[i];
               let signedField = await findSignedFieldPeer(plainField,signedPayload,(hmacKeys?hmacKeys[i]:null));
              
               //ensure there is a match within signature, otherwise it is just junk tagged onto detached plainFields
               if(signedField)
               		fieldVerification.fields.push(signedField);
            }
        }
      
        let isEmptyClaim = typeof signedPayload.maskedFields == "undefined" || signedPayload.maskedFields == null;
      
        //if we're using plainFields detached from signature, ensure they haven't been tampered with
        if(isDetachedPlainFields && ((isEmptyClaim && fieldVerification.fields.length>0) || (!isEmptyClaim && signedPayload.maskedFields.length != fieldVerification.fields.length) )){
            //fieldVerification.fields = [];
            //fieldVerification["certificateVerified"]=false;
        	//return fieldVerification;
            console.warn(fieldVerification,plainFields,signedPayload)
            throw new Error("Signature tampering detected.")
        }

      	//exec.logger().info("verifyCertificateFields result:"+fieldVerification.fields.size()+",signedPayload.plainFields:"+signedPayload.plainFields);
        fieldVerification["certificateVerified"]=await verifyDocument(signer,fieldVerification.fields,false,contextLeafCert);
        return fieldVerification;
    }

    async function findSignedFieldPeer(field,signedPayload,hmacKey){
        /*
          TODO: Fix this function, it currently combines signature validation with hmac validation.
          hmac validation should happen only at data use stage, for instance when displaying on client ui
          or left to be performed by a service provider before accepting plain data attached to claims.
          
          Ultimately the goal of this function is to help ensure supplied data (plain or masked) matches signed data, ie prevent
          tampering.
        */
        let fieldName = Object.keys(field)[0];
        let fieldValue = field[fieldName];

      	if(signedPayload.maskedFields){
            for(let i=0;i<signedPayload.maskedFields.length;i++)
            {
                let maskedField = signedPayload.maskedFields[i];
              
                if(false && typeof maskedField["hmacKey"] == "undefined"){//treat it as a plain field...or already hmaced...**UNFINISHED business**
                    
                    let plainFieldName = Object.keys(maskedField)[0];
                    let plainFieldValue = maskedField[plainFieldName];

                    if(fieldName == plainFieldName && fieldValue == plainFieldValue)
                    {
                        let verifiedField = {};

                        let m = Object.assign({},plainField);
                        verifiedField["plainField"]=m;           
                        return verifiedField;
                    }
                }
                else
                {
                    for(let maskedFieldName in maskedField){

                        let maskedFieldValue = maskedField[maskedFieldName];
						if(!maskedFieldValue || !maskedFieldName || !isValidString(fieldValue) || !isValidString(fieldName))
                      		continue;
                      
                        if(true /*maskedFieldName != "hmacKey"*/)
                        {
                            //const hmacKey = hmacKeyMask && hmacKeyMask.hasOwnProperty(maskedField.hmacKey)?hmacKeyMask[maskedField.hmacKey]:maskedField.hmacKey;
                          
                            let {fieldName:fieldNameHash,fieldValue:fieldValueHash} = await hashPlainField(field,PUBLIC_PLAIN_FIELDS,null,false,hmacKey);
                            //perform hmac on plain data...future changes to this function should remove this approach
                            const dataIsHMACValidated = (fieldNameHash == maskedFieldName &&  fieldValueHash == maskedFieldValue)
                            //const dataIsHMACValidated = (hmacKey && hmacKey.length >0 && hmacHex(hmacKey,fieldNameHash) == maskedFieldName &&  hmacHex(hmacKey,fieldValueHash) == maskedFieldValue)

                            let {fieldName:fieldNameHash1,fieldValue:fieldValueHash1} = await hashPlainField(field,PUBLIC_PLAIN_FIELDS,null,false,hmacKey,true);
                            //perform hmac on hashed data...future changes to this function should remove this approach
                            const dataHashIsHMACValidated = (fieldNameHash1 == maskedFieldName &&  fieldValueHash1 == maskedFieldValue)

                            //assume data was hmaced before being included...this is better for privacy and doesn't require exposing
                            //hmac key to validation routine.
                            const dataIsHMACed = (fieldName == maskedFieldName && fieldValue == maskedFieldValue);
                            //const dataIsHMACed = (hmacHex(hmacKey,fieldName) == maskedFieldName && hmacHex(hmacKey,fieldValue) == maskedFieldValue);
                            
                            //console.log("findSignedFieldPeer:",fieldNameHash,fieldValueHash,hmacHex(hmacKey,fieldValue),hmacHex(hmacKey,fieldValueHash),fieldName,fieldValue);
                            //console.log("mask test fieldName:"+fieldName+"/"+hmacHex(maskedField.hmacKey,fieldName)+","+hmacHex(maskedField.hmacKey,fieldValue));
                            if(dataIsHMACed || dataHashIsHMACValidated || dataIsHMACValidated)
                            {
                                //console.log("passed mask test fieldName:"+fieldName+"/"+hmacHex(maskedField.hmacKey,fieldName)+","+hmacHex(maskedField.hmacKey,fieldValue));
                                let verifiedField = {};

                                let m = Object.assign({},field);
                                verifiedField["plainField"]=m;

                                m = Object.assign({},maskedField);
                                verifiedField["maskedField"]=m;
                              
                                //this is a hack to accomodate existing private certificates that have an hmac of their 
                                //corresponding plainFields instead of an hmac of the hash of their corresponding plainFields.
                                if(false && !(hmacHex(hmacKey,fieldName) == maskedFieldName && hmacHex(hmacKey,fieldValue) == maskedFieldValue)){                                  
                                    verifiedField["unhashedMaskedField"] = {[hmacHex(hmacKey,fieldName)]:hmacHex(hmacKey,fieldValue),"hmacKey":hmacKey};
                                }
                                return verifiedField;
                            }
                          	//else
                            //if(fieldName.startsWith("pki-plain-fields:"))
                            //  	console.log(maskedField,JSON.parse(fieldValueHash),JSON.parse(fieldValueHash1))
                        }
                    }
                }
            }
        }      

      	if(signedPayload.plainFields){
            for(let i=0;i<signedPayload.plainFields.length;i++)
            {
                let plainField = signedPayload.plainFields[i];
              
                let plainFieldName = Object.keys(plainField)[0];
                let plainFieldValue = plainField[plainFieldName];
              
				if(!isValidString(plainFieldName) || !isValidString(plainFieldValue) || !isValidString(fieldValue) || !isValidString(fieldName))
                   continue;
              
                if(fieldName == plainFieldName && fieldValue == plainFieldValue)
                {
                    //exec.logger().info("passed mask test fieldName:"+fieldName+"/"+hmacUtil.hmacHex(fieldName)+","+hmacUtil.hmacHex(fieldValue));
                    let verifiedField = {};

                    let m = Object.assign({},plainField);
                    verifiedField["plainField"]=m;           
                    return verifiedField;
                }
            }
        }

		return null;
    }

    async function getMatchingMaskedFields(plainFields,maskedFields,hmacKeyMask){
      
        let matchedMaskedFields = [];
        for(const plainField of plainFields){
            let fieldName    = Object.keys(plainField)[0];
            let fieldValue 	 = plainField[fieldName];

            //let fieldNameHash = await sha2Hex(fieldName);
            //let fieldValueHash = fieldValue?(await sha2Hex(fieldValue)):fieldValue;
      		let {fieldName:fieldNameHash,fieldValue:fieldValueHash} = await hashPlainField(plainField,PUBLIC_PLAIN_FIELDS);

          
          	let matched = false;
            for(const maskedField of maskedFields){
              	  if(!maskedField.hmacKey)
                    	continue;
              
                  let hmacKey = hmacKeyMask?hmacKeyMask[maskedField.hmacKey]:maskedField.hmacKey;
              
                  if((maskedField[hmacHex(hmacKey,fieldName)] == hmacHex(hmacKey,fieldValue))
                    ||
                     (maskedField[hmacHex(hmacKey,fieldNameHash)] == hmacHex(hmacKey,fieldValueHash))
                    ){
                     matchedMaskedFields.push(maskedField);
                     matched = true;
                     break;
                  }
            }
          	if(!matched)
              	return;
        }
      
        if(matchedMaskedFields.length>0)
          	return matchedMaskedFields;
    }

	function getFlatPlainFields(plainFields){
		let flatField = {};
        for(const plainField of plainFields){
			if(plainField.hasOwnProperty("name") && plainField.hasOwnProperty("value"))
          		flatField[plainField.name] = plainField.value;
          	else
              	flatField[Object.keys(plainField)[0]] = plainField[Object.keys(plainField)[0]];
        }
        return flatField;
    }

	async function hashPlainField(plainField,excludeFields=[],includeFields=[],excludeInternalFields=false,hmacKey,skipHash){
        const hashedPlainField 	= await getHashedPlainField(plainField,excludeFields,includeFields,excludeInternalFields,hmacKey,skipHash);
        let fieldName    	= Object.keys(hashedPlainField)[0];
        let fieldValue 	 	= hashedPlainField[fieldName];
      	return {fieldName,fieldValue};
    }

	function isValidString(str){
    	return !(typeof str == "undefined" || str == null)
    }

	async function getHashedPlainField(plainField,excludeFields=[],includeFields=[],excludeInternalFields=false,hmacKey,skipHash){
          
        let fieldName    = Object.keys(plainField)[0];
        let fieldValue 	 = plainField[fieldName];

        if(excludeFields && excludeFields.includes(fieldName))
          return plainField;

        if((excludeInternalFields && (fieldName.startsWith("pki-") || fieldName.startsWith("certisfy-"))) && (!includeFields || !includeFields.includes(fieldName)))
          return;
      	
      	let hashName 		= await sha2Hex(fieldName);
        let useName 		= skipHash?fieldName:hashName;
      
        let hashValue 		= isValidString(fieldValue)?(await sha2Hex(fieldValue)):fieldValue;
        let useValue 		= skipHash?fieldValue:hashValue;
      
        let fieldNameHash 	= (hmacKey && hmacKey.length>0)?hmacHex(hmacKey,useName):useName;
        let fieldValueHash  = (hmacKey && hmacKey.length>0) && isValidString(useValue)?hmacHex(hmacKey,useValue):useValue;      
      
        if(fieldName == "pki-hmac-keys"){//don't sha2 hmac keys
            if(hmacKey && hmacKey.length>0)
            	return {[hmacHex(hmacKey,"pki-hmac-keys")]:hmacHex(hmacKey,fieldValue)};
          
            return plainField;
        }
        else
        if(fieldName.startsWith("pki-plain-fields:")){//preserve structure while hashing
          	let hmacKeys;
          	let extractedPlainFields = JSON.parse(fieldValue);
          	if(hmacKey && extractedPlainFields.find(f=>f["pki-hmac-keys"])){
            	hmacKeys = extractedPlainFields.find(f=>f["pki-hmac-keys"])
                //extractedPlainFields.splice(1,extractedPlainFields.indexOf(hmacKeys));
              	hmacKeys = JSON.parse(hmacKeys["pki-hmac-keys"]);
            }
          
          	return {[fieldName]: JSON.stringify(await getHashedPlainFields(extractedPlainFields,PUBLIC_PLAIN_FIELDS,null,false,hmacKeys,skipHash)) };
        }
        else
        {            
            return {[fieldNameHash]:fieldValueHash};
        }
    }

    async function getHashedPlainFields(plainFields,excludeFields=[],includeFields=[],excludeInternalFields=false,hmacKeys,skipHash){
      
          let hashedPlainFields = [];
          for(let i=0;i<plainFields.length;i++){
              const plainField = plainFields[i];
            
              const hashedPlainField = await getHashedPlainField(plainField,excludeFields,includeFields,excludeInternalFields,(hmacKeys?hmacKeys[i]:null),skipHash);
              if(hashedPlainField)
                	hashedPlainFields.push(hashedPlainField);
          }
          return hashedPlainFields;
    }

	async function getUnHashedPlainField(hashPlainFields,plainField,hmacKey,skipHash){

        let fieldName = (plainField.name && Object.keys(plainField).length>1) ?plainField.name:Object.keys(plainField)[0];
        let fieldValue = (plainField.name && Object.keys(plainField).length>1)?plainField.value:plainField[fieldName];              

      	/*
      	let hashName 		= await sha2Hex(fieldName);
        let useName 		= skipHash?fieldName:hashName;
      
        let fieldNameHash 	= hmacKey?hmacHex(hmacKey,useName):useName;
        */
      	let {fieldName:fieldNameHash,fieldValue:fieldValueHash} = await hashPlainField(plainField,PUBLIC_PLAIN_FIELDS,null,false,hmacKey,skipHash);      
      
        if(fieldName.startsWith("pki-plain-fields:") && hashPlainFields.find(h=>(h.hasOwnProperty(fieldName)))){
          	let hmacKeys;
          	let extractedPlainFields = JSON.parse(fieldValue);
          	if(hmacKey && extractedPlainFields.find(f=>f["pki-hmac-keys"])){
            	hmacKeys = extractedPlainFields.find(f=>f["pki-hmac-keys"])
                //extractedPlainFields.splice(1,extractedPlainFields.indexOf(hmacKeys));
              	hmacKeys = JSON.parse(hmacKeys["pki-hmac-keys"]);
            }

          	return {[fieldName]: JSON.stringify(await getUnHashedPlainFields(JSON.parse(hashPlainFields.find(h=>(h.hasOwnProperty(fieldName)))[fieldName]),extractedPlainFields,hmacKeys,skipHash)) };
        }
        else
        {
          	/*
            let hashValue = fieldValue?(await sha2Hex(fieldValue)):fieldValue;
          	let useValue =  skipHash?fieldValue:hashValue;
            
            let fieldValueHash = hmacKey && useValue?hmacHex(hmacKey,useValue):useValue;
            */
            
            if(!hashPlainFields.find(h=>(h.hasOwnProperty(fieldNameHash) && h[fieldNameHash] == fieldValueHash)) &&
               !hashPlainFields.find(h=>(h.hasOwnProperty(fieldName) && h[fieldName] == fieldValue)) &&
               !hashPlainFields.find(h=>(h.hasOwnProperty(fieldNameHash) && h[fieldNameHash] == fieldValue)))
              return;

            return {[fieldName]:fieldValue};
        }
    }

	async function getUnHashedPlainFields(hashPlainFields,plainFields,hmacKeys,skipHash,ifPlainFieldEmptyReturnHashed=false){
      	  if(!plainFields || plainFields.length == 0){
              if(ifPlainFieldEmptyReturnHashed)
      			 return hashPlainFields;

              return [];
      	  }      

          let unHashedPlainFields = [];
          for(let i=0;i<plainFields.length;i++){
              const plainField = plainFields[i];

              const unHashedPlainField = await getUnHashedPlainField(hashPlainFields,plainField,(hmacKeys?hmacKeys[i]:null),skipHash);
              if(unHashedPlainField)
                	unHashedPlainFields.push(unHashedPlainField);
          }

          return unHashedPlainFields;    
    }

	async function extractClaimPlainFields(claim,verification,strict=false){
        let signedStringObject = JSON.parse(claim.signedString.substring(0,claim.signedString.lastIndexOf("}")+1));
        let plainFields = claim.plainFields?claim.plainFields:signedStringObject.plainFields;
        if(!plainFields)
          	plainFields = [];
      
		let usePlainField = [];
        usePlainField.push(...plainFields);
      
        /*
        let hashedPlainFields = claim.hmacedPlainFields;
        if(!hashedPlainFields)
      		hashedPlainFields = claim.hashedPlainFields; 
      
        
        //console.log("usePlainField1",usePlainField)
        usePlainField = hashedPlainFields?(await getUnHashedPlainFields(hashedPlainFields,usePlainField)):usePlainField;
        //console.log("usePlainField2",usePlainField)
      
      	if(!strict && usePlainField.length == 0 && hashedPlainFields)
          	usePlainField.push(...hashedPlainFields)
        */
      
        if(!verification)
          return usePlainField;
      
     	let verifiedPlainFields = [];
        for(const plainField of usePlainField){
            let fieldName    = Object.keys(plainField)[0];
            let fieldValue 	 = plainField[fieldName];

            //let fieldNameHash = await sha2Hex(fieldName);
            //let fieldValueHash = fieldValue?(await sha2Hex(fieldValue)):fieldValue; 

          	/*
          	let {fieldName:fieldNameHash,fieldValue:fieldValueHash} = await hashPlainField(plainField,PUBLIC_PLAIN_FIELDS);

            let verifiedField = verification.fieldVerification.fields.find(f=>((f.plainField.hasOwnProperty(fieldName) || f.plainField.hasOwnProperty(fieldNameHash)) && (f.plainField[fieldName] == fieldValue || f.plainField[fieldNameHash] == fieldValueHash)));
            if(verifiedField)
              verifiedPlainFields.push(plainField);
            */
          
            let verifiedField = verification.fieldVerification.fields.find(f=>((f.plainField.hasOwnProperty(fieldName)) && (f.plainField[fieldName] == fieldValue)));
            if(verifiedField)
              verifiedPlainFields.push(plainField);
        }
        return verifiedPlainFields;
    }

	async function unmaskFieldVerifications(context,plainFields){
        for(const plainField of plainFields){
             let fieldName    = Object.keys(plainField)[0];
             let fieldValue 	 = plainField[fieldName];

             let fieldNameHash = await sha2Hex(fieldName);
             let fieldValueHash = fieldValue?(await sha2Hex(fieldValue)):fieldValue; 
          
          	 let hashedPlainField = context.fieldVerification.fields.find(f=>(f.plainField.hasOwnProperty(fieldNameHash) && f.plainField[fieldNameHash] == fieldValueHash));
          	 if(hashedPlainField){
             	hashedPlainField.plainField[fieldName] = fieldValue;
                delete hashedPlainField.plainField[fieldNameHash];
             }
        }
    }

    function verifyCertChain(chain){
          //create new X.509 certificate chain object
          const certChainVerificationEngine = new pkijs.CertificateChainValidationEngine({
              trustedCerts:chain[0],//trusted cert
              certs: chain.slice(1,chain.length),//chain to verify
              crls:[],//revocations
          });
          return certChainVerificationEngine.verify();      
    }

	async function verifyPrivateCertChain(trustChain){
      	let validChain = true;
      
      	if(!trustChain.validfrom_date || !trustChain.expiration_date){
            if(trustChain.certs.length == 1 && issuerIsPrivate(trustChain.certs[0])  && isLocalCert(trustChain.certs[0]))//allow this, it useful for testing 
              return true;
          
          	return false;
        }
      
        //check valid from
        if(trustChain.validfrom_date>new Date().getTime()){
          //throw new Error(`Pretermed certificate(${issuerThumbprint}) in trust chain.`);
          console.warn(`Pretermed certificate in private trust chain.`);
          validChain = false;
        }
      
        //check expiry
        if(new Date().getTime()>trustChain.expiration_date){
          //throw new Error("Expired certificate in certificate chain.");
          console.warn(`Expired certificate in private trust chain.`);
          validChain = false;
        }
      
      	const signedString = [];
      
      	signedString.push(trustChain.certs[0].finger_print);
      
      	signedString.push(trustChain.validfrom_date);
        signedString.push(trustChain.expiration_date);
      
        signedString.push(trustChain.isValid);
        signedString.push(trustChain.isTrustworthy);

      	signedString.push(`timestamp=${trustChain.signature.timestamp}`);
      
        const signerCert = decodeCertificate(trustChainRoot.cert_text);
        let verified = await verifyText(signedString.join(""),trustChain.signature.signature,signerCert);
        
      	return (validChain && verified);
    }
    
	async function verifyDocument(signer,fields,flatten,contextLeafCert,hmacKeyMask){
      
        let signerCert = contextLeafCert;
      
        if(!signerCert){
            signerCert = typeof signer == "string"?await getCert(signer):signer;
            signerCert = typeof signer == "string"?signerCert.cert_text:signerCert;
        }
      	else
        {
          	//signerCert = await exportCertificate(signerCert);
        }
      
        if(fields.length == 0)
            return false;

        let verified = true;
        let payloadObject = getCertificatePayload(signerCert);
      
        if(payloadObject == null)
            return false;

      	let updatedFields = [];
        
        for(let i=0;i<fields.length;i++)
        {
            let  fieldContainer = fields[i];

            let plainField = fieldContainer.plainField;
            let maskedField = fieldContainer.maskedField;
          	let unhashedMaskedField = fieldContainer.unhashedMaskedField;

            let updatedFieldContainer = {};
            updatedFields.push(updatedFieldContainer);

          	let updatedPlainField = {};
          	let updatedMaskedField = {};
            let updatedUnhashedMaskedField = {};

          	if(plainField)
          	{
                Object.assign(updatedPlainField,plainField);
                updatedFieldContainer["plainField"]=updatedPlainField;
          	}

          	if(maskedField)
            {
                Object.assign(updatedMaskedField,maskedField); 
                updatedFieldContainer["maskedField"]=updatedMaskedField;
            }
          
            if(unhashedMaskedField)
            {
                Object.assign(updatedUnhashedMaskedField,unhashedMaskedField); 
                updatedFieldContainer["unhashedMaskedField"]=updatedUnhashedMaskedField;
            }

            let useMaskedField = unhashedMaskedField?unhashedMaskedField:maskedField;

            if(fieldContainer.maskedField)
            {
                if(flatten)
                {
                    let flattenMaskedField = {};
                    flattenMaskedField[useMaskedField.name]=useMaskedField.value;
                    flattenMaskedField["hmacKey"]=hmacKeyMask && hmacKeyMask.hasOwnProperty(useMaskedField.hmacKey)?hmacKeyMask[useMaskedField.hmacKey]:useMaskedField.hmacKey;
                    useMaskedField = flattenMaskedField;
                }

                for (let fieldName in useMaskedField)
                {
                    let fieldValue 	= useMaskedField[fieldName];
                    if(fieldName != "hmacKey")
                    {
                        if(typeof payloadObject[fieldName] != "undefined" && payloadObject[fieldName]==fieldValue)
                        {
                            updatedMaskedField["certificateVerified"]=true;
                            updatedPlainField["certificateVerified"]=true;
                        }
                        else
                        {
                            updatedMaskedField["certificateVerified"]=false;
                            updatedPlainField["certificateVerified"]=false;
                            verified = false;
                        }
                    }        
                }
            }
            else              
            {
                if(flatten)
                {
                    let flattenPlainField = {};
                    flattenPlainField[plainField.name]=plainField.value;
                    plainField = flattenPlainField;
                }

                for (let fieldName in plainField)
                {
                    let fieldValue 	= plainField[fieldName];
                    if(typeof payloadObject[fieldName] != "undefined" && payloadObject[fieldName]==fieldValue)
                    {
                      	updatedPlainField["certificateVerified"]=true;
                    }
                    else
                    {
                        updatedPlainField["certificateVerified"]=false;
                        updatedPlainField["certificateVerificationFailure"]="name/value pair mismatch";
                        verified = false;
                    }
                }
            }
        }

      	fields.splice(0,fields.length);
      	fields.push(...updatedFields);

        return verified;
    }

  	async function verifySignatureExpiry(signaturePayload,signatureVerification){
      
      	signatureVerification["signatureExpirationStatus"]="unspecified";
        signatureVerification["signatureValidFromStatus"]="unspecified";
      
        let signedStringText 	= signaturePayload.signedString.substring(0,signaturePayload.signedString.lastIndexOf("timestamp"));
        let signedStringObject;
      	let plainFields;
      
        if(signedStringText.trim().startsWith("{") && signedStringText.trim().endsWith("}"))
        {
              try
              {
                  /*signedStringObject   = JSON.parse(signedStringText);
                  plainFields = signedStringObject.plainFields?signedStringObject.plainFields:signaturePayload.plainFields;*/
                  plainFields = await extractClaimPlainFields(signaturePayload,signatureVerification);
              }
              catch(error){
                  console.warn(`Failed to parse signedString for certificate expiry verification. ${error}`)
              }
        }
      
      	//check valid from time if present
        if(hasClaimField("pki-valid-from-time",signatureVerification.fieldVerification.fields)){
            let validfromField = getVerifiedCertificateField("pki-valid-from-time",signatureVerification.fieldVerification.fields,true);
            if(validfromField == null){
                signatureVerification["signatureValidFromStatus"]="invalid";
            }
          	else
            {
                let validfromDateText = validfromField["pki-valid-from-time"].substring(0,validfromField["pki-valid-from-time"].indexOf(" ")).trim();
                let validfromTimeText = validfromField["pki-valid-from-time"].substring(validfromField["pki-valid-from-time"].indexOf(" ")).trim();

                let validfromDateTime = new Date();
                validfromDateTime.setUTCFullYear(parseInt(validfromDateText.split("/")[2]),parseInt(validfromDateText.split("/")[0])-1,parseInt(validfromDateText.split("/")[1]));
                validfromDateTime.setUTCHours(parseInt(validfromTimeText.split(":")[0].trim()));
                validfromDateTime.setUTCMinutes(parseInt(validfromTimeText.split(":")[1].trim()));              

                if(validfromDateTime.getTime()>new Date().getTime())
                  signatureVerification["signatureValidFromStatus"]="pretermed";
                else
                  signatureVerification["signatureValidFromStatus"]="valid";
            }
        }
      
      	//check expiration time if present
        if(hasClaimField("pki-expiration-time",signatureVerification.fieldVerification.fields)){
            let expiryField = getVerifiedCertificateField("pki-expiration-time",signatureVerification.fieldVerification.fields,true);
            if(expiryField == null){
                signatureVerification["signatureExpirationStatus"]="invalid";
            }
          	else
            {
                let expireDateText = expiryField["pki-expiration-time"].substring(0,expiryField["pki-expiration-time"].indexOf(" ")).trim();
                let expireTimeText = expiryField["pki-expiration-time"].substring(expiryField["pki-expiration-time"].indexOf(" ")).trim();
                let expireDateTime = new Date();
                expireDateTime.setUTCFullYear(parseInt(expireDateText.split("/")[2]),parseInt(expireDateText.split("/")[0])-1,parseInt(expireDateText.split("/")[1]));
                expireDateTime.setUTCHours(parseInt(expireTimeText.split(":")[0].trim()));
                expireDateTime.setUTCMinutes(parseInt(expireTimeText.split(":")[1].trim()));              

                if(expireDateTime.getTime()<new Date().getTime())
                  signatureVerification["signatureExpirationStatus"]="expired";
                else
                  signatureVerification["signatureExpirationStatus"]="valid";
            }
        }
    }

  	async function verifyPKIIdentity(signaturePayload,signatureVerification,spUri){
            let identityPayload   = signaturePayload["pki-identity"];
            
      		//console.log("pki-identity",identityPayload,signatureVerification,spUri);
            if(identityPayload)
            {
                let platformSignerCert = decodeCertificate(trustRoots[0].cert_text);

                if(identityPayload.cloaked_token)//for stickers
                {
                        //identity (relative to certisfy.com as service provider) is validated before sticker is issued
                  		signatureVerification["pkiIdentityReceiverMatch"]=true;
                  
                        //this works for server-side additional validation 
                  		/*
                      	let signatureEmbed = await getEmbededSignature(identityPayload.embed_id);
                        if(signatureEmbed != null)
                        {
                            let cloakedIdentity = await pkiHMAC([identityPayload.embed_id,[signaturePayload.signature]]);
                            if(cloakedIdentity != identityPayload.cloaked_token){//ensure the token is for this signature
                                  return;
                            }

                            let signatureEmbedObject = JSON.parse(signatureEmbed.signatureEmbed);
                            let signedStringText 	= signatureEmbedObject.signedString.substring(0,signatureEmbedObject.signedString.lastIndexOf("timestamp"));
                            let signedStringObject   = JSON.parse(signedStringText);

                            //get actual identity information
                            for(let i=0;i<signedStringObject.plainFields.length;i++)
                            {
                                let plainField = signedStringObject.plainFields[i];

                                if(typeof plainField.embeddedSignature != "undefined" && plainField.embeddedSignature != null)
                                {
                                    let cloakedIdentityPayload = identityPayload;
                                    let embeddedSignatureObject = JSON.parse(plainField.embeddedSignature);
                                    identityPayload = embeddedSignatureObject["pki-identity"];

                                    let coSignature = identityPayload["pki-cosignature"];
                                  	if(coSignature.signatureP1363)
                                      	coSignature.signature = coSignature.signatureP1363;
                                  
                                    let identitySigString = identityPayload["pki-id-anchor-element"]+identityPayload["pki-sp-id-anchor-token"]+identityPayload["pki-sp-identifier"]+signaturePayload.signature+"timestamp="+coSignature.timestamp;
                                    signatureVerification["pkiIdentityVerified"]= await verifyText(identitySigString,coSignature.signature,platformSignerCert);
                                    signatureVerification["pki-identity"]=cloakedIdentityPayload;                                  

                                    //if an spUri is provided, confirm that the identity spUri matches
                                    if(typeof spUri != "undefined" && spUri != null && spUri.length>0 && !spUri.includes(identityPayload["pki-sp-identifier"]))
                                        signatureVerification["pkiIdentityReceiverMatch"]=false;
                                    else
                                        signatureVerification["pkiIdentityReceiverMatch"]=true;

                                    break;
                                }
                            }
                         }
                        */
                }
                else
                {
                    let coSignature = identityPayload["pki-cosignature"];
                  	if(coSignature.signatureP1363)
                          coSignature.signature = coSignature.signatureP1363;
                  
                    let identitySigString = (identityPayload["pki-sp-id-anchor-token-persona"]?identityPayload["pki-sp-id-anchor-token-persona"]:"")+identityPayload["pki-id-anchor-element"]+identityPayload["pki-sp-id-anchor-token"]+identityPayload["pki-sp-identifier"]+signaturePayload.signature+"timestamp="+coSignature.timestamp;
                    signatureVerification["pkiIdentityVerified"]=await verifyText(identitySigString,coSignature.signature,platformSignerCert);                
                    signatureVerification["pki-identity"]=identityPayload;
                    
                    //if an spUri is provided, confirm that the identity spUri matches
                    if(typeof spUri != "undefined" && spUri != null/* && spUri.length>0*/ /*&& !spUri.includes(identityPayload["pki-sp-identifier"])*/){
                        let hashes = [];
                        for(let i=0;i<spUri.length;i++){
                          	if(spUri[i].startsWith("hash:"))
                              	hashes.push(spUri[i].substring(spUri[i].indexOf(":")+1))
                            else
                          		hashes.push(await sha2Hex(spUri[i]));
                        }
                      
                        signatureVerification["pkiIdentityReceiverMatch"]= (typeof hashes.find(uri=>(uri == identityPayload["pki-sp-identifier"] )) != "undefined");
                    }
                    else//??should this be false or true
                        signatureVerification["pkiIdentityReceiverMatch"]=true;
                  
                    //console.log(signatureVerification,identitySigString);
                }
            }
    }

    async function isIdentityCert(cert,fieldVerification){
      
        //id anchor cert must be issued by trust anchor
        let certVerification = await buildTrustedCertChain(cert.finger_print);
        if(!certVerification.certificateVerified)
        	return false;

        let trustChain = certVerification.chain;
      
        //does the id anchor cert have an identity anchor element (SSN,DLN..etc) on it
        for(let idElementKey in idAnchorElements)
        {
			let idElement = certField(cert,idElementKey,fieldVerification);
            if(idElement != null)
            {
				return true;
            }
        }
      	return false;
    }

    async function extractIdentityAnchorElement(idAnchorCertObj, cloakKeyMaterial){
      
            let idAnchorCert = decodeCertificate(idAnchorCertObj.cert_text);  

      		//For server-side extra validation. This will now be done by actual identity generation call
      		/*
            //id anchor cert must be issued by trust anchor      	
      		let certVerification = await buildTrustedCertChain(idAnchorCertObj.finger_print);
            
      		if(!certVerification.certificateVerified)
      			return null;
      
            let trustChain = certVerification.chain;
			*/
      
            let idAnchorCertPayload = getCertificatePayload(idAnchorCert);
            if(idAnchorCertPayload != null && Object.keys(idAnchorCertPayload).length>0)
            {
                //console.log(idAnchorCertObj,idAnchorCertPayload,idAnchorElements);
                //does the id anchor cert have an identity anchor element (SSN,DLN..etc) on it
                for(let idElementKey in idAnchorElements)
                {
                  	let mappedSignedDocument = [];
                  
                    let idAnchorEl = idElementKey;//idAnchorElements[idElementKey];
                    let signedAnchorEl = null;//idAnchorCertObj.csr.signedDocument.get(idAnchorEl);// != null?signerCertDocument.get(idAnchorEl):idAnchorCert.csr.signedDocument.get(idAnchorEl.toLowerCase());
                    for(let i=0;i<idAnchorCertObj.csr.signedDocument.length;i++)
                    {
                        let saEl = idAnchorCertObj.csr.signedDocument[i];
                        //create a plain hashmap version of document
                        let mappedDocField = {};
                      	mappedSignedDocument.push(mappedDocField);
                      
                      	let mappedDocPlainField = {};
                      	Object.assign(mappedDocPlainField,saEl.plainField);                      
                      	mappedDocField["plainField"]=mappedDocPlainField;                        
                      
                        if(saEl.maskedField)
                      	{
                            let mappedDocMaskedField = {};
                            Object.assign(mappedDocMaskedField,saEl.maskedField);                      
                            mappedDocField["maskedField"]=mappedDocMaskedField;
                      	}
                        //console.log("loop"+i,saEl,idAnchorEl)
                        if(saEl.plainField.name == idAnchorEl)
                        {
                            signedAnchorEl = saEl.plainField.value.toUpperCase().replaceAll("-","").replaceAll(" ","").toUpperCase();                            
                            //break;
                        }
                    }

                    if(signedAnchorEl != null)
                    {
                        //console.log("Found identity anchor element "+idAnchorEl);
						return {
                          "cert":idAnchorCert,
                          "element":signedAnchorEl,
                          "elementName":idAnchorEl
                        };
                      
                      	//For server-side additional validation
                      	/*
                        //verify that the id anchor cert contains supplied document
                        if(await verifyDocument(idAnchorCert,mappedSignedDocument,true))
                        {                          
                            console.log("identity anchor element document verified");
                          
                          	let result = {
                              "cert":idAnchorCert,
                              "element":signedAnchorEl,
                              "elementName":idAnchorEl
                            };
                          
                            if(cloakKeyMaterial != null && cloakKeyMaterial.length>0){
                                  //create cloaked id as a sort of key-material/salt + public key finger print
                                  result["ownerIdCloak"]= await pkiHMAC([idAnchorCertObj.finger_print+cloakKeyMaterial])+","+cloakKeyMaterial;
                            }
                          
							return result;
                        }
                        */
                    }
                }
            }
        	return null;
    }

    async function attachIdentity(element,elementName,pkiSpUri,enclosedSig,idAnchorCertObj,includeTrustChain,vouchedForClaimIdentities,isForPrivatePersona){
        let isVersioned = certPayloadHasField(idAnchorCertObj.cert_text,"pki-cert-version");
      
        let idFields = await selectCertFields([elementName+(isVersioned?"":"_HASH")],idAnchorCertObj,null);
      
        //hash id before sending it
        if(isVersioned){
            let plainField = idFields.plainFields[0];
          
          	let idField = {
              "name":(await sha2Hex(Object.keys(plainField)[0])),
              "value": (await sha2Hex(plainField[Object.keys(plainField)[0]])),
              "hmacKey":idFields.maskedFields[0].hmacKey
            };
            
            plainField[idField.name] = idField.value;
            delete plainField[Object.keys(plainField)[0]];
          
            idFields.maskedFields.splice(0,idFields.maskedFields.length);
   			let maskedField = await createPrivateField(idField,false);
            idFields.maskedFields.push(maskedField);       
        }
      	const plainFields = idFields.plainFields;
      	delete idFields.plainFields;
      
        let idCertSig = await signClaim(idAnchorCertObj,JSON.stringify(idFields),plainFields,null,pkiSpUri,includeTrustChain);
        idCertSig["hashedPlainFields"] = idCertSig.plainFields;//id plainFields is already hashed
        delete idCertSig["plainFields"];
      	delete idCertSig["hmacedPlainFields"];
      
        return await wrapCertIdentity(JSON.stringify(idCertSig),pkiSpUri,enclosedSig,includeTrustChain,vouchedForClaimIdentities,isForPrivatePersona);
    }

    async function buildSPIdentityAnchorSignature(idAnchorCertObj,pkiSpUri,signatureObject,signer,includeTrustChain,vouchedForClaimIdentities,isForPrivatePersona){
            if(pkiSpUri == null || pkiSpUri.length == 0)
                return null;      
      		
      		let idAnchor = await extractIdentityAnchorElement(idAnchorCertObj);
      
            //verify that the id anchor cert contains supplied document
            if(idAnchor != null)
            {
              //For server-side extra validation
              /*
              //console.log("identity anchor element document verified:"+signatureObject.signedString);             
              let fieldVerification = await verifyCertificateFields(signatureObject.signedString,signatureObject.signerID);
              //console.log(fieldVerification)
              //console.log("isIdentityCert:"+isIdentityCert(signerCert,fieldVerification));
              //console.log(await isIdentityCert(signer,fieldVerification))
              
              //verify the id link, identity anchor certs carry their identity
              if(!await isIdentityCert(signer,fieldVerification) || signer.finger_print != idAnchorCertObj.finger_print)
              {                  
                  let signerIdLink = certField(signer,"pki-id-link",fieldVerification);
                  //console.log("pki-id-link",signerIdLink,fieldVerification,signer);
                  //console.log("certField pki-id-link:"+signerIdLink);
                  if(signerIdLink == null)
                        return null;

                  let cloakKeyMaterial  = signerIdLink.split(",")[0];
                  let cloakPublicKey    = signerIdLink.split(",")[1];
                  let cloakPrivateKey   = idAnchorCertObj.finger_print;

                  let cloakSignerIdLink = await pkiHMAC([cloakPrivateKey+cloakPublicKey])+","+cloakPublicKey;

                  if(cloakSignerIdLink != signerIdLink)
                        return null;
              }
              */
      		  return await attachIdentity(idAnchor.element,idAnchor.elementName,pkiSpUri,JSON.stringify(signatureObject)/*signatureObject.signature*/,idAnchorCertObj,includeTrustChain,vouchedForClaimIdentities,isForPrivatePersona);
            }
      		return null;
    }

    async function buildTrustedCertChain(fingerPrint,useChain){
		let certChainVerification = await buildCertChain(fingerPrint,true,useChain);

        if(certChainVerification.certificateVerified && (certChainVerification.chain.length>1))
      		certChainVerification["certificateVerified"] = await isTrustedChain(certChainVerification.chain);

        return certChainVerification;
    }

   /*
    * chain constructed via this call is what's considered trust chain.
    */
    async function buildCertChain(finger_print,validate,useChain){
        let certChain = [];
        let certVerification = {};
      
        let validChain = true;
        let chain = (useChain && typeof useChain == "object" && !Array.isArray(useChain))?useChain.certs:useChain;
        if(!chain || chain.length == 0){
        	 let trustChain = await getCertChain(finger_print);
             if(trustChain && trustChain.certs)
               chain = trustChain.certs;
             else
               chain = [];
        }
      
        if(chain.length == 0)
        {
          	console.warn(`Empty trust chain.`);
          	certVerification["certificateVerified"]=false;
        	certVerification["chain"]=[];
        	return certVerification;
        }
      
        let cert = decodeCertificate(chain[0].cert_text);
        chain[0].validFrom = cert.notBefore.value.getTime();
      
        //check valid from
        if(validate && cert.notBefore.value.getTime()>new Date().getTime()){
          //throw new Error(`Pretermed certificate(${issuerThumbprint}) in trust chain.`);
          console.warn(`Pretermed certificate in trust chain.`);
          validChain = false;
        }
      
        //check expiry
        if(validate && new Date().getTime()>cert.notAfter.value.getTime()){
          //throw new Error("Expired certificate in certificate chain.");
          console.warn("Expired certificate in certificate trust chain.");
          validChain = false;
        }

        if(validate && (chain[0].status && chain[0].status != "good")){
			console.warn("Revoked certificate in certificate trust chain.");
            validChain = false;
        }
      	//console.log(new Date().getTime(),">",cert.notAfter.value.getTime(),(new Date().getTime()>cert.notAfter.value.getTime()));      	
      	//console.log(new Date(),">",cert.notAfter.value,(new Date().getTime()>cert.notAfter.value.getTime()));      	
      
        let leafCert = cert;
        
        certVerification["certificateVerified"]=false;
        certVerification["chain"]=certChain;
      
        certChain.push(await exportCertificate(leafCert,copyFromObject(chain[0],["issuer_finger_print","isTrustworthy"])));
      
        if(chain[0].status){
           certChain[certChain.length-1].status = chain[0].status;
           if(chain[0].status_message)
             	certChain[certChain.length-1].status_message = chain[0].status_message;
          
           if(chain[0].revocation_date)
             	certChain[certChain.length-1].revocation_date = chain[0].revocation_date;
        }
      
        if(chain[0].authority_status){
           certChain[certChain.length-1].authority_status = chain[0].authority_status;
           if(chain[0].authority_status_message)
             	certChain[certChain.length-1].authority_status_message = chain[0].authority_status_message;
          
           if(chain[0].authority_suspension_date)
             	certChain[certChain.length-1].authority_suspension_date = chain[0].authority_suspension_date;
        }

      	if(isTrustChainRoot(finger_print))
        {
            certVerification["certificateVerified"]= (validate && validChain);
            return certVerification;
        }
      
		if(chain.length == 1 && issuerIsPrivate(chain[0])){
            let isValidPrivateChain = (useChain && typeof useChain == "object" && !Array.isArray(useChain))?(await verifyPrivateCertChain(useChain)):false;
          	//console.log("platform validate",isValidPrivateChain,validate,validChain/*,chain[0].isTrustworthy*/)
			certVerification["certificateVerified"]= (validate && validChain && isValidPrivateChain /*&& chain[0].isTrustworthy*/);
            return certVerification;
        }      
      
        try
        {
            //first verify and build cryptographic chain relationship
            for(let i=1;i<chain.length;i++)
            {
              	let certData = chain[i-1];
                let issuerCertPEM = chain[i].cert_text;

                let certFingerPrint = await getCertFingerPrint(cert);
                let issuerThumbprint = await getCertIssuerFingerPrint(certData)/*.substring(3)*/;
              
                //console.log("Checking issuer:"+issuerThumbprint);

                let issuerCert = decodeCertificate(issuerCertPEM);
                let computedIssuerThumbprint = await getCertFingerPrint(issuerCert);

              	//chain[i].validfrom_date = issuerCert.notBefore.value.getTime();
                if(issuerThumbprint == computedIssuerThumbprint)
                {
                    if(validate && !verifyCertChain([issuerCert,cert]))
                      	throw new Error(`Unable to verify trust chain(${certFingerPrint},${issuerThumbprint})`);

                    //check valid from
                    if(validate && issuerCert.notBefore.value.getTime()>new Date().getTime()){
                      	//throw new Error(`Pretermed certificate(${issuerThumbprint}) in trust chain.`);
                        console.warn(`Pretermed certificate(${issuerThumbprint}) in trust chain.`);
                        validChain = false;
                    }
                  
                    //check expiry
                    if(validate && new Date().getTime()>issuerCert.notAfter.value.getTime()){
                      	//throw new Error(`Expired certificate(${issuerThumbprint}) in trust chain.`);
                        console.warn(`Expired certificate(${issuerThumbprint}) in trust chain.`);
                        validChain = false;
                    }

                  	if(validate && (chain[i].status && chain[i].status != "good")){
                        console.warn(`Revoked certificate(${issuerThumbprint} in cert trust chain.`);
                        validChain = false;
                    }
                  
                    if(validate && (chain[i].authority_status && chain[i].authority_status != "good")){
                        if(cert.notBefore.value.getTime() >= chain[i].authority_suspension_date){
                            console.warn(`Suspended certificate(${issuerThumbprint} in cert trust chain before certificate was issued.`);
                            validChain = false;
                        }
                    }
                  
                    let exportedCert = await exportCertificate(issuerCert,copyFromObject(chain[i],["issuer_finger_print","isTrustworthy"]));
                    certChain.push(exportedCert);
                  
                    if(chain[i].status){
                       certChain[certChain.length-1].status = chain[i].status;
                       if(chain[i].status_message)
                            certChain[certChain.length-1].status_message = chain[i].status_message;
                      
                       if(chain[i].revocation_date)
             				certChain[certChain.length-1].revocation_date = chain[i].revocation_date;
                    }
                  
                    if(chain[i].authority_status){
                       certChain[certChain.length-1].authority_status = chain[i].authority_status;
                       if(chain[i].authority_status_message)
                            certChain[certChain.length-1].authority_status_message = chain[i].authority_status_message;

                       if(chain[i].authority_suspension_date)
                            certChain[certChain.length-1].authority_suspension_date = chain[i].authority_suspension_date;
                    }

                    cert = issuerCert;

                    if(isTrustChainRoot(computedIssuerThumbprint))
                    {
                       certVerification["certificateVerified"]= ((typeof validate != "undefined" && validate == true) && validChain);
                       return certVerification;
                    }
                    continue;
                }
                else
                {
                   throw new Error(`invalid certificate(${issuerThumbprint},${computedIssuerThumbprint}) in trust chain, invalid issuer for ${certFingerPrint}.`);
                }                
            }
			//this means either trust chain root is bypassed or chain is empty
            return certVerification;
        }
        catch(e)
        {
            console.error("buildTrustedCertChain Error",e);
        }

        certVerification["certificateVerified"]=false;
        certVerification["chain"]=[];
        return certVerification;
    }

    async function isIssuedBy(cert,issuer,strictCheck=false){
        let certObject = decodeCertificate(cert.cert_text);
        let issuerCertObject = decodeCertificate(issuer.cert_text);

      	let certThumbprint = await getCertFingerPrint(certObject);
        let issuerThumbprint = await getCertFingerPrint(issuerCertObject);
      
      	if(certThumbprint == issuerThumbprint && strictCheck)
      		return false;

        //console.log("isIssuedBy:"+certObject.verify(issuerCertObject.getPublicKey()));
        //console.log("isIssuedBy:"+(certObject.getIssuerX500Principal() != null && certObject.getIssuerX500Principal().equals(DigestUtils.sha1Hex(issuerCertObject.getEncoded())))+"/"+issuerThumbprint+"/"+certObject.getIssuerX500Principal());
        try
        {              
            if(!verifyCertChain([issuerCertObject,certObject]))
               throw new Error("Unable to verify issuer trust chain.");
          
            //console.log(certThumbprint+" isIssuedBy:"+issuerThumbprint,((await getCertIssuerFingerPrint(cert)) == issuerThumbprint),cert);
            return ((await getCertIssuerFingerPrint(cert)) == issuerThumbprint);
        }
        catch(error)
        {
            console.error(error);
        }

        return false;
    }

   /*
    * A valid trust anchor chain is one that:
    *    -1. either consists of only root 
    *    -2. or consists of only root and leaf, and leaf is issued by root 
    *    -3. or leaf is a delegate to a cert (up chain) that satisfies condition 2.
    *
    * rootCert:chain[chain.size()-1]
    * leafCert:chain[0]
    *
    * conds 1 & 2 makes you a trust anchor, cond 3 makes you a delegate with 
    * the authority to issue trustworthy certs.
    */
    async function isValidTrustAnchorChain(chain){
        if(chain.length <1)
      		return false;

      	if(chain.length == 1)
			return isTrustChainRoot(chain[0].finger_print);
      
        //validate root
        if(!isTrustChainRoot(chain[chain.length-1].finger_print))
      		return false;
      
        //console.log(chain[chain.length-1].cert_text)
        let rootCert = chain[chain.length-1];
        let leafCert = chain[0];

        if(chain.length == 2)//if the leaf cert itself is a trust anchor
            return (await isIssuedBy(leafCert,rootCert));       
		
        leafCert = chain[chain.length-2];
        //validate trust anchor
        if(!(await isIssuedBy(leafCert,rootCert)))
      		return false;

      	//if trust anchor didn't issue it then validate delegation chain
        //skip root and validate the rest of the chain as delegates
        return isValidDelegationChain(chain.toSpliced(chain.length-1,1));
    }  

   /*
    *A chain is trusted if 
    *	1. it is a trust anchor chain or 
    *	2. the leaf is issued by a trust anchor chain
    *
    *possible structures of a trusted chain:
    *	1. root
    *	2. trust anchor>root
    *	3. [one or more delegates]>trust anchor>root>
    *	4. trusted cert>[zero or more delegates]>trust anchor>root
    */
    async function isTrustedChain(chain){
        //cond 1. it is a trust anchor chain, 
        //  a). chain.size() ==1 and chain[0] is root 
        //  b). chain.size() ==2 and chain[1] is root, chain[0] is issued by root (ie trust anchor)
		if(chain.length<3)
      		return isValidTrustAnchorChain(chain);
      
        let issuerCert = chain[1];
        let leafCert = chain[0];
        //cond 2. leaf is issued by a trust anchor chain,
      	//  a). the leaf could itself be a trust anchor delegate, 
      	//	    in that case whole chain is a trust anchor chain.
      	//  b). or leaf is a trusted cert
        //console.log(await isValidTrustAnchorChain(chain),await isValidTrustAnchorChain(chain.slice(1,chain.length)),await isIssuedBy(leafCert,issuerCert))
      	return (await isValidTrustAnchorChain(chain) || (await isValidTrustAnchorChain(chain.slice(1,chain.length)) && await isIssuedBy(leafCert,issuerCert)) );
    }
  
    function isTrustRoot(fingerPrint){            
      	return (fingerPrint == trustRoots[0].finger_print);
    }  
  
    function isTrustChainRoot(fingerPrint){            
      	return (trustChainRoot.finger_print == fingerPrint);
    }
    
   /*
    * A trust anchor is either, root, a trust anchor (issued by root) or trust anchor delegate.
    * ie the leaf in a trust chain.
    */  
    async function isTrustAnchor(cert,useChain){
        let fingerPrint = await getCertFingerPrint(cert);
		let certChainVerification = await buildCertChain(fingerPrint,true,useChain);
        
        let chain = certChainVerification.chain;
      
      	if(certChainVerification.certificateVerified){
            return  isValidTrustAnchorChain(chain);
        }
        return false;
    }

   /*
    * has right if 
    * 1. it is on a valid trust anchor chain 
    * 2. and the delegationLevel requested is less than pki-maximum-delegates of issuer.
    *
    */
    async function hasDelegationRight(issuerCert,delegationLevel) {
        //cond 1.
        let issuerCertFingerPrint = await getCertFingerPrint(issuerCert);
        if(isTrustChainRoot(issuerCertFingerPrint))
      		return true;
      
      	let trustAnchor = await isTrustAnchor(issuerCert);
		if(!trustAnchor)
      		return false;
      
        //cond 2.
        let issuerCertPayload = getCertificatePayload(issuerCert);  

        //confirm that this would be a valid delegation chain if the delegationLevel is granted
        if(issuerCertPayload["pki-maximum-delegates"] && (parseInt(issuerCertPayload["pki-maximum-delegates"]) > delegationLevel))
        {
            return true;
        }
      	return false;
    }

   /*
    * validation involves
    *	1. Ensure the delegated trust chain length is less than pki-maximum-delegates 
    *	   of trust anchor. chain is rooted at trust anchor.
    *   2. Ensure that cond 1. holds at every level below trust anchor in the 
    *      delegated trust chain. In other words a delegate can only delegate below the level
    *	   of delegation of it's immediate issuer.
    *
    */
    function isValidDelegationChain(chain){
        
        //if issued by a delegate, check that delegation level is valid  
        let delegationLevel = chain.length-1;//move to root of delegation (ie minus trust anchor)
		let cumulativeDelgation = 0;
      
        let trustAnchorCert = decodeCertificate(chain[delegationLevel].cert_text);  
        let trustAnchorCertPayload = getCertificatePayload(trustAnchorCert);  

        //cond 1.
        if(typeof trustAnchorCertPayload["pki-maximum-delegates"] == "undefined" ||
           trustAnchorCertPayload["pki-maximum-delegates"] == null ||
           !(parseInt(trustAnchorCertPayload["pki-maximum-delegates"]) >= delegationLevel) )
        	return false;
      
      	//cond 2.
        //extra sanity check, verify delegation chain
        let parentDelgationLevel = parseInt(trustAnchorCertPayload["pki-maximum-delegates"]);
        
        for(let i=delegationLevel-1; i>=0;i--)
        {
            let issuerCert = decodeCertificate(chain[i].cert_text)
            let issuerCertPayload = getCertificatePayload(issuerCert);
          	
            if(typeof trustAnchorCertPayload["pki-maximum-delegates"] == "undefined" || issuerCertPayload["pki-maximum-delegates"] == null || parseInt(issuerCertPayload["pki-maximum-delegates"])<0)
            	return false;

            if(parseInt(issuerCertPayload["pki-maximum-delegates"]) >= parentDelgationLevel)
          		return false;
          
            parentDelgationLevel = parseInt(issuerCertPayload["pki-maximum-delegates"]);
        }
        
      	return true;
    }

  	function certField(cert,fieldName,fieldVerification){
        for(let i=0;i<fieldVerification.fields.length;i++)
        {
            let fieldContainer=fieldVerification.fields[i];
          
			if(fieldContainer.plainField[fieldName])
            {
				if(fieldContainer.plainField.certificateVerified)
                {
                    if(fieldContainer.maskedField)
                  	{
                        if(fieldContainer.maskedField.certificateVerified)
                            return fieldContainer.plainField[fieldName];    
                  	}
                    else
                    return fieldContainer.plainField[fieldName];                  
                }
              	break;
            }
        }
      	return null;
    }

	async function createPrivateField(field,hashInput=true){
        let plainField = {};
        plainField[field.name] = field.value;
      
        if(field.name == "pki-asym-encryption-key")
          	return plainField;        
      
      	let hmacKey = field.hmacKey?field.hmacKey:randomUUID().replaceAll("-","");
      
        //hash structurally instead of blindly hashing
        const hashedPlainField = await hashPlainField(plainField,PUBLIC_PLAIN_FIELDS,null,false,hmacKey,!hashInput);
        let {fieldName:privateFieldName,fieldValue:privateFieldVal} = hashedPlainField;

      	if(!isValidString(privateFieldName) || !isValidString(privateFieldVal) || privateFieldName.length == 0 || privateFieldVal.length == 0 || !isValidString(field.name) || !isValidString(field.value)){
            console.error(`Invalid field, unable to create private field.`,field)
            throw `Invalid field, unable to create private field.`;
        }

        let maskedField = {};
        //let privateFieldName =hmacHex(hmacKey,hashInput?hashedPlainField.fieldName:field.name);
        //let privateFieldVal  =hmacHex(hmacKey,hashInput?hashedPlainField.fieldValue:field.value);      
        //let privateFieldName =hashInput?hashedPlainField.fieldName:field.name;
        //let privateFieldVal  =hashInput?hashedPlainField.fieldValue:field.value;
      
        maskedField[privateFieldName]=privateFieldVal;
        maskedField["hmacKey"] = hmacKey;
      
      	return maskedField;
    }

    async function selectCertFields(fields,cert,_selectedFields){

        return new Promise(async (resolve,reject)=>{
            let selectedFields = _selectedFields?_selectedFields:[];
            let plainFields = [];
            let maskedFields = [];          

            for(let i=0;i<fields.length;i++)
                selectedFields.push(cert.csr.signedDocument.find(f=>f.plainField.name == fields[i]));

            //attach verified fields
            for(const field of selectedFields){    
                let plainField = {};
                plainField[field.plainField.name]=field.plainField.value;
                plainFields.push(plainField);

                if(field.maskedField)
                {
                    let maskedField = {};
                    maskedField[field.maskedField.name]=field.maskedField.value;
                    maskedField["hmacKey"] = field.hmacKey?field.hmacKey:field.maskedField.hmacKey;
                    maskedFields.push(maskedField);
                }
                else
                {
                    let maskedField = await createPrivateField(field.plainField);
                    maskedFields.push(maskedField);
                }
            }

            resolve(Object.assign({},{"plainFields":plainFields,"maskedFields":maskedFields}));
        });
    }

	function filterFields(fields,filter){
        let filteredFields = [];
        for(let i=0;i<filter.length;i++){
            for(let j=0;j<fields.length;j++){
                if(fields[j][filter[i]]){
                    filteredFields.push(fields[j]);
                    break;
                }
            }
        }
        return filteredFields;
    }

	function textToClaimObject(text){
		if(text && text.trim().startsWith("{") && text.trim().endsWith("}")){
            try
            {
              const obj = JSON.parse(text);
              if(obj.certisfy_object && obj.signerID)
                	return obj;
            }
            catch(error){
            }
        }    
    }

	async function maskClaimPlainFields(plainFields,textPlainFields = [],skipTextFields=false){
        if(plainFields){
            const claimPlainFields = [];
          
            for(const plainField of plainFields){
                const plainFieldName = Object.keys(plainField)[0]
              	const claim = textToClaimObject(plainField[plainFieldName]);

                if(claim && claim.plainFields && Array.isArray(claim.plainFields)){
                    claim.plainFields = await maskClaimPlainFields(claim.plainFields,textPlainFields);
                    let usePlainFieldName = !plainFieldName.startsWith("pki-")?(await sha2Hex(plainFieldName)):plainFieldName;

                	claimPlainFields.push({[usePlainFieldName]:JSON.stringify(claim)});
                }
              	else
                if(!skipTextFields)
                {
                    if(!["pki-valid-from-time","pki-expiration-time"].includes(plainFieldName))
                      claimPlainFields.push({[(await sha2Hex(plainFieldName))]:(await sha2Hex(plainField[plainFieldName]))});
                    else
                      claimPlainFields.push({[plainFieldName]:plainField[plainFieldName]});                	
                }
                textPlainFields.push(plainField);
            }
            return claimPlainFields;
        }
    }

	function fieldsContainVouchedForClaims(plainFields){
      
      	if(!plainFields)
          	return false;
      
        for(let plainField of  plainFields){
            const plainFieldName = Object.keys(plainField)[0];

            //this means claim is a vouch claim
            if(plainFieldName.startsWith("pki-vouch-for-claim") && textToClaimObject(plainField[plainFieldName]))
              	return true;
        }
    }

	function claimContainsVouchedForClaims(presentingClaim){
      
      	if(!presentingClaim.plainFields)
          	return false;
      
        for(let plainField of presentingClaim.plainFields){
            const vouchClaim = textToClaimObject(plainField[Object.keys(plainField)[0]]);

            if(vouchClaim && fieldsContainVouchedForClaims(vouchClaim.plainField))
                return true;            
        }
    }

	async function maskEmbeddedClaimsPlainFields(presentingClaim,type){
        if(false && type == "vouch" && claimContainsVouchedForClaims(presentingClaim)){
            let textPlainFields = [];
          	let claimFields = await maskClaimPlainFields(presentingClaim.plainFields,textPlainFields);
          	presentingClaim["embeddedClaimsPlainFields"] = {"claimFields":claimFields,"textFields":textPlainFields};
        }
    }

    function filterPlainFields(plainFields,filter){
        if(plainFields.find(f=>f["pki-hmac-keys"])){
            let hmacKeys = JSON.parse(plainFields.find(f=>f["pki-hmac-keys"])["pki-hmac-keys"]);

            let filteredHMACKeys = []          
            let filteredFields = [];
          
            for(let i=0;i<filter.length;i++){
                for(let j=0;j<plainFields.length;j++){
                    if(plainFields[j][filter[i]]){
                        filteredFields.push(plainFields[j]);
                        filteredHMACKeys.push(hmacKeys[j])
                        break;
                    }
                }
            }            
          
            //last entry represents the pki-hmac-keys field's hmac key
            filteredHMACKeys.push(hmacKeys[hmacKeys.length-1]);
            filteredFields.push({"pki-hmac-keys":JSON.stringify(filteredHMACKeys)})
          
            return filteredFields;
        }
      
        return filterFields(plainFields,filter);
    }

	function publicPlainFields(signature){
      
    	if(signature.plainFields)
          	return signature.plainFields;
      
    	if(signature.hashedPlainFields)
          	return signature.hashedPlainFields;
      
    	if(signature.hmacedPlainFields)
          	return signature.hmacedPlainFields;
    }

	function setPlainFields(signature){
        const claim = JSON.parse(JSON.stringify(signature));//clone
      
      	delete claim["hashedPlainFields"];
      	delete claim["hmacedPlainFields"];
      
      	if(publicPlainFields(signature))
      		claim["plainFields"] = publicPlainFields(signature);
      
      	return claim;
    }

	async function attachHMACKeys(stringToSign,plainFields){
        
      	const stringToSignObject = JSON.parse(stringToSign);
		if(stringToSignObject.maskedFields){
            const hmk = randomUUID().replaceAll("-","");
            let auxField = {
              "name":("pki-hmac-keys"),
              "value":JSON.stringify(stringToSignObject.maskedFields.map(f=>f.hmacKey).concat([hmk])),
              "hmacKey":hmk
            }
            let plainField = {};
            plainField[auxField.name]=auxField.value;
            plainFields.push(plainField);

            let maskedField = await createPrivateField(auxField);
            stringToSignObject.maskedFields.push(maskedField);
          
            for(const maskedField of stringToSignObject.maskedFields){
            	delete maskedField["hmacKey"];
            }
          
          	return JSON.stringify(stringToSignObject);
        }
      	return stringToSign;
    }

	function isValidDHExchange(userCode,dhExchange,verification){
        let dhxNonce = getVerificationField(verification,"pki-dhx-nonce");

        if(dhxNonce){
          dhxNonce = dhxNonce.plainField["pki-dhx-nonce"];
          return (dhxNonce == (userCode+"-"+dhExchange.create_date));
        }
        return false;
    }

    async function signClaim(signer,stringToSign,plainFields,idAnchorCertObject,pkiSpUri,includeTrustChain,includeTrustChainInIDCertSig,vouchedForClaimIdentities,isForPrivatePersona){
        //console.log("signClaim:",signer,stringToSign,enclosedSigIdLink,idAnchorCertObject,pkiSpUri)
        
        let verified = false;
        let includeTC = (typeof signer.isInRegistry == "undefined" || signer.isInRegistry != true || includeTrustChain);
      
        //for better privacy, mask hmacKey for all fields except pki-id-link
        //const stringToSignObject = JSON.parse(stringToSign);
      
        //attach hmac keys as a field within the plain fields, remove hmac keys from signature string
      	if(plainFields)
        	stringToSign = await attachHMACKeys(stringToSign,plainFields)
      
      	/*
        const hmacKeyMask = {}
        if(idAnchorCertObject && stringToSignObject.maskedFields){
            let pkiIdLinkKey = certPayloadHasField(signer.cert_text,"pki-cert-version")?(await sha2Hex("pki-id-link")):"pki-id-link";
            let pkiPrivPersona = certPayloadHasField(signer.cert_text,"pki-cert-version")?(await sha2Hex("pki-private-persona")):"pki-private-persona";
          
            for(const maskField of stringToSignObject.maskedFields){
                if(false && maskField.hmacKey && !maskField[hmacHex(maskField.hmacKey,pkiIdLinkKey)]){
                    hmacKeyMask[await sha2Hex(maskField.hmacKey)] = maskField.hmacKey;
                    maskField["hmacKey"] = await sha2Hex(maskField.hmacKey);
                }
            }

            if(Object.keys(hmacKeyMask).length>0)
                stringToSign = JSON.stringify(stringToSignObject);
        }
        */
      
        let signaturePayload = await signText(signer,stringToSign,includeTC);
      	if(!signaturePayload || (signaturePayload.status && signaturePayload.status == "error")){
        	return;
        }

        if(idAnchorCertObject){
            //only include pki-id-link in signature since it is used for identity generation.
            //The basic idea is to only sign masked fields and expose plain fields for signature 
            //verification. Limit private information leak. this needs to be plain.
            let idLinkPlainFields = Object.assign({},{"plainFields":filterPlainFields(plainFields,["pki-id-link"])});
            
            signaturePayload["plainFields"]=idLinkPlainFields.plainFields;
            //if(certPayloadHasField(signer.cert_text,"pki-cert-version"))
            //    signaturePayload["hashedPlainFields"]= await getHashedPlainFields(idLinkPlainFields.plainFields);
            
            includeTC = (typeof idAnchorCertObject.isInRegistry == "undefined" || idAnchorCertObject.isInRegistry != true || includeTrustChainInIDCertSig);
          
            signaturePayload["pki-identity"]=await buildSPIdentityAnchorSignature(idAnchorCertObject,pkiSpUri,signaturePayload,signer,includeTC,vouchedForClaimIdentities,isForPrivatePersona);
          
            if(typeof signaturePayload["pki-identity"] == "undefined" || signaturePayload["pki-identity"] == null){
				alert("Your identity certificate appears to have a problem, unable to generate identity for claim");
              	return;
            }
          
            if(signaturePayload["pki-identity"].status && signaturePayload["pki-identity"].status == "error"){
				alert(`Unable to generate identity for claim, ${signaturePayload["pki-identity"].error_message}`);
              	return;
            }
          
            //remove private info before attaching to claim
			delete signaturePayload["pki-owner-id-info"];
          
            delete signaturePayload["plainFields"];
        }

		//attach plain fields after signing to prevent privacy leak during id generation
        if(plainFields)
        	await attachPlainFields(signaturePayload,plainFields,signer);
      
        //if(Object.keys(hmacKeyMask).length>0)
      	//	signaturePayload["hmacKeyMask"] = hmacKeyMask;

        signaturePayload["debug_verified"]=verified;
        return signaturePayload;
    }

    async function verifyClaim(signaturePayloadText,spUri=null,useChain=null){
            try
            {
                let signaturePayload   = typeof signaturePayloadText == "string"?JSON.parse(signaturePayloadText):signaturePayloadText;
                signaturePayload 	   = setPlainFields(signaturePayload);
              
                let signedStringPayloadText 	= signaturePayload.signedString.substring(0,signaturePayload.signedString.lastIndexOf("timestamp"));

              	let trustChain = useChain;
                if(typeof useChain == "boolean" && useChain && signaturePayload.trustChain)
                   trustChain = signaturePayload.trustChain;                  	
              
                if((!trustChain || trustChain.certs.length == 0)){
                    trustChain = await getCertChain(signaturePayload.signerID);
                    /*
                    trustChain = await getCertChain(signaturePayload.signerID);//NOTE:might contain local leaf cert
                                      
                    if((trustChain.length == 0 || trustChain[0].fromLocalStore) && (!signaturePayload.trustChain || signaturePayload.trustChain.length < 2)){//attempt to build the full chain by concat of issuer chain and provided leaf
                       trustChain = await getCertChain(await getCertIssuerFingerPrint(signerCert));
                       trustChain.unshift(await exportCertificate(signerCert));
                    }
                  	else
                    if(trustChain.length == 0)
                       trustChain = signaturePayload.trustChain;
                    */
                }
              	else//any supplied trust chain must start with leaf
                {
                     //isTrustworthy on individual certs is only valid if it comes directly from registry
                     if(trustChain){
                         for(const cert of trustChain.certs){
                            delete cert["isTrustworthy"]//don't allow user supplied value
                         }
                     }
                  
                     if(trustChainRoot && trustChain.certs[trustChain.certs.length-1].finger_print != trustChainRoot.finger_print){//get the rest of the trust chain

                         const resolveFullChain = async ()=>{
                             let issuerFingerprint = await getCertIssuerFingerPrint(trustChain.certs[trustChain.certs.length-1]);                     
                             let trustChainRemainder = await getCertChain(issuerFingerprint?issuerFingerprint:trustChain.certs[trustChain.certs.length-1].finger_print);
                             trustChain.certs.push(...trustChainRemainder.certs);
                             trustChain.certs = await getCertChainWithStatus(trustChain.certs);                         
                         }
                       
						 if(issuerIsPrivate(trustChain.certs[0])){
                           
						     let chain = await getCertChainWithStatus(trustChain.certs);
                             
                           	 if(!issuerIsPrivate(chain[0])){//issuer is no longer private                                
                                trustChain.certs[0].issuer_finger_print = chain[0].issuer_finger_print;                                
                                await resolveFullChain()
                             }
                             else
                             { 
                                trustChain.certs = [chain[0]];
                             }
                         }
                         else
                         {
							 await resolveFullChain()
                         }
                     }
                }
              
                let signerCert = trustChain && trustChain.certs.length>0?trustChain.certs[0]:await getCert(signaturePayload.signerID);
                
                if(!signerCert){
                    let signatureVerification = {};
                    signatureVerification["signatureVerified"]=false; 
                    signatureVerification["errorMessage"] = "No certificate found to verify claim";
                    return signatureVerification;
                }
              
                signerCert = decodeCertificate(signerCert.cert_text);
                let verified = await verifyText(signaturePayload.signedString,signaturePayload.signature,signerCert);

                let signatureVerification 	= {
                  "certisfy_object":true,
                  "signedString":signaturePayload.signedString,
                  "signerID":signaturePayload.signerID,
                  "signature":signaturePayload.signature,
                  "signatureVerified":verified
                };

                signatureVerification["certChainVerification"]= (await buildTrustedCertChain(signaturePayload.signerID,trustChain));

                if(signatureVerification["certChainVerification"].chain.length>0)
                  	signatureVerification["certificateIsTrustAnchor"] = (await isTrustAnchor(signatureVerification["certChainVerification"].chain[0].cert_text,trustChain.certs));

                signatureVerification["fieldVerification"]=await verifyCertificateFields(signatureVerification.signedString,signatureVerification.signerID,signaturePayload.plainFields,signerCert);

              
				await verifyPKIIdentity(signaturePayload,signatureVerification,(spUri && typeof spUri == "string" && spUri.length>0?[spUri]:spUri));   
              	await verifySignatureExpiry(signaturePayload,signatureVerification);
              
                let timeStamp = signaturePayload.signedString.substring(signaturePayload.signedString.lastIndexOf("timestamp")+10).trim();
                signatureVerification["timestamp"]=timeStamp;
              
                const trackedSig = await getTrackedSignature(await sha2Hex(signaturePayload.signature));
              	if(trackedSig.sig && trackedSig.sig.status && trackedSig.sig.status.length>0 && trackedSig.sig.status != "good"){
                  	signatureVerification["sigStatusVerification"] = trackedSig.sig.status;
                    signatureVerification["sigStatusVerificationMessage"] = trackedSig.sig.status_message;
                }

                //console.log(signatureVerification)
                return signatureVerification;
            }
            catch(e)
            {
                console.error("verifySignature Error",e);
            }

            let signatureVerification = {};
            signatureVerification["signatureVerified"]=false; 
            return signatureVerification;
    }

	async function verifyDHExchangeClaim(userCode,alicePrivateKey,useDHExchange,spUri=null,useChain=null){
        let dhExchange =  useDHExchange;
        if(!dhExchange){
          const dhResp = await getDHExchange(userCode);
          if(dhResp.status != "success")
             return {error:dhResp};
          
          dhExchange =  dhResp.dhExchange;
        }
      
        const dhKey 		= await certisfyCryptoUtil.bobsResponseKeyGen(dhExchange.bob_public_key,{"publicKey":dhExchange.alice_public_key,"privateKey":alicePrivateKey});
        const claim 		= JSON.parse(await certisfyCryptoUtil.AES_GCM_CIPHER.decryptMessage(dhKey.AESKey,dhExchange.bob_data));

      	const verification  = await verifyClaim(claim,spUri,useChain||claim.trustChain);
        verification["failedDHExchangeNonceValidation"] = !isValidDHExchange(userCode,dhExchange,verification);

      	return {verification,claim};
    }

    async function getVouches(plainFields,plainFieldsSummary){

        return new Promise(async (resolve,reject)=>{
        let vouches = [];
        for(const plainField of plainFields){

            const plainFieldName = Object.keys(plainField)[0];
            const plainFieldVal = plainField[plainFieldName];

            if(plainFieldName != "pki-claim-vouch")
              continue;

            let vouchClaim = textToClaimObject(plainFieldVal);
            //console.log("checking vouch claim plain fields:"+plainFieldName);
            if(vouchClaim){
                try
                {
                    let plainFieldHashName = "pki-plain-fields:"+(await sha2Hex(/*plainFieldVal*/vouchClaim.signature));
					vouchClaim = setPlainFields(vouchClaim);//ensure there is an appropriate plainFields object
                  
                    //restore any plain fields from containing claim object plainFields for contained claim
                    if(plainFields.find(f=>f[plainFieldHashName]))
                        vouchClaim.plainFields = JSON.parse(plainFields.find(f=>f[plainFieldHashName])[plainFieldHashName]);
                  
                    //console.log("extracting vouch claim plain fields",vouchClaim,plainFieldHashName,plainFields);
                    if(vouchClaim.plainFields && Array.isArray(vouchClaim.plainFields)){

                        const claims = [];
                        const supportingStatements = [];

                        for(const embeddedPlainField of vouchClaim.plainFields){
                            const embeddedPlainFieldName = Object.keys(embeddedPlainField)[0];
                            const embeddedPlainFieldVal  = embeddedPlainField[embeddedPlainFieldName];
                            //console.log("checking vouched for claim plain fields",embeddedPlainFieldName)
                            if((embeddedPlainFieldName.startsWith("pki-vouch-for-claim") || embeddedPlainFieldName == "pki-vouch-claim")  && embeddedPlainFieldVal){
                                try
                                {
                                    let claim = JSON.parse(embeddedPlainFieldVal);
                                    claim = setPlainFields(claim);//ensure there is an appropriate plainFields object

                                    let plainFieldHashName = "pki-plain-fields:"+(await sha2Hex(/*embeddedPlainFieldVal*/claim.signature));
                                  
                                    //restore any plain fields from containing claim object plainFields for contained claim
                                    if(vouchClaim.plainFields.find(f=>f[plainFieldHashName]))
                                        claim.plainFields = JSON.parse(vouchClaim.plainFields.find(f=>f[plainFieldHashName])[plainFieldHashName]);

                                    //console.log("extracting vouched for claim plain fields",claim,plainFieldHashName);
                                    claims.push(claim);
                                }
                                catch(error){}
                            }
                            else
                            supportingStatements.push(embeddedPlainField)
                        }

                        if(claims.length>0)
                          vouches.push({"vouch":vouchClaim,"plainFieldName":plainFieldName,"claims":claims,"supportingStatements":supportingStatements});
                    }
                }
                catch(error){
                    console.warn(`Error extracting vouched for claims`,error)
                }
            }
        }

        resolve(vouches);
        });
    }

    async function getValidVouches(presentingClaim,docVerificationContext){

        return new Promise(async (resolve,reject)=>{
            let validVouchedClaims = [];
            if(presentingClaim["pki-identity"] && presentingClaim["pki-identity"]["pki-vouched-claim-ownership"]){

                const vouchOwnershipSig = presentingClaim["pki-identity"]["pki-vouched-claim-ownership"];

                verifyClaim(vouchOwnershipSig.signature,null,vouchOwnershipSig.signature.trustChain).then( async (signature)=>{
                    if(!signature.signatureVerified){
                        console.warn(`Unable to verify vouched ownership signature for presenting claim. ${signature.errorMessage?signature.errorMessage:""}`)
                        resolve(validVouchedClaims);
                        return;
                    }

                    const signedStringBuf = [];
                    for(const hash of vouchOwnershipSig.identities){
                        signedStringBuf.push(hash);
                    }
                    signedStringBuf.push(presentingClaim["pki-identity"]["pki-cosignature"].signature);              

                    const vouchSignString = await sha2Hex(signedStringBuf.join(""));//await sha2Hex(JSON.stringify(vouchOwnershipSig.identities)+vouchOwnershipSig.signature.signature);
                    if(!vouchOwnershipSig.signature.signedString.startsWith(vouchSignString)){
                        console.warn(`Unable to verify vouched ownership signature for presenting claim. Identity hash doesn't match signature.`)
                        resolve(validVouchedClaims);
                        return;
                    }


                    let presentingClaimPlainFields = await extractClaimPlainFields(presentingClaim,docVerificationContext);
                    //console.log("presentingClaimPlainFields",presentingClaimPlainFields,presentingClaim,docVerificationContext)
                    for(const vouchEntry of (await getVouches(presentingClaimPlainFields))){

                          //spoof receiver so identity verification succeeds, it doesn't matter for this verification type
                          let receiverId = vouchEntry.vouch["pki-identity"]?[`hash:${vouchEntry.vouch["pki-identity"]["pki-sp-identifier"]}`]:null;

                          let sig = await verifyClaim(vouchEntry.vouch,receiverId,vouchEntry.vouch.trustChain)

                          if(!sig.signatureVerified){
                              console.warn(`Unable to verify vouch signature for presenting claim  from signer ${sig.signerID}. ${sig.errorMessage?sig.errorMessage:""}`)
                              continue;
                          }

                          let isTrustAnchor = (await isTrustAnchorCert(sig.certChainVerification.chain[0]));

                          if(!isTrustAnchor && !isClaimTrustworthy(sig)){
                              console.warn(`Unable to verify vouch signature for presenting claim from signer ${sig.signerID}. Vouch claim is not trustworthy.`)
                              continue;
                          }                      

                          const claims = [];
                          for(const claim of vouchEntry.claims){
                              if(!claim["pki-identity"] || !claim["pki-identity"]["pki-owner-id-info-cloak"]){
                                  console.warn(`Unable to match a vouched claim with signer ${claim.signerID}, it lacks an identity.`)
                                  continue;
                              }

                              //ensure the vouched for claim is owned by the presenting claim owner
                              if(!vouchOwnershipSig.identities.includes(claim["pki-identity"]["pki-owner-id-info-cloak"])){
                                  console.warn(`Unable to link a vouched claim identity (${claim["pki-identity"]["pki-owner-id-info-cloak"]}) to presenting claim owner. The vouched claim signer is ${claim.signerID}`)
                                  continue;
                              }

                              //spoof receiver so identity verification succeeds, it doesn't matter for this verification type
                              let receiverId = claim["pki-identity"]?[`hash:${claim["pki-identity"]["pki-sp-identifier"]}`]:null;

                              let sig = await verifyClaim(claim,receiverId,claim.trustChain)

                              if(!sig.signatureVerified){
                                  console.warn(`Unable to verify vouch claim signature for presenting claim from signer ${claim.signerID}. ${sig.errorMessage?sig.errorMessage:""}`)
                                  continue;
                              }

                              if(!isClaimTrustworthy(sig)){
                                  console.warn(`Unable to verify vouch claim signature for presenting claim from signer ${claim.signerID}. Vouched claim is not trustworthy.`)
                                  continue;
                              }

                              if(false && claim.hashedPlainFields)
                                  await unmaskFieldVerifications(sig,(await extractClaimPlainFields(claim)));

                              //treat all trust anchor vouches as trustworthy, essentially as certified certificate fields
                              if(isTrustAnchor){                            
                                  for(const field of sig.fieldVerification.fields){
                                     field.plainField["certificateVerified"] = true;
                                     if(field.maskedField)
                                        field.maskedField["certificateVerified"] = true;                                   	
                                  }
                              }

                              claims.push({"claim":claim,"verification":sig});
                          }

                          if(claims.length>0){
                            if(false && vouchEntry.vouch.hashedPlainFields)
                                await unmaskFieldVerifications(sig,(await extractClaimPlainFields(vouchEntry.vouch)));

                            validVouchedClaims.push({"entry":vouchEntry,"claims":claims,"isTrustAnchor":isTrustAnchor,"verification":sig})                   
                          }
                    }
                    resolve(validVouchedClaims);
                })
            }
            else
            resolve(validVouchedClaims)
        });
    }

    async function verifyVouches(presentingClaim,docVerificationContext){

        return new Promise(async (resolve,reject)=>{
            presentingClaim  = setPlainFields(presentingClaim);
            //extract and validate embedded vouches
            const vouches = await getValidVouches(presentingClaim,docVerificationContext);

            //treat all trust anchor vouches as trustworthy, essentially as certified certificate fields
            const trustedVouchVerifications = [];
            const untrustedVouches = [];

            for(const vouchEntry of vouches){
                if(vouchEntry.claims.length == 0)
                    continue;

                if(vouchEntry.isTrustAnchor){
                    for(const claimEntry of vouchEntry.claims){
                      trustedVouchVerifications.push(claimEntry.verification);
                    }
                }
                else
                {
                    const vouchVerificationSummary = {"issuer":{},"fields":[],"vouch":vouchEntry,"supportingStatements":[]};

                    //extract issuer information, only allow certificate verified fields as descriptors for the vouch issuer
                    for(const field of vouchEntry.verification.fieldVerification.fields){
                        const rebuiltField = rebuildVerificationField(field);
                        if(!rebuiltField.plainField.name || Object.keys(rebuiltField.plainField).length<2)
                            continue;

                        if(isVerifiedField(vouchEntry.verification,field)){                        
                            vouchVerificationSummary.issuer[rebuiltField.plainField.name] = rebuiltField.plainField.value;
                        }
                        else
                        {
                            vouchVerificationSummary.supportingStatements.push(rebuiltField);
                        }
                    }

                    for(const claimEntry of vouchEntry.claims){
                        const verifiedFields = [];

                        //extract vouched-for information. only include non-certificate fields, those are the ones being vouched for
                        for(const field of claimEntry.verification.fieldVerification.fields){
                            const rebuiltField = rebuildVerificationField(field);
                            if(!rebuiltField.plainField.name || Object.keys(rebuiltField.plainField).length<2)
                                continue;

                            if(!isVerifiedField(claimEntry.verification,field))
                                vouchVerificationSummary.fields.push(rebuildVerificationField(field));
                            else
                                verifiedFields.push(field)
                        }

                        //roll up these verified fields so they are available under verified field section
                        if(verifiedFields.length>0){
                            claimEntry.verification.fieldVerification["preservedFields"]  = claimEntry.verification.fieldVerification.fields;
                            claimEntry.verification.fieldVerification["fields"] = verifiedFields;
                            trustedVouchVerifications.push(claimEntry.verification);
                        }
                    }

                    //don't show as vouch if there are no fields vouched for
                    if(vouchVerificationSummary.fields.length == 0)
                        continue;
                    else
                      untrustedVouches.push(vouchVerificationSummary);
                }

                //remove the unverified field that held this vouch
                for(const field of docVerificationContext.fieldVerification.fields){
                    if(field.plainField.hasOwnProperty(vouchEntry.entry.plainFieldName)){
                        docVerificationContext.fieldVerification.fields.splice(docVerificationContext.fieldVerification.fields.indexOf(field),1);
                        break;
                    }
                }
            }

            //deduplicate display fields
            const knownFields = [];
            for(const rebuiltField of rebuildVerificationFields(docVerificationContext,docVerificationContext.fieldVerification.fields)){
                if(/*!vm.isVerifiedField(field) ||*/ !rebuiltField.plainField.name || Object.keys(rebuiltField.plainField).length<2)
                   continue;

                knownFields.push(rebuiltField);                         
            }

            for(const trustedVouchVerification of trustedVouchVerifications){
                const fields = [];
                fields.push(...trustedVouchVerification.fieldVerification.fields);//supports concurrent modification below

                for(const field of fields){
                     const rebuiltField = rebuildVerificationField(field);
                     if(/*!vm.isVerifiedField(field) ||*/ !rebuiltField.plainField.name || Object.keys(rebuiltField.plainField).length<2)
                        continue;

                     if(knownFields.find(f=>(f.plainField.name && f.plainField.name == rebuiltField.plainField.name && f.plainField.value == rebuiltField.plainField.value)))
                       trustedVouchVerification.fieldVerification.fields.splice(trustedVouchVerification.fieldVerification.fields.indexOf(field),1);
                     else
                       knownFields.push(rebuiltField);
                }
            }

            if(trustedVouchVerifications.length>0)
              Object.assign(docVerificationContext,{"trustedVouchVerifications":trustedVouchVerifications});
            else
              delete docVerificationContext["trustedVouchVerifications"];

            if(untrustedVouches.length>0)
              Object.assign(docVerificationContext,{"untrustedVouches":untrustedVouches});
            else
              delete docVerificationContext["untrustedVouches"];

            resolve();
        });
    }

    async function getVouchedClaimIdentities(plainFields){
        return new Promise(async (resolve,reject)=>{
            let vouchedClaimIdentities = [];
            for(const vouch of (await getVouches(plainFields))){
                for(const claim of vouch.claims){
                    if(claim["pki-identity"] && claim["pki-identity"]["pki-owner-id-info-cloak"]){
                      vouchedClaimIdentities.push(claim["pki-identity"]["pki-owner-id-info-cloak"])
                    }
                }
            }
            resolve(vouchedClaimIdentities);
        });
    }

    function isClaimTrustworthy(docVerificationContext){
      
      	if(!docVerificationContext || !docVerificationContext.certChainVerification)
          return false;

        if(docVerificationContext.isEmbedSticker)
            return (docVerificationContext.certChainVerification.certificateVerified && 
                    !docVerificationContext.failedDHExchangeNonceValidation &&
                    (!docVerificationContext.sigStatusVerification || docVerificationContext.sigStatusVerification == "good") &&
                    docVerificationContext.signatureExpirationStatus !='expired' &&
                    docVerificationContext.signatureExpirationStatus !='invalid' &&
                    docVerificationContext.signatureValidFromStatus !='pretermed' &&
                    docVerificationContext.signatureValidFromStatus !='invalid' &&
                    docVerificationContext.signatureValidFromStatus !='unspecified' &&
                    (!clientApp || !clientApp.isFlaggedIdentity(docVerificationContext)) && 
                    !docVerificationContext.certChainVerification.chain.find(c=>c.finger_print == demoTrustAnchorFingerprint));

        return (docVerificationContext.certChainVerification.certificateVerified && 
                !docVerificationContext.failedDHExchangeNonceValidation &&
                (/*docVerificationContext.certificateIsTrustAnchor ||*//*this.isEmbedSession()*/docVerificationContext.stickerClaimValidation || 
                (docVerificationContext.pkiIdentityVerified && 
                docVerificationContext.pkiIdentityReceiverMatch)) &&
                (!docVerificationContext.sigStatusVerification || docVerificationContext.sigStatusVerification == "good") &&
                docVerificationContext.signatureExpirationStatus !='expired' &&
                docVerificationContext.signatureExpirationStatus !='invalid' &&
                docVerificationContext.signatureValidFromStatus !='pretermed' &&
                docVerificationContext.signatureValidFromStatus !='invalid' &&
                docVerificationContext.signatureValidFromStatus !='unspecified' &&
                (!clientApp || !clientApp.isFlaggedIdentity(docVerificationContext)) && 
                !docVerificationContext.certChainVerification.chain.find(c=>c.finger_print == demoTrustAnchorFingerprint));
    }

    /**********************************************************************************************
     *	AI GENERATED from UI markup structure.													  *
     **********************************************************************************************/
    function getVerificationResult(docVerificationContext,includeInternalFields) {
      if (!docVerificationContext) return null;

      const result = {};

      // Trustworthiness
      const trustworthy = isClaimTrustworthy(docVerificationContext);

      result.trust = {
        isTrustworthy: trustworthy
      };

      if (trustworthy) {
        result.trust.message = "This Claim Is Trustworthy";
        if (docVerificationContext.claimPurpose) {
          result.trust.intendedPurpose = docVerificationContext.claimPurpose;
        }
      } else {
        result.trust.message = "This Claim Is Not Trustworthy";
        result.trust.errors = buildErrorList(docVerificationContext) || [];
      }

      // Verified Information
      const verifiedFieldsRaw = filterVerificationFields(
        docVerificationContext,
        docVerificationContext.fieldVerification.fields,
        true,
        true,
        includeInternalFields
      );

      if (verifiedFieldsRaw && verifiedFieldsRaw.length > 0) {
        result.verifiedInformation = {
          title: "Verified Information",
          fields: []
        };

        const rebuiltVerified = rebuildVerificationFields(
          docVerificationContext,
          docVerificationContext.fieldVerification.fields,
          true,
          true,
          includeInternalFields
        );

        rebuiltVerified.forEach(field => {
          result.verifiedInformation.fields.push({
            name: field.plainField.name,
            value: field.plainField.value
          });
        });

        // Trusted Vouch Verifications
        if (docVerificationContext.trustedVouchVerifications) {
          result.verifiedInformation.trustedVouches = [];

          docVerificationContext.trustedVouchVerifications.forEach(vouchVerification => {
            const rebuiltVouchFields = rebuildVerificationFields(
              vouchVerification,
              vouchVerification.fieldVerification.fields,
              true,
              true,
              includeInternalFields
            );

            const vouchFields = rebuiltVouchFields.map(field => ({
              name: field.plainField.name,
              value: field.plainField.value
            }));

            result.verifiedInformation.trustedVouches.push({
              fields: vouchFields
            });
          });
        }
      }

      // Unverified Information
      const unverifiedFieldsRaw = filterVerificationFields(
        docVerificationContext,
        docVerificationContext.fieldVerification.fields,
        false,
        true,
        includeInternalFields
      );

      if (unverifiedFieldsRaw && unverifiedFieldsRaw.length > 0) {
        result.unverifiedInformation = {
          title: "Unverified Information",
          fields: []
        };

        const rebuiltUnverified = rebuildVerificationFields(
          docVerificationContext,
          docVerificationContext.fieldVerification.fields,
          false,
          true,
          includeInternalFields
        );

        rebuiltUnverified.forEach(field => {
          result.unverifiedInformation.fields.push({
            name: field.plainField.name,
            value: field.plainField.value
          });
        });
      }

      // Owner Identity Information
      if (
        docVerificationContext.pkiIdentityVerified &&
        docVerificationContext["pki-identity"] &&
        docVerificationContext["pki-identity"]["pki-sp-id-anchor-token"]
      ) {
        result.ownerIdentityInformation = {
          id: docVerificationContext["pki-identity"]["pki-sp-id-anchor-token"],
          personaType:
            docVerificationContext["pki-identity"]["pki-sp-id-anchor-token-persona"],
          validForReceiver: docVerificationContext.spUri,
          basedOnIdentityElement:
            docVerificationContext["pki-identity"]["pki-id-anchor-element"]
        };
      }

      // Untrusted Vouches
      if (
        docVerificationContext.untrustedVouches &&
        docVerificationContext.untrustedVouches.length > 0
      ) {
        result.vouching = [];

        docVerificationContext.untrustedVouches.forEach(vouch => {
          const vouchObj = {};

          // Claims Vouched For
          vouchObj.claimsVouchedFor = (vouch.fields || [])
            .filter(field =>
              (field.plainField.name && field.plainField.name.length > 0) ||
              (field.plainField.value && field.plainField.value.length > 0)
            )
            .map(field => ({
              label:
                field.plainField.name && field.plainField.value
                  ? field.plainField.name
                  : "Claim",
              value:
                field.plainField.value && field.plainField.value.length > 0
                  ? field.plainField.value
                  : field.plainField.name
            }));

          // Vouch Issuer
          vouchObj.issuer = Object.keys(vouch.issuer || {}).map(fieldName => ({
            fieldName,
            value: vouch.issuer[fieldName]
          }));

          // Supporting Statements
          if (vouch.supportingStatements && vouch.supportingStatements.length > 0) {
            vouchObj.supportingStatements = vouch.supportingStatements
              .filter(field =>
                (field.plainField.name && field.plainField.name.length > 0) ||
                (field.plainField.value && field.plainField.value.length > 0)
              )
              .map(field => ({
                label:
                  field.plainField.name && field.plainField.value
                    ? field.plainField.name
                    : "Statement",
                value:
                  field.plainField.value && field.plainField.value.length > 0
                    ? field.plainField.value
                    : field.plainField.name
              }));
          }

          result.vouching.push(vouchObj);
        });
      }

      return result;
    }

    function buildErrorList(docVerificationContext){
        
        let messageList = [];  
      
      	if(!docVerificationContext || !docVerificationContext.certChainVerification)
          	return messageList;
      
        if(docVerificationContext.clientErrorList)
            messageList = messageList.concat(docVerificationContext.clientErrorList);

        if(docVerificationContext.certChainVerification.chain.find(c=>c.finger_print == demoTrustAnchorFingerprint))
           messageList.push("This claim's certificate was issued using the demo trust anchor certificate!!!");

        if(/*!docVerificationContext.certificateIsTrustAnchor &&*/ /*!docVerificationContext.isEmbedSticker*/ /*!vm.isEmbedSession()*/!docVerificationContext.stickerClaimValidation)
        {
            if(!docVerificationContext.pkiIdentityVerified)
            {      
              messageList.push('No valid claimant identity information provided.');
            }

            if(docVerificationContext.pkiIdentityVerified && !docVerificationContext.pkiIdentityReceiverMatch)
            {
               //messageList.push('The receiver for this claim doesn\'t match your receiver Id('+vm.receiverIds+'). It could be a stolen claim.');
               messageList.push(`The claim receiver id for this claim doesn\'t match any of your receiver Ids. It could be a stolen claim.`);
            }    
        }

        if(clientApp && clientApp.isFlaggedIdentity(docVerificationContext))
        {
            messageList.push(`You are currently tracking this claim creator's identity and you have it flagged!`);

            if(clientApp.getTrackedIdentity(docVerificationContext).reason)
              messageList.push(`Your reason for flagging it: ${clientApp.getTrackedIdentity(docVerificationContext).reason}`);
        }

        if(!docVerificationContext.certChainVerification.certificateVerified)
        {
          messageList.push('The certificate that attests to this claim was either not issued by a valid Certisfy trust anchor partner (and/or their certificate is invalid) or is not valid (expired,pretermed or revoked).');
        }

        if(docVerificationContext.failedDHExchangeNonceValidation)
        {
           messageList.push('The claim was transmited via a claim exchange but failed validation.');
        }
      
        if(docVerificationContext.signatureExpirationStatus=='unspecified')
        {
          messageList.push(`The claim doesn't specify an expiration time.`);
        } 
        else
        if(docVerificationContext.signatureExpirationStatus=='expired')
        {
          messageList.push('The claim has expired.');
        }
        else
        if(docVerificationContext.signatureExpirationStatus=='invalid')
        {
          messageList.push('The claim has invalid expiration time.');
        }    


        if(docVerificationContext.signatureExpirationStatus !='expired' && docVerificationContext.signatureValidFromStatus=='pretermed')
        {
          messageList.push('The claim is for a future date.');
        }
        else
        if(docVerificationContext.signatureValidFromStatus=='invalid')
        {
          messageList.push('The claim has invalid future validity time.');
        }  

        if(docVerificationContext.sigStatusVerification && docVerificationContext.sigStatusVerification != "good"){
          messageList.push(`The claim's status(${docVerificationContext.sigStatusVerification}) is invalid.`);    
        }

        return messageList;
    }

    function isTrustAnchorCert(cert,disallowDemoCert){
        if(disallowDemoCert && cert.finger_print == demoTrustAnchorFingerprint)
            return Promise.resolve(false);

        return new Promise(async (resolve,reject)=>{
            resolve(await isTrustAnchor(cert.cert_text))
        });
    }

    function isInternalField(field){
           for(let key in field.plainField)//assume just one entry
           {
               if(key != "certificateVerified" &&
                  key != "certificateVerificationFailure" &&
                  !key.startsWith('certisfy-') &&
                  !key.startsWith('pki-') &&
                  !isIDElementHash(key))
                 return false;
           }
           return true;
    }

    function isVerifiedField(docVerificationContext,field){
       return ((docVerificationContext.certChainVerification.certificateVerified) && (field.plainField.certificateVerified && (typeof field.maskedField == 'undefined' || field.maskedField.certificateVerified)));      
    }

    function rebuildVerificationField(field,includeInternalFields){
           let metaPlainField = {};
           for(let key in field.plainField)
           {
               if((!includeInternalFields || !includeInternalFields.includes(key)) && isInternalFieldName(key))
                 metaPlainField[key] = field.plainField[key];
               else
               {
                 metaPlainField['name'] = key; 
                 metaPlainField['value'] = field.plainField[key]; 
               }
           }

           let metaMaskedField = {};
           for(let key in field.maskedField)
           {
               if((!includeInternalFields || !includeInternalFields.includes(key)) && isInternalFieldName(key))
                 metaMaskedField[key] = field.maskedField[key];
               else
               {
                 metaMaskedField['name'] = key; 
                 metaMaskedField['value'] = field.maskedField[key]; 
               }
           }
           let metaField = Object.assign({},{"plainField":metaPlainField,"maskedField":metaMaskedField});
           return metaField;
    }

    function isInternalFieldName(key){
        if(key != "certificateVerified" &&
                   key != "certificateVerificationFailure" &&
                   !key.startsWith('certisfy-') && 
                   !key.startsWith('pki-') &&
                   !isIDElementHash(key))
                  return false;
                 return true;
    }

    function filterVerificationFields(docVerificationContext,fields,verified,hideInternal,includeInternalFields){
        const resultSet = [];
        for(var i=0;i<fields.length;i++)
        {
            var field = fields[i];            
          
            if((!includeInternalFields || !includeInternalFields.includes(Object.keys(field.plainField)[0])) && hideInternal && isInternalField(field))
              continue;

            if(verified && isVerifiedField(docVerificationContext,field))
            {
               resultSet.push(field);
            }
            else
            if(!verified && !isVerifiedField(docVerificationContext,field))
            {
               resultSet.push(field);
            }
        }
        //console.log("filterVerificationFields:"+verified);
        //console.log(resultSet);

        return resultSet;
    }

    function rebuildVerificationFields(docVerificationContext,fields,verificationFilter,internalFieldFilter,includeInternalFields){    
        let filteredFields = fields;
        if(typeof verificationFilter != "undefined")
          filteredFields = filterVerificationFields(docVerificationContext,fields,verificationFilter,internalFieldFilter,includeInternalFields);

        let metaFields = [];
        for(let i=0;i<filteredFields.length;i++)
        {
           let field = filteredFields[i];      
           metaFields.push(rebuildVerificationField(field,includeInternalFields));       
        }
        //console.log("metaFields",metaFields)
        return metaFields;
    }

    function getVerificationField(docVerificationContext,fieldName){
        let metaFields = rebuildVerificationFields(docVerificationContext,docVerificationContext.fieldVerification.fields);
        for(let i=0;i<metaFields.length;i++)
        {
          if(metaFields[i].plainField.name && metaFields[i].plainField.name == fieldName)
            return metaFields[i];

          if(metaFields[i].plainField[fieldName])//meta data
            return metaFields[i];      
        }
        return null;
    }

    async function createPKCS10Internal(hashAlg, signAlg,csrText,keyPair) {
        //#region Initial variables
        const pkcs10 = new pkijs.CertificationRequest();
        //#endregion
        //#region Get a "crypto" extension
        const crypto = pkijs.getCrypto(true);
        //#endregion
        //#region Put a static values
        pkcs10.version = 0;

        //CN
        pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.Utf8String({ value: "Human" })
        }));
        const altNames = new pkijs.GeneralNames({
            names: [
                new pkijs.GeneralName({
                    type: /*0*/2,
                    value: csrText//new asn1js.Utf8String({ value:csrText})
                })
            ]
        });
        pkcs10.attributes = [];
        //#endregion
        //#region Create a new key pair
        //#region Get default algorithm parameters for key generation
        const algorithm = pkijs.getAlgorithmParameters(signAlg, "generateKey");
        if ("hash" in algorithm.algorithm)
            algorithm.algorithm.hash.name = hashAlg;
        //#endregion
        //console.log(algorithm)
        let privateKey = null; 
        let publicKey = null;
      
              
        if(keyPair){
            let kp = typeof keyPair == "string"?JSON.parse(keyPair):keyPair;
			privateKey = await crypto.subtle.importKey(
                "pkcs8", 
                base64ToArrayBuffer(kp.privateKey),
                certAlgo, 
                true, 
                ["sign"]);
          
          	 publicKey = await crypto.subtle.importKey(
                    "spki", 
                    base64ToArrayBuffer(kp.publicKey),
                    certAlgo,true,["verify"]);
        }
      	else
        {      
           let kp = await crypto.generateKey(certAlgo, true, /*[ "sign", "encrypt","verify","decrypt"]*/algorithm.usages);
           privateKey = kp.privateKey;
           publicKey = kp.publicKey;
        }
        //#endregion
        //#region Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
        await pkcs10.subjectPublicKeyInfo.importKey(publicKey);
        //#endregion
        // SubjectKeyIdentifier
        const subjectKeyIdentifier = await crypto.digest({ name: "SHA-1" }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
        pkcs10.attributes.push(new pkijs.Attribute({
            type: "1.2.840.113549.1.9.14",
            values: [(new pkijs.Extensions({
                    extensions: [
                        new pkijs.Extension({
                            extnID: "2.5.29.14",
                            critical: false,
                            extnValue: (new asn1js.OctetString({ valueHex: subjectKeyIdentifier })).toBER(false)
                        }),
                        new pkijs.Extension({
                            extnID: "2.5.29.17",
                            critical: false,
                            extnValue: altNames.toSchema().toBER(false)
                        })/*,
                        new pkijs.Extension({
                            extnID: "1.2.840.113549.1.9.7",
                            critical: false,
                            extnValue: (new asn1js.PrintableString({ value: "passwordChallenge" })).toBER(false)
                        })*/
                    ]
                })).toSchema()]
        }));
        // Signing final PKCS#10 request
        await pkcs10.sign(privateKey, hashAlg);

        let privateKeyPEM = await crypto.subtle.exportKey("pkcs8",privateKey);
        let publicKeyPEM  = await crypto.subtle.exportKey("spki",publicKey);
      
        return {
          "csrPEM":toPEM(pkcs10.toSchema().toBER(false),"CERTIFICATE REQUEST"),
          "privateKey":toPEM(privateKeyPEM,"PRIVATE KEY"),
          "publicKey":toPEM(publicKeyPEM,"PUBLIC KEY")
        };
    }

    async function createCSR(csrPayload,isPrivate,idCert,_identityCertSig,certIdentity,keyPair,encKeyPair,payloadEncryptionKey,useStrongIdProofing,includeIdCertSigTrustChain,isForPrivatePersona,encryptIssuerFingerPrint){
      
        /////////////////////////////////Generate keys for asymmetric encryption/////////////////////////////
        let asymDecryptionKeyPEM = null;
        let asymEncryptionKeyPEM  = null;
        
        if(encKeyPair){
           asymDecryptionKeyPEM=toPEM(encKeyPair.privateKey,"PRIVATE KEY");
           asymEncryptionKeyPEM=toPEM(encKeyPair.publicKey,"PUBLIC KEY");
        }
      	else
        {      
            let asymKeyPair = await crypto.subtle.generateKey(
                  {
                  name: "RSA-OAEP",
                  // Consider using a 4096-bit key for systems that require long-term security
                  modulusLength: 2048,
                  publicExponent: new Uint8Array([1, 0, 1]),
                  hash: "SHA-256",
                  },
                  true,
                  ["encrypt", "decrypt"]
            );

            asymDecryptionKeyPEM = await crypto.subtle.exportKey("pkcs8",asymKeyPair.privateKey);
            asymEncryptionKeyPEM  = await crypto.subtle.exportKey("spki",asymKeyPair.publicKey);

            asymDecryptionKeyPEM=toPEM(asymDecryptionKeyPEM,"PRIVATE KEY");
            asymEncryptionKeyPEM=toPEM(asymEncryptionKeyPEM,"PUBLIC KEY");
        }
        /*
        const keyDetails = await crypto.subtle.generateKey({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048, 
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: { name: 'SHA-256' }, 
        }, true, ["sign","verify"]);

      	
        let decryptionKeyPEM = await crypto.subtle.exportKey("jwk",keyDetails.privateKey);
        let encryptionKeyPEM  = await crypto.subtle.exportKey("jwk",keyDetails.publicKey);      
      
        //Adapt parameters and import
        encryptionKeyPEM.key_ops = ['encrypt'];
        decryptionKeyPEM.key_ops = ['decrypt'];
        encryptionKeyPEM.alg = 'RSA-OAEP-256';
        decryptionKeyPEM.alg = 'RSA-OAEP-256';
        encryptionKeyPEM = await crypto.subtle.importKey("jwk", encryptionKeyPEM, {name: "RSA-OAEP", hash: {name: "SHA-256"}}, true, ["encrypt"]);    
        decryptionKeyPEM = await crypto.subtle.importKey("jwk", decryptionKeyPEM,{name: "RSA-OAEP", hash: {name: "SHA-256"}}, true, ["decrypt"]);
      
        decryptionKeyPEM = await crypto.subtle.exportKey("pkcs8",decryptionKeyPEM);
        encryptionKeyPEM  = await crypto.subtle.exportKey("spki",encryptionKeyPEM);
      
        let asymDecryptionKeyPEM=toPEM(decryptionKeyPEM,"PRIVATE KEY");
        let asymEncryptionKeyPEM=toPEM(encryptionKeyPEM,"PUBLIC KEY");
        */
        ///////////////////////////////////////////////////////////////////////////////////////////////       
      
      	let ownerIdCloak = null;
        let identityCertSig = null;
        if(_identityCertSig){
            if(typeof _identityCertSig == "string" && _identityCertSig.length>0)
             	identityCertSig = JSON.parse(_identityCertSig);
            else
            if(typeof _identityCertSig == "object")
             	identityCertSig = _identityCertSig;
        }
      
        if(certIdentity){
            ownerIdCloak = certIdentity.ownerIdCloak;
        }
        else      
        if(identityCertSig){
            let pkiIdentity = identityCertSig["pki-identity"]?identityCertSig["pki-identity"]:await wrapCertIdentity(JSON.stringify(identityCertSig),"certisfy.com",JSON.stringify(identityCertSig));//idCert?await extractIdentityAnchorElement(idCert,randomUUID().replaceAll("-","")):null;
            let certIdInfo = pkiIdentity["pki-owner-id-info"];
            ownerIdCloak = certIdInfo?certIdInfo.ownerIdCloak:null;
        }
        else
      	if(idCert){
            let isVersioned = certPayloadHasField(idCert.cert_text,"pki-cert-version");
          
            let idElementInfo = await extractIdentityAnchorElement(idCert);
            let idFields = await selectCertFields([idElementInfo.elementName+(isVersioned?"":"_HASH")],idCert);
      
        	//hash id before sending it
			if(isVersioned){
                let plainField = idFields.plainFields[0];
                plainField[await sha2Hex(Object.keys(plainField)[0])] = await sha2Hex(plainField[Object.keys(plainField)[0]]);
                delete plainField[Object.keys(plainField)[0]];
        	}
          
            let idCertSig = await signClaim(idCert,JSON.stringify(idFields),null,null,"certisfy.com",includeIdCertSigTrustChain);

            let pkiIdentity = await wrapCertIdentity(JSON.stringify(idCertSig),"certisfy.com",JSON.stringify(idCertSig));//idCert?await extractIdentityAnchorElement(idCert,randomUUID().replaceAll("-","")):null;
            let certIdInfo = pkiIdentity["pki-owner-id-info"];
            ownerIdCloak = certIdInfo?certIdInfo.ownerIdCloak:null;
        }

        let signedDocFieldList = [];

        let maskedPayload = {};
        let plainPayload = {"pki-asym-encryption-key":asymEncryptionKeyPEM,"pki-cert-version":PKI_CERT_VERSION};
      	      
        if(csrPayload){
             let csrFields = Object.assign(csrPayload,{});
             if(ownerIdCloak)//attach id signature if available
             {
                plainPayload["pki-id-link"]=ownerIdCloak;
                Object.assign(csrFields,{"pki-id-link":ownerIdCloak});
             }
          
             if(isForPrivatePersona){
             	plainPayload["pki-private-persona"]="yes";
                Object.assign(csrFields,{"pki-private-persona":"yes"});
             }
          
            if(encryptIssuerFingerPrint){
             	plainPayload["pki-is-private-issuer"]="true";
                Object.assign(csrFields,{"pki-is-private-issuer":"true"});            
            }
          	 
             for(let idElementKey in idAnchorElements){
                if(csrFields[idElementKey]){
                   //make id element value uniformly uppercase
                   csrFields[idElementKey] = csrFields[idElementKey].toUpperCase();
                   
                   //create privacy preserving versions of ID elements to support claim identity generation
                   if(false /*&& PKI_CERT_VERSION < "1.5"*/ )
                   		csrFields[idElementKey+"_HASH"] = await sha2Hex(csrFields[idElementKey].toUpperCase());
                }
             }

             for(let fieldName in csrFields)
             {
                let field = csrFields[fieldName];
                plainPayload[fieldName]=field;

                let fieldNameHash = await sha2Hex(fieldName);
                let fieldHash = (field?await sha2Hex(field):field);
               
                let hmacKey = randomUUID().replaceAll("-","");

                let fieldContainer = {};
                let maskedField = {};
                let plainField = {}; 

                fieldContainer["plainField"]=plainField;           	        
                plainField["name"]=fieldName;
                plainField["value"]=field;

                if(isPrivate)
                {
                    let maskFieldName = hmacHex(hmacKey,/*fieldName*/fieldNameHash);
                    let maskedFieldValue = hmacHex(hmacKey,/*field*/fieldHash);
                  
                    //fieldContainer["hmacKey"]=hmacKey;
                    fieldContainer["maskedField"]=maskedField;
                    maskedField["name"]=maskFieldName;
                    maskedField["value"]=maskedFieldValue;
                    maskedField["hmacKey"]=hmacKey;
                    maskedPayload[maskFieldName]=maskedFieldValue;
                }
                signedDocFieldList.push(fieldContainer);
             }   
        }    
        //these should not be masked
        maskedPayload["pki-asym-encryption-key"]=asymEncryptionKeyPEM;
        maskedPayload["pki-cert-version"]= PKI_CERT_VERSION;

        let cn = [];
        cn[0] = isPrivate?JSON.stringify(maskedPayload):JSON.stringify(plainPayload);//csrPayload;

        const csrResp = await createPKCS10Internal(hashAlg, signAlg,cn[0],keyPair);
        let csrText = csrResp.csrPEM;

        let iv = crypto.getRandomValues(new Uint8Array(12));  
        // crypto functions are wrapped in promises so we have to use await and make sure the function that
        // contains this code is an async function
        // encrypt function wants a cryptokey object
        let encryptionKey = null;
        if(payloadEncryptionKey){
            if(typeof payloadEncryptionKey == "string"){
                encryptionKey = await crypto.subtle.importKey(
                    "raw",
                    base64ToArrayBuffer(payloadEncryptionKey),
                    { 
                      name: "AES-GCM",
                	  length: 128
                    }, 
                    true, 
                    ["encrypt"]
                  );
            }
          	else
            {
               encryptionKey = payloadEncryptionKey;
            }
        }
        else
        {
            encryptionKey = await crypto.subtle.generateKey(
              {
                name: "AES-GCM",
                length: 128
              },
              true,
              ["encrypt", "decrypt"]);
        }
      
        let csrDetails = {"csr":csrText,"signedDocument":signedDocFieldList};
        if(useStrongIdProofing && idCert)
                Object.assign(csrDetails,{"identity":idCert});
      
      	if(identityCertSig)
           		Object.assign(csrDetails,{"identityCertSig":identityCertSig});
      
        csrText = new TextEncoder().encode(JSON.stringify(csrDetails));
        let encryptedPayload = await crypto.subtle.encrypt(
                                {
                                  name: "AES-GCM",
                                  iv: iv,
                                  tagLength: 128
                                },encryptionKey,csrText); 

          //let cipherTextPlusIV = new Uint8Array(encryptedPayload.length + iv.length);
          //cipherTextPlusIV.set(iv);
          //cipherTextPlusIV.set(encryptedPayload, iv.length);
          encryptedPayload = new Uint8Array([ ...iv, ...new Uint8Array(encryptedPayload)]);

          encryptionKey = await crypto.subtle.exportKey("raw", encryptionKey);

          //atob(btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedPayload))));
          //atob(btoa(String.fromCharCode.apply(null, new Uint8Array(encryptionKey))));
          //console.log(await decryptCSR(btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedPayload))),btoa(String.fromCharCode.apply(null, new Uint8Array(encryptionKey)))))

         let finger_print = await sha2Hex(base64EncodeBin(encryptedPayload));
      
          return {
              "finger_print":finger_print,
              "encryptedPayload":base64EncodeBin(encryptedPayload),
              "encryptionKey":base64EncodeBin(encryptionKey),
              "csr":csrResp,
              "signedDocument":signedDocFieldList,
              "asymDecryptionKey":asymDecryptionKeyPEM,
              "asymEncryptionKey":asymEncryptionKeyPEM
          };
    }

    async function decryptCSR(csrCipherText,encryptionKey){

        // Decode the Base64-encoded key to binary
        let decryptionKey = new Uint8Array(Array.from(atob(encryptionKey), c => c.charCodeAt(0)));///*Uint8Array.from*/(atob(encryptionKey));

        // Import the binary key
        decryptionKey =  await crypto.subtle.importKey(
          "raw", // Key format
          decryptionKey,
          { 
            name: "AES-GCM",
            length: 256 
          }, // Algorithm details (modify for your encryption algorithm)
          true, // Whether the key is extractable
          ["encrypt", "decrypt"/*,"sign","verify"*/] // Key usages
        )


         let ctBuffer = Array.from(atob(csrCipherText), c => c.charCodeAt(0));
         let csr = new Uint8Array(ctBuffer);///*new Uint8Array*/(atob(csrText));
         let decryptedPayload = await crypto.subtle.decrypt(
                                {
                                  name: "AES-GCM",
                                  iv:new Uint8Array(ctBuffer.slice(0, 12)),
                                  tagLength: 128
                                },decryptionKey,new Uint8Array(ctBuffer.slice(12))); 

          decryptedPayload = new TextDecoder().decode(decryptedPayload);
          //console.log(JSON.parse(decryptedPayload))
          return JSON.parse(decryptedPayload);
    }

	function addFieldToCertPayload(payLoad,fieldName,fieldVal){
     	if(fieldVal)
            payLoad[fieldName] = fieldVal;
        else
          	delete payLoad[fieldName]; 
    }

    async function createClaimFields(selectedFields,isPrivate,hashInput=true){
      	
        let vm = this;
        let plainFields = [];
        let maskedFields = [];          
        
      	for(const field of selectedFields){               
              if(isPrivate)
              {
                  let maskedField = await createPrivateField({"name":field.name,"value":field.value,"hmacKey":field.hmacKey},hashInput);
                  maskedFields.push(maskedField);
              }

          	  let plainField = {};
              plainField[field.name] = field.value;
              plainFields.push(plainField);
        };

        if(isPrivate)
        	return Object.assign({},{"plainFields":plainFields,"maskedFields":maskedFields});
      	else
          	return Object.assign({},{"plainFields":plainFields}); 
    }

	async function createStandardClaimFields(signer,certContextSelectedFields,certContextUnverifiedFields,extraFields,claimValidFrom,claimExpiration){
        let plainFields = [];
        let maskedFields = [];
  
        //attach verified fields
        if(certContextSelectedFields){
            for(let field of certContextSelectedFields){

                if(clientApp && clientApp.isStrictlyInternalClaimField && field.maskedField && clientApp.isStrictlyInternalClaimField(field.maskedField)) {
                  	return {error:"Claim field "+field.maskedField.name+" can't be used, will be ignored."};
                }

                if(clientApp && clientApp.isStrictlyInternalClaimField && clientApp.isStrictlyInternalClaimField(field.plainField)) {
                  	return {error:"Claim field "+field.plainField.name+" can't be used, will be ignored."};
                }

                let plainField = {};
                plainField[field.plainField.name]=field.plainField.value;
                plainFields.push(plainField);

                if(field.maskedField)
                {
                    let maskedField = {};
                    maskedField[field.maskedField.name]=field.maskedField.value;
                    maskedField["hmacKey"] = field.hmacKey?field.hmacKey:field.maskedField.hmacKey;
                    maskedFields.push(maskedField);
                }
                else
                {
                    let maskedField = await createPrivateField(field.plainField);
                    maskedFields.push(maskedField);
                }
            }
        }

        //attach unverified fields
        if(certContextUnverifiedFields){
            for(const field of certContextUnverifiedFields){
                if(clientApp && clientApp.isStrictlyInternalClaimField && clientApp.isStrictlyInternalClaimField(field)) {
                  return {error:"Claim field "+field.name+" can't be used, will be ignored."};
                }
                let fieldVal = field.value;
                let fieldClaimObject = textToClaimObject(field.value);

                const normizeFieldNames = ["pki-vouch-for-claim"];
                field.name =  normizeFieldNames.find(f=>field.name.startsWith(f))?normizeFieldNames.find(f=>field.name.startsWith(f)):field.name;

                if(fieldClaimObject && fieldsContainVouchedForClaims(fieldClaimObject.plainFields))
                  field.name =  "pki-claim-vouch";

                let embeddedPlainFields;

                //before embedding, remove plainFields to preserve privacy
                if(fieldClaimObject){
                  embeddedPlainFields = fieldClaimObject.plainFields;

                  delete fieldClaimObject.plainFields;
                  delete fieldClaimObject.hashedPlainFields;

                  field.value = JSON.stringify(fieldClaimObject);
                }

                let plainField = {};
                plainField[field.name]=field.value;
                plainFields.push(plainField);

                let maskedField = await createPrivateField(field);
                maskedFields.push(maskedField);

                //map claim text hash to plainFields for claim for future use
                if(embeddedPlainFields){
                    let auxField = {
                      "name":("pki-plain-fields:"+(await sha2Hex(fieldClaimObject.signature))),
                      "value":JSON.stringify(embeddedPlainFields)
                    }
                    plainField = {};
                    plainField[auxField.name]=auxField.value;
                    plainFields.push(plainField);

                    maskedField = await createPrivateField(auxField);
                    maskedFields.push(maskedField);
                }

                field.value = fieldVal;//restore if it was changed
            }
        }

        if(extraFields){
            for(const field of extraFields){                  
                let plainField = {};
                plainField[field.name]=field.value;
                plainFields.push(plainField);

                let maskedField = await createPrivateField(field);
                maskedFields.push(maskedField);
            }
        }

        if(plainFields.length == 0){
          	return {error:"Please select one or more fields for the claim."};
        }

    	//attach validity start date
        if(claimValidFrom){
            plainFields.push({"pki-valid-from-time":claimValidFrom});
            let maskedField = await createPrivateField({"name":"pki-valid-from-time","value":claimValidFrom})
            maskedFields.push(maskedField);
        }
        else
        {
          	return {error:"Please provide a validity start date for this claim."}; 
        }

        //attach expiration date
        if(claimExpiration){
            plainFields.push({"pki-expiration-time":claimExpiration});
            let maskedField = await createPrivateField({"name":"pki-expiration-time","value":claimExpiration})
            maskedFields.push(maskedField);
        }
        else
        {
          	return {error:"Please provide an expiration date for this claim."}; 
        }

    	//attach metadata fields
        for(const field of signer.csr.signedDocument){
            let plainField = {};
            if(["pki-id-link","pki-id-proofing-level"].includes(field.plainField.name))
            {
                plainField[field.plainField.name]=field.plainField.value;
                plainFields.push(plainField);

                if(field.maskedField)
                {
                    let maskedField = {};
                    maskedField[field.maskedField.name]=field.maskedField.value;
                    maskedField["hmacKey"] = field.hmacKey?field.hmacKey:field.maskedField.hmacKey;
                    maskedFields.push(maskedField);
                }
                else
                {                    
                    let maskedField = await createPrivateField(field.plainField);
                    maskedFields.push(maskedField);
                }
            }
        }
   		return {plainFields,maskedFields};
	}

    async function extractAndAttachPlainFields(claim,plainFields){
        const claimObject = typeof claim == "string"?JSON.parse(claim):claim;
        const plainFieldHashName = "pki-plain-fields:"+(await sha2Hex(claimObject.signature/*typeof claim == "string"?claim:JSON.stringify(claim)*/));

		const plainFieldsJSON =  plainFields.find(f=>f[plainFieldHashName])?plainFields.find(f=>f[plainFieldHashName])[plainFieldHashName]:null;
        if(plainFieldsJSON)
           claimObject["plainFields"] = JSON.parse(plainFieldsJSON);
      
        return claimObject;
    }

	async function attachPlainFields(signature,plainFields,signerCert){
    	const cert  = signerCert?signerCert:await getCert(signature.signerID);      
        //used to verify signed masked fields in claim, it will take precedence 
        //over plain fields included in the signature signedString
        signature["plainFields"] = plainFields;
      
        //this a private version of the plain fields, primarily useful of API use or some other remote verification of claims
        if(certPayloadHasField(cert.cert_text,"pki-cert-version")){
        	signature["hashedPlainFields"] = await getHashedPlainFields(plainFields,PUBLIC_PLAIN_FIELDS);

            if(plainFields.find(f=>f["pki-hmac-keys"])){
              signature["hmacedPlainFields"] = await getHashedPlainFields(plainFields,PUBLIC_PLAIN_FIELDS,null,false,JSON.parse(plainFields.find(f=>f["pki-hmac-keys"])["pki-hmac-keys"]));
            }
        }
    }

    async function createCert(csrPEM,startDateText,expireDateText,privateKey,delegateSigningAuthority,lateralLimit,issuer,certisfy_stripe_token,approvedCSRFields,encryptIssuerFingerPrint){
        const crypto = pkijs.getCrypto(true);
        let signerPrivateKey =  fromPEM(issuer?issuer.csr.privateKey:privateKey);
      
        signerPrivateKey =  await crypto.subtle.importKey(
              "pkcs8", // Key format
              signerPrivateKey,
              certAlgo, // Algorithm details (modify for your encryption algorithm)
              true, // Whether the key is extractable
              ["sign"] // Key usages
        );

        //Decode the Base64-encoded CSR to binary
        const binaryCsr = fromPEM(csrPEM);//new Uint8Array(Array.from(atob(csrPEM), c => c.charCodeAt(0)));

        const certificate = new pkijs.Certificate();
        //Import the CSR using PKIjs
        const csr = pkijs.CertificationRequest.fromBER(binaryCsr);  
        

       //#region Parse and display information about "subject"
        const typemap = {
            "2.5.4.6": "C",
            "2.5.4.11": "OU",
            "2.5.4.10": "O",
            "2.5.4.3": "CN",
            "2.5.4.7": "L",
            "2.5.4.8": "ST",
            "2.5.4.12": "T",
            "2.5.4.42": "GN",
            "2.5.4.43": "I",
            "2.5.4.4": "SN",
            "1.2.840.113549.1.9.1": "E-mail"
        };  

        let certCN = null;
        let payLoad = null;
        for (let i = 0; i < csr.subject.typesAndValues.length; i++) {
            let typeval = typemap[csr.subject.typesAndValues[i].type];
            if (typeof typeval === "undefined")
                typeval = csr.subject.typesAndValues[i].type;

            const subjval = csr.subject.typesAndValues[i].value.valueBlock.value;

            if (typeval === "CN") {
                certCN = subjval;
            }
        }  


        //extract payload
        for (let i = 0; i < csr.attributes.length; i++) {

          if(csr.attributes[i].type == "1.2.840.113549.1.9.14"){        
            let extensions = pkijs.Extensions.fromBER(csr.attributes[i].values[0].toBER(false)).extensions;

            for (let j = 0; j < extensions.length; j++) {
                if(extensions[j].extnID == "2.5.29.17"){

                     let altNameBin = asn1js.fromBER(extensions[j].extnValue.toBER(false)).result;              
                     let altNames = pkijs.GeneralNames.fromBER(altNameBin.getValue());
                     let altName = altNames.names[0].value;

                     //let altName = altNameBin.valueBlock.value[0].valueBlock.value[0].valueBlock.value[0].valueBlock.value
                     payLoad = JSON.parse(altName);
                     break;
                }
            }

            break;
          }
        }

        //CN
        certificate.subject.typesAndValues=[new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.Utf8String({ value: certCN })
        })];  
      
      	if(approvedCSRFields){
            let safeCSRFields = {};
          	let preApprovedFields = ["pki-asym-encryption-key","pki-cert-version"];
            for(let fieldName in payLoad){
              
              	if(preApprovedFields.includes(fieldName)){
                   safeCSRFields[fieldName] = payLoad[fieldName];
                   continue;
                }
              
                for(let j=0;j<approvedCSRFields.length;j++){
                   if(fieldName == approvedCSRFields[j].name && payLoad[fieldName] == approvedCSRFields[j].value){
                      safeCSRFields[fieldName] = payLoad[fieldName];
                      break;
                   }
                }
              
                if(!safeCSRFields[fieldName] && !confirm(`Unapproved field '${fieldName}' found in certificate request, it will be ignored.\n Do you want to continue with issuing the certificate?`))
                  	return;
            }
            payLoad = safeCSRFields;
        }

      	addFieldToCertPayload(payLoad,"pki-maximum-delegates",delegateSigningAuthority);
        addFieldToCertPayload(payLoad,"pki-maximum-issuance",lateralLimit);
        addFieldToCertPayload(payLoad,"certisfy-stripe-token",certisfy_stripe_token);
      
      	if(encryptIssuerFingerPrint){
        	addFieldToCertPayload(payLoad,"pki-is-private-issuer","true");        
        }

        const altNames = new pkijs.GeneralNames({
            names: [
                new pkijs.GeneralName({
                    type: /*0*/2,
                    value: JSON.stringify(payLoad)//new asn1js.Utf8String({ value:JSON.stringify(payLoad)})
                })
            ]
        });    

        //console.log("payLoad");
        //console.log(payLoad);
        //console.log(csr)

        const subjectKeyIdentifier = await crypto.digest({ name: "SHA-1" }, csr.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
        certificate.subjectPublicKeyInfo = csr.subjectPublicKeyInfo;
        certificate.signatureAlgorithm = csr.signatureAlgorithm;
        certificate.extensions=[
            new pkijs.Extension({
              extnID: "2.5.29.14",
              critical: false,
              extnValue: (new asn1js.OctetString({ valueHex: subjectKeyIdentifier })).toBER(false)
            }),
            new pkijs.Extension({
              extnID: "2.5.29.17",
              critical: false,
              extnValue: altNames.toSchema().toBER(false)
            })
        ];

        /*
         certificate.attributes=[new pkijs.Attribute({
            type: "1.2.840.113549.1.9.14",
            values: [(new pkijs.Extensions({
                    extensions: [
                        new pkijs.Extension({
                            extnID: "2.5.29.14",
                            critical: false,
                            extnValue: (new asn1js.OctetString({ valueHex: subjectKeyIdentifier })).toBER(false)
                        }),
                        new pkijs.Extension({
                            extnID: "2.5.29.17",
                            critical: false,
                            extnValue: altNames.toSchema().toBER(false)
                        })
                    ]
                })).toSchema()]
        })];*/

        certificate.version = 2;
        certificate.serialNumber = new asn1js.Integer({ value: 1 });

        let signerSignature = null;
        if(issuer && issuer.finger_print && issuer.finger_print.length>0){
          	let issuerFingerPrint = issuer.finger_print;
          
          	if(encryptIssuerFingerPrint){
      			let signedString = Object.assign({},{"plainFields":[{"pki-action":"encrypt-issuer-fingerprint"},{"finger-print":issuerFingerPrint}]});
                const resp = await getEncryptedIssuerFingerPrint(await signClaim(issuer,JSON.stringify(signedString)));
              
                if(resp.encryptedIssuerFingerPrint)
                	issuerFingerPrint = resp.encryptedIssuerFingerPrint;
              	else
                if(!confirm(`There was a problem encrypting issuer finger print, ${resp.message},\n do you want to issue the certificate with a non-private issuer finger print?\n Ask procurer for confirmation.`))
                	return;                
            }
          
            certificate.issuer.typesAndValues=[new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3",
                value: new asn1js.Utf8String({ value: issuerFingerPrint })
            })];
            signerSignature = JSON.stringify(await signText(issuer,randomUUID(crypto),false));
        }
        else
        {
            certificate.issuer.typesAndValues=[new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3",
                value: new asn1js.Utf8String({ value: "Prometheus" })
            })];
        }

        certificate.notBefore.value = new Date();
        certificate.notBefore.value.setFullYear(parseInt(startDateText.split("/")[2]),parseInt(startDateText.split("/")[0])-1,parseInt(startDateText.split("/")[1]));

        certificate.notAfter.value = new Date();
        certificate.notAfter.value.setFullYear(parseInt(expireDateText.split("/")[2]),parseInt(expireDateText.split("/")[0])-1,parseInt(expireDateText.split("/")[1]));

        await certificate.sign(signerPrivateKey, hashAlg);  

        let finger_print = await getCertFingerPrint(certificate);
        //let finger_print = hmacUtil.hash(certificate.toSchema(true).toBER(false));

        /*console.log({
            signerSignature,
            certificate,
            finger_print:finger_print,
            certPEM: pemEncodeCert(certificate),
        })*/
        return {
            signerSignature,
            certificate,
            finger_print:finger_print,
            certPEM: pemEncodeCert(certificate),
        }; 
      }

    async function signText(signer,stringToSign,includeTrustChain){
            let signerPrivateKey =  await crypto.subtle.importKey(
                  "pkcs8", // Key format
                  fromPEM(signer.csr.privateKey),
                  certAlgo, // Algorithm details (modify for your encryption algorithm)
                  true, // Whether the key is extractable
                  ["sign"] // Key usages
            );

            let now = (new Date().getTime());
            let signedString = stringToSign+"timestamp="+now;
            let signedStringHash = await sha2Hex(signedString);
      
            let sigPayload = {
               "id":randomUUID().replaceAll("-",""),
               "certisfy_object":true,
               "timestamp":now,
               "signerID":signer.finger_print,
               "signedString":signedString,
               //"certificate":signer.cert_text
            };
      		let includeTC = (typeof signer.isInRegistry == "undefined" || signer.isInRegistry != true || includeTrustChain);
      
			if(includeTC){
                //This will recursively resolve the trust chain and attach the whole thing
      			//sigPayload.trustChain = await getCertChainFromLocalStore(signer.finger_print);
                sigPayload.trustChain = await getCertChain(signer.finger_print,false,false);
              
                //prefer registry chain over local store
              	if((!sigPayload.trustChain || !sigPayload.trustChain.certs || sigPayload.trustChain.certs.length == 0 || sigPayload.trustChain.certs[0].fromLocalStore) && signer.trustChain)
                  	sigPayload.trustChain = signer.trustChain;
              
                /*
                sigPayload.trustChain = await getCertChain(signer.finger_print);
                if(sigPayload.trustChain.certs.length == 0){//if signer is not in registry, attach local cert
                    sigPayload.trustChain.certs=[await exportCertificate(signer.cert_text,Object.assign({"fromLocalStore":true},(signer.issuer_finger_print?{"issuer_finger_print":signer.issuer_finger_print}:{})))];
                }*/
            }
      
            let signature = await crypto.subtle.sign(certAlgo,
              signerPrivateKey,
              new TextEncoder().encode(signedStringHash)
            );
            sigPayload.signature = base64EncodeBin(signature); 

            return sigPayload;
    }

    async function verifyText(signedString,signature,signerCert){

            //console.log(signerCert,decodeCertificate(signerCert))
            const parsedKey = decodeCertificate(signerCert).subjectPublicKeyInfo.parsedKey;
            //const publicKeyExtract = pkijs.PublicKeyInfo.fromBER(decodeCertificate(signerCert).subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
      		//console.log(parsedKey);
      		//console.log(toPEM(parsedKey.toSchema().toBER(false),"PUBLIC KEY"))
            let signerPublicKey =  await crypto.subtle.importKey(
                  //"spki", // Key format
                  //decodeCertificate(signerCert).subjectPublicKeyInfo,
                  //"pkcs8",
                  //fromPEM(toPEM(parsedKey.toSchema().toBER(false),"PUBLIC KEY")),
                  "raw",
                   parsedKey.toSchema().toBER(false),
                  (parsedKey.namedCurve?{
                    name:signAlg,
                    hash:hashAlg,
                    namedCurve:parsedKey.namedCurve
                  }:{
                    name:signAlg,
                    hash:hashAlg
                  }), // Algorithm details (modify for your encryption algorithm)
                  true, // Whether the key is extractable
                  ["verify"] // Key usages
            );
      
        //console.log(signerPublicKey)

        let signedStringHash = await sha2Hex(signedString);
      
        let result = await crypto.subtle.verify(
            (parsedKey.namedCurve?{
                    name:signAlg,
                    hash:hashAlg,
                    namedCurve:parsedKey.namedCurve
                  }:{name:signAlg,hash:hashAlg}),
            signerPublicKey,
            base64DecodeToBin(signature),
            new TextEncoder().encode(signedStringHash),
        );

        return result;
    }

	export  {
      createCSR,
      decryptCSR,
      createCert,
      signText,
      verifyText,
      signClaim,
      verifyClaim,
      verifyDHExchangeClaim,
      isClaimTrustworthy,
      buildErrorList,
      verifyVouches,
      getVouchedClaimIdentities,
      isValidDHExchange,
      createPrivateField,
      filterFields,
      getMatchingMaskedFields,
      hashPlainField,
      getHashedPlainFields,
      getUnHashedPlainFields,
      getHashedPlainField,
      getUnHashedPlainField,
      attachPlainFields,
      extractAndAttachPlainFields,
      maskEmbeddedClaimsPlainFields,
      toPEM,
      fromPEM,
      decodePEM,
      setIdAnchorElements,
      setClientApp,
      certPayloadHasField,
      getCertPayloadField,
      loadTrustRoots,
      setAPITarget,
      wrapCertIdentity,
      extractCertPublicKey,
      getCertFingerPrint,
      decodeCertificate,
      getCertChain,
      createClaimFields,
      createStandardClaimFields,
      selectCertFields,
      extractClaimPlainFields,
      unmaskFieldVerifications,
      maskClaimPlainFields,
      claimContainsVouchedForClaims,
      fieldsContainVouchedForClaims,
      textToClaimObject,
      isTrustAnchorCert,
      isInternalField,
      isVerifiedField,
      rebuildVerificationField,
      isInternalFieldName,
      filterVerificationFields,
      rebuildVerificationFields,
      getVerificationField,
      setPlainFields,
      sha1Hex,
      sha2Hex,
      sha2HexList,
      sha1HexList,
      hmacHex,
      hashAlg,
      signAlg,
      isTrustAnchor,
      updateCertTrustchainPrivacy,
      getVerificationResult,
      getVerifiedCertificateField,
      randomUUID,
      postDHExchange,
      getDHExchange,
      initiateDHExchange,
      executeDHExchange,
      createClaimDateTime,
      PKI_CERT_VERSION,
      SET_SDK_MODE,
      demoTrustAnchorFingerprint,
      idAnchorElements
    };