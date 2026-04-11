    /******************************Copyright 2026, Edmond Kemokai, pkijs example authors******************
    1. This code is provided as is without warranty of any kind. 
    2. You may modify it for your own use and only for automated signing of claims or verification 
       of claims created either via the Certisfy app or claims created via the Certisfy signer code included herein. 
    3. You may not use it to create a Certisfy alternative client, ie a competing alternative to the Certisfy app.
    4. For verification of Certisfy app claims, verification of claims created via the Certisfy signer (ie Certisfy claims), 
       or automated signing of Certisfy claims, you are free to use it for both personal and commercial needs.
    5. You may not redistribute it with or without modifications.
    ******************************************************************************************************/

	import * as cryptoUtil from './utils/crypto.js';
    import * as helperUtil from './utils/helpers.js';
	import * as certUtil from './utils/cert.js';

	import * as certisfyAPIAuth from './core-api/api-auth.js';
    import * as certisfyAPI from './core-api/api.js';

	import * as defaultConfig from './config.js';

	import * as certGen from './core-pki/cert-gen.js';
	import * as certStore from './core-pki/cert-store.js';

    import * as claimData from './core-pki/claim-data.js';
    import * as certisfySigner from './core-pki/signer.js';
    import * as certisfyVerifier from './core-pki/verifier.js'; 	

    const {removeUndefinedFields} = helperUtil;
    const {sha2Hex,aliceKeyGen,bobKeyGen,ECDSA_SIGNER,AES_GCM_CIPHER} = cryptoUtil;
	const {decodeCertificate,getCertificatePayload,certPayloadHasField,getCertIssuerFingerPrint,exportCertificate} = certUtil;
	const {signRequest} = certisfyAPIAuth;
	const {postDHExchange,getDHExchange,getSignature,getCertChain,postServiceRequest} = certisfyAPI;
	const {buildTrustedCertChain,isTrustAnchor} = certisfyVerifier;
	const {certField} = claimData;
	

	let {
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
	} = defaultConfig;

	//access to properly configured modules
    let certisfySDK;

	function getConfig(){
    	 return {
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
    }

	function setAPIInfo(_apiInfo){
    	apiInfo = _apiInfo
    }

    function setClientApp(app){
      clientApp = app;
      if(app.pkiPlatformFullURL)
      	  apiInfo.target = app.pkiPlatformFullURL(apiInfo.target);
    }

    function setIdAnchorElements(elements){
       idAnchorElements = elements; 
    }

    async function loadTrustRoots(useRoots){
      
            const setRoot = (roots)=>{
              	trustRoots = roots;
              	trustChainRoot = trustRoots[0];
            }
            
            if(useRoots)//user provided
            	setRoot(useRoots);
            else
          	if(!getConfig().apiInfo || !getConfig().apiInfo.target){//use default included
            	setRoot(trustRoots);
            }
            else//fetch from registry
            {              
              	const roots = await sendRequest({action: "get-trust-roots"});                
                setRoot(roots);
            }  
    }

    function isIDElementHash(fieldName){
        for(let idEl in idAnchorElements){
           if(fieldName == idEl+"_HASH")
              return true;
        }
        return false;
  	}

	async function sendRequest(args,method,contentType){
		return new Promise(async (resolve,reject)=>{
          		if(clientApp && typeof clientApp.ajaxStartFN == "function")
                  		clientApp.ajaxStartFN();
          
          		let useURL = apiInfo?apiInfo.target:null;
          		const headers = {
                   "Content-Type": (contentType?contentType:"application/x-www-form-urlencoded")
                }
                
                let useMethod = (method?method:"POST");
          
          		if(apiInfo && apiInfo.requestSigningInfo){
                  
                	let authInfo = await signRequest(args,apiInfo.target,apiInfo.requestSigningInfo);
                  
                  	if(authInfo){
                        headers["Authorization"] = authInfo.authorization;
                        headers["Timestamp"] = authInfo.timestamp;

                        if(authInfo.method)
                            useMethod = authInfo.method;
                      
                      	if(authInfo.url)
                          	useURL = authInfo.url;
                    }
                }
          		else//TODO:generate signer_signature with certisfy.com as receiver for authentication
                {
                  
                }
          
          		let request = {
                    method: useMethod,
                    headers: headers,
                    body: new URLSearchParams(removeUndefinedFields(args))
                };
          
          		if(useMethod == "GET"){
                	useURL = `${useURL}?${new URLSearchParams(removeUndefinedFields(args))}`
                    delete request["body"];
                }
          
          
				fetch(useURL, request)
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

	/*
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
    }*/

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

    async function getEncryptedIssuerFingerPrint(signer_signature){
      	return new Promise((resolve,reject)=>{
          
			postServiceRequest({
              "service_action":"encrypt-issuer-fingerprint",
              "signer_signature":(typeof signer_signature == "string"?signer_signature:JSON.stringify(signer_signature))
            }).
            then(function(resp){
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

    async function updateCertDerivationSourcePrivacy(signer_signature){
      	return new Promise((resolve,reject)=>{
          
			sendRequest({
                      "action":"update-cert-derivation-source-privacy",
                      "signer_signature":(typeof signer_signature == "string"?signer_signature:JSON.stringify(signer_signature))
            }).then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function updateCertDerivationSourceIssuerPrivacy(signer_signature){
      	return new Promise((resolve,reject)=>{
          
			sendRequest({
                      "action":"update-cert-derivation-source-issuer-privacy",
                      "signer_signature":(typeof signer_signature == "string"?signer_signature:JSON.stringify(signer_signature))
            }).then(function(resp){
                resolve(resp);
            })
        });      
    }


	function configure({config,sdk}){
      	if(config){
            if(config.idAnchorElements)
                setIdAnchorElements(config.idAnchorElements);

            if(config.clientApp)
                setClientApp(config.clientApp);

            if(config.trustRoots)
                loadTrustRoots(config.trustRoots);

            if(config.trustChainRoot)
                trustChainRoot 				= config.trustChainRoot;

            if(config.demoTrustAnchorFingerprint)
                demoTrustAnchorFingerprint 	= config.demoTrustAnchorFingerprint;

            if(config.PUBLIC_PLAIN_FIELDS)
                PUBLIC_PLAIN_FIELDS 		= config.PUBLIC_PLAIN_FIELDS;    

            if(config.apiInfo)
              	setAPIInfo(config.apiInfo);            

            if(config.PKI_CERT_VERSION)
                PKI_CERT_VERSION = config.PKI_CERT_VERSION;
        }
          
      	if(sdk){
        	certisfySDK = sdk;
          
          	certisfySigner.configure(sdk);
          	certisfyVerifier.configure(sdk);
          	claimData.configure(sdk);
            certGen.configure(sdk);
            certStore.configure(sdk);
            certisfyAPI.configure(sdk);
        }
    }

	export  {
      getConfig,
      configure,
      sendRequest,
      setIdAnchorElements,
      setClientApp,
      loadTrustRoots,
      setAPIInfo,
      updateCertTrustchainPrivacy,
      updateCertDerivationSourcePrivacy,
      getEncryptedIssuerFingerPrint,
      getEmbededSignature,      
      
      certisfyAPIAuth,
      
      certisfyAPI,      
      certisfySigner,
      certisfyVerifier,
      certStore,
      claimData,
      certGen,
      
      certUtil,
      helperUtil,
      cryptoUtil
    };