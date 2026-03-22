	import * as cryptoUtil from '../utils/crypto.js';
    import * as helperUtil from '../utils/helpers.js';
    import * as certUtil from '../utils/cert.js';

	import * as defaultConfig from '../config.js';

	import * as certStore from './cert-store.js';
	import * as claimData from './claim-data.js';

	import * as certisfyAPI from '../core-api/api.js';
	
 	const {isValidString,textToClaimObject} = helperUtil;
	const {sha2Hex,hmacHex,fromPEM,randomUUID,base64EncodeBin,ECDSA_SIGNER,AES_GCM_CIPHER,bobKeyGen} = cryptoUtil;
	const {decodeCertificate,getCertificatePayload,certPayloadHasField} = certUtil;
	const {setPlainFields,hashPlainField,getHashedPlainFields,filterPlainFields,getVouches,fieldsContainVouchedForClaims} = claimData;
	const {getCertFromStore,getCertChainFromStore,getCertChainFromLocalStore} = certStore;

    const {postCertIdentity,postDHExchange,getDHExchange} = certisfyAPI;

    //access to properly configured modules
    let sdk;

	function getConfig(){
    	return sdk?sdk.getConfig():defaultConfig;
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

    async function executeDHExchange(userCode,fnClaimProvider,useExchange){

           const dhExchange = useExchange?useExchange:await getDHExchange(userCode);

           let skipReceiverIdVerification = true;
           let alice_data = dhExchange.alice_data?JSON.parse(dhExchange.alice_data):null;
           //let receiverIdAuth = JSON.parse(dhExchange.alice_data);
           //ECDSA_SIGNER.verifyMessage(receiverIdAuth.publicKey,receiverIdAuth.auth_signature_string,receiverIdAuth.signature).

           let verified = (skipReceiverIdVerification?true:(await ECDSA_SIGNER.verifyMessage(receiverIdAuth.publicKey,receiverIdAuth.auth_signature_string,receiverIdAuth.auth_signature)))

           let dhKey = await bobKeyGen(dhExchange.alice_public_key);
           let spUri = alice_data && alice_data.sp_uri && alice_data.sp_uri.length>0?alice_data.sp_uri:null;

           let dhxParams = [{"name":"pki-dhx-nonce","value":userCode+"-"+dhExchange.create_date}];
           let claimSig = await fnClaimProvider(dhxParams);

           let cipherText = await AES_GCM_CIPHER.encryptMessage(dhKey.AESKey,typeof claimSig == "object"?JSON.stringify(claimSig):claimSig);

           let resp = await postDHExchange({
               "user_code":userCode,
               "bob_public_key":dhKey.publicKeyBase64,
               "bob_data":cipherText
           })

           return Object.assign(resp,{claim:claimSig});
    }

    async function wrapCertIdentity(idCertSig,spUri,enclosedSig,includeTrustChain,vouchedForClaimIdentities,isForPrivatePersona){
      
        let privateSPUri = await sha2Hex(spUri);
      	return new Promise((resolve,reject)=>{
			postCertIdentity({
                      	"id_anchor_cert_sig":idCertSig,
                        "sp_uri":privateSPUri,
                        "enclosed_sig":enclosedSig,
                      	"vouch_for_claim_identities":(vouchedForClaimIdentities && Array.isArray(vouchedForClaimIdentities)?JSON.stringify(vouchedForClaimIdentities):vouchedForClaimIdentities),
                      	"include_trust_chain":includeTrustChain,
                      	"is_private_persona":isForPrivatePersona
            }).
            then(function(resp){
                if(typeof resp.status == "undefined" || (resp.status != "failure" && resp.status != "error")){
                	resolve(resp);
                }
                else
                {                    
                 	console.error((resp.message || resp.error_message));
                }
            })
        });      
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
                //console.log(idAnchorCertObj,idAnchorCertPayload,getConfig().idAnchorElements);
                //does the id anchor cert have an identity anchor element (SSN,DLN..etc) on it
                for(let idElementKey in getConfig().idAnchorElements)
                {
                  	let mappedSignedDocument = [];
                  
                    let idAnchorEl = idElementKey;//getConfig().idAnchorElements[idElementKey];
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

	async function createPrivateField(field,hashInput=true){
        let plainField = {};
        plainField[field.name] = field.value;
      
        if(field.name == "pki-asym-encryption-key")
          	return plainField;        
      
      	let hmacKey = field.hmacKey?field.hmacKey:randomUUID().replaceAll("-","");
      
        //hash structurally instead of blindly hashing
        const hashedPlainField = await hashPlainField(plainField,getConfig().PUBLIC_PLAIN_FIELDS,null,false,hmacKey,!hashInput);
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

                if(getConfig().clientApp && getConfig().clientApp.isStrictlyInternalClaimField && field.maskedField && getConfig().clientApp.isStrictlyInternalClaimField(field.maskedField)) {
                  	return {error:"Claim field "+field.maskedField.name+" can't be used, will be ignored."};
                }

                if(getConfig().clientApp && getConfig().clientApp.isStrictlyInternalClaimField && getConfig().clientApp.isStrictlyInternalClaimField(field.plainField)) {
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
                if(getConfig().clientApp && getConfig().clientApp.isStrictlyInternalClaimField && getConfig().clientApp.isStrictlyInternalClaimField(field)) {
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

	async function attachPlainFields(signature,plainFields,signerCert){
    	const cert  = signerCert?signerCert:await getCertFromStore(signature.signerID);      
        //used to verify signed masked fields in claim, it will take precedence 
        //over plain fields included in the signature signedString
        signature["plainFields"] = plainFields;
      
        //this a private version of the plain fields, primarily useful of API use or some other remote verification of claims
        if(certPayloadHasField(cert.cert_text,"pki-cert-version")){
        	signature["hashedPlainFields"] = await getHashedPlainFields(plainFields,getConfig().PUBLIC_PLAIN_FIELDS);

            if(plainFields.find(f=>f["pki-hmac-keys"])){
              signature["hmacedPlainFields"] = await getHashedPlainFields(plainFields,getConfig().PUBLIC_PLAIN_FIELDS,null,false,JSON.parse(plainFields.find(f=>f["pki-hmac-keys"])["pki-hmac-keys"]));
            }
        }
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

    async function signText(signer,stringToSign,includeTrustChain){
            let signerPrivateKey =  await crypto.subtle.importKey(
                  "pkcs8", // Key format
                  fromPEM(signer.csr.privateKey),
                  getConfig().certAlgo, // Algorithm details (modify for your encryption algorithm)
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
                let trustChain = await getCertChainFromStore(signer.finger_print,false,false);
              
                //prefer registry chain over local store
              	if((!trustChain || !trustChain.certs || trustChain.certs.length == 0 || trustChain.certs[0].fromLocalStore) && (signer.trustChain && signer.trustChain.certs && signer.trustChain.certs.length>0))
                  	trustChain = signer.trustChain;
                
              	if((!trustChain || !trustChain.certs || trustChain.certs.length == 0)){
                    trustChain = await getCertChainFromLocalStore(signer.finger_print)
                  
                  	//last resort
                  	if((!trustChain || !trustChain.certs || trustChain.certs.length == 0))
                  		trustChain = {"certs":[await exportCertificate(signer.cert_text,Object.assign({"fromLocalStore":true}))]};
                }
              
                if((trustChain && trustChain.certs && trustChain.certs.length > 0))
                  	sigPayload["trustChain"] = trustChain;
              
                /*
                sigPayload.trustChain = await getCertChainFromStore(signer.finger_print);
                if(sigPayload.trustChain.certs.length == 0){//if signer is not in registry, attach local cert
                    sigPayload.trustChain.certs=[await exportCertificate(signer.cert_text,Object.assign({"fromLocalStore":true},(signer.issuer_finger_print?{"issuer_finger_print":signer.issuer_finger_print}:{})))];
                }*/
            }
      
            let signature = await crypto.subtle.sign(getConfig().certAlgo,
              signerPrivateKey,
              new TextEncoder().encode(signedStringHash)
            );
            sigPayload.signature = base64EncodeBin(signature); 

            return sigPayload;
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
				console.error("Your identity certificate appears to have a problem, unable to generate identity for claim");
              	return;
            }
          
            if(signaturePayload["pki-identity"].status && signaturePayload["pki-identity"].status == "error"){
				console.error(`Unable to generate identity for claim, ${signaturePayload["pki-identity"].error_message}`);
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

	function configure(_sdk){
       sdk = _sdk;

       certisfyAPI.configure(sdk);//ensure configuration is propagated
       certStore.configure(sdk);
    }

	export  {
      signText,
      signClaim,
      createPrivateField,
      attachPlainFields,
      extractAndAttachPlainFields,
      wrapCertIdentity,
      createClaimFields,
      createStandardClaimFields,
      selectCertFields,
      getVouchedClaimIdentities,
      executeDHExchange,
      configure
    };