	import {asn1js,pkijs} from '../utils/pkijs.js';

    import * as cryptoUtil from '../utils/crypto.js';
    import * as certUtil from '../utils/cert.js';

	import * as defaultConfig from '../config.js';

	import * as certisfyAPI from '../core-api/api.js';

	import * as certisfySigner from './signer.js';
    import * as claimData from './claim-data.js';

	const {fromPEM,toPEM,sha2Hex,hmacHex,base64ToArrayBuffer,base64EncodeBin,randomUUID,AES_GCM_CIPHER} = cryptoUtil;
	const {getCertFingerPrint,certPayloadHasField,pemEncodeCert} = certUtil;
	const {signClaim,signText,selectCertFields} = certisfySigner;
	const {wrapCertIdentity} = certisfyAPI;

    //access to properly configured modules
    let sdk;

	function getConfig(){
    	return sdk?sdk.getConfig():defaultConfig;
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
                getConfig().certAlgo, 
                true, 
                ["sign"]);
          
          	 publicKey = await crypto.subtle.importKey(
                    "spki", 
                    base64ToArrayBuffer(kp.publicKey),
                    getConfig().certAlgo,true,["verify"]);
        }
      	else
        {      
           let kp = await crypto.generateKey(getConfig().certAlgo, true, /*[ "sign", "encrypt","verify","decrypt"]*/algorithm.usages);
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
        let plainPayload = {"pki-asym-encryption-key":asymEncryptionKeyPEM,"pki-cert-version":getConfig().PKI_CERT_VERSION};
      	      
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
          	 
             for(let idElementKey in getConfig().idAnchorElements){
                if(csrFields[idElementKey]){
                   //make id element value uniformly uppercase
                   csrFields[idElementKey] = csrFields[idElementKey].toUpperCase();
                   
                   //create privacy preserving versions of ID elements to support claim identity generation
                   if(false /*&& getConfig().PKI_CERT_VERSION < "1.5"*/ )
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
        maskedPayload["pki-cert-version"]= getConfig().PKI_CERT_VERSION;

        let cn = [];
        cn[0] = isPrivate?JSON.stringify(maskedPayload):JSON.stringify(plainPayload);//csrPayload;

        const csrResp = await createPKCS10Internal(getConfig().hashAlg, getConfig().signAlg,cn[0],keyPair);
        let csrText = csrResp.csrPEM;

        let iv = crypto.getRandomValues(new Uint8Array(12));  
        // crypto functions are wrapped in promises so we have to use await and make sure the function that
        // contains this code is an async function
        // encrypt function wants a cryptokey object
        /*let encryptionKey = null;
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
        }*/
      
        let csrDetails = {"csr":csrText,"signedDocument":signedDocFieldList};
        if(useStrongIdProofing && idCert)
                Object.assign(csrDetails,{"identity":idCert});
      
      	if(identityCertSig)
           		Object.assign(csrDetails,{"identityCertSig":identityCertSig});
      
        /*csrText = new TextEncoder().encode(JSON.stringify(csrDetails));
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
          */
      
      	  csrText = JSON.stringify(csrDetails);
          let encryptionKey = payloadEncryptionKey?payloadEncryptionKey:(await AES_GCM_CIPHER.generateKey())
          let encryptedPayload = await AES_GCM_CIPHER.encryptMessage(encryptionKey,csrText);

          //atob(btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedPayload))));
          //atob(btoa(String.fromCharCode.apply(null, new Uint8Array(encryptionKey))));
          //console.log(await decryptCSR(btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedPayload))),btoa(String.fromCharCode.apply(null, new Uint8Array(encryptionKey)))))

         let finger_print = await sha2Hex(/*base64EncodeBin*/(encryptedPayload));
      
          return {
              "finger_print":finger_print,
              "encryptedPayload":/*base64EncodeBin(encryptedPayload)*/encryptedPayload,
              "encryptionKey":encryptionKey,
              "csr":csrResp,
              "signedDocument":signedDocFieldList,
              "asymDecryptionKey":asymDecryptionKeyPEM,
              "asymEncryptionKey":asymEncryptionKeyPEM
          };
    }

    async function decryptCSR(csrCipherText,encryptionKey){

      	/*
        // Decode the Base64-encoded key to binary
        let decryptionKey = new Uint8Array(Array.from(atob(encryptionKey), c => c.charCodeAt(0)));///*Uint8Array.from* /(atob(encryptionKey));

        // Import the binary key
        decryptionKey =  await crypto.subtle.importKey(
          "raw", // Key format
          decryptionKey,
          { 
            name: "AES-GCM",
            length: 128 
          }, // Algorithm details (modify for your encryption algorithm)
          true, // Whether the key is extractable
          ["encrypt", "decrypt"/*,"sign","verify"* /] // Key usages
        )


         let ctBuffer = Array.from(atob(csrCipherText), c => c.charCodeAt(0));
         let csr = new Uint8Array(ctBuffer);///*new Uint8Array* /(atob(csrText));
         let decryptedPayload = await crypto.subtle.decrypt(
                                {
                                  name: "AES-GCM",
                                  iv:new Uint8Array(ctBuffer.slice(0, 12)),
                                  tagLength: 128
                                },decryptionKey,new Uint8Array(ctBuffer.slice(12))); 

          decryptedPayload = new TextDecoder().decode(decryptedPayload);
          //console.log(JSON.parse(decryptedPayload))
          return JSON.parse(decryptedPayload);
          */
          return JSON.parse(await AES_GCM_CIPHER.decryptMessage(encryptionKey,csrCipherText));
    }

    async function createCert(csrPEM,startDateText,expireDateText,privateKey,delegateSigningAuthority,lateralLimit,issuer,certisfy_stripe_token,approvedCSRFields,encryptIssuerFingerPrint){
        const crypto = pkijs.getCrypto(true);
        let signerPrivateKey =  fromPEM(issuer?issuer.csr.privateKey:privateKey);
      
        signerPrivateKey =  await crypto.subtle.importKey(
              "pkcs8", // Key format
              signerPrivateKey,
              getConfig().certAlgo, // Algorithm details (modify for your encryption algorithm)
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
                const resp = await encryptIssuerFingerPrint(await signClaim(issuer,JSON.stringify(signedString)));
              
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

        await certificate.sign(signerPrivateKey, getConfig().hashAlg);  

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

	function addFieldToCertPayload(payLoad,fieldName,fieldVal){
     	if(fieldVal)
            payLoad[fieldName] = fieldVal;
        else
          	delete payLoad[fieldName]; 
    }

	function configure(_sdk){
       sdk = _sdk;

       certisfyAPI.configure(sdk);//ensure configuration is propagated
       certisfySigner.configure(sdk);
    }

	export  {
      createCSR,
      decryptCSR,
      createCert,
      addFieldToCertPayload,
      configure
    };